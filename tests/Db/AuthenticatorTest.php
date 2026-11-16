<?php

// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace MailPanel\Tests\Db;

use MailPanel\Auth\AuthException;
use MailPanel\Auth\Authenticator;
use MailPanel\Auth\Totp;
use MailPanel\Support\Crypto;
use MailPanel\Tests\Support\DbTestCase;
use MailPanel\Tests\Support\FakeDirectory;

final class AuthenticatorTest extends DbTestCase
{
    private const ADMIN_SID = 'S-1-5-21-1-2-3-1101';
    private const AUDIT_SID = 'S-1-5-21-1-2-3-1105';

    private FakeDirectory $dir;
    private Crypto $crypto;
    private Authenticator $auth;

    public function setUp(): void
    {
        parent::setUp();
        $this->dir = new FakeDirectory([
            'jnovak'   => ['password' => 'Heslo123!', 'sids' => ['S-1-5-21-1-2-3-513', self::ADMIN_SID]],
            'auditor'  => ['password' => 'Heslo123!', 'sids' => [self::AUDIT_SID]],
            'nikdo'    => ['password' => 'Heslo123!', 'sids' => ['S-1-5-21-1-2-3-513']],
            'zamceny'  => ['password' => 'x', 'error' => 'account_locked'],
        ]);
        $this->crypto = new Crypto(Crypto::generateKey());
        $this->auth = new Authenticator($this->db, $this->dir, $this->audit, $this->crypto,
            ['admin' => [self::ADMIN_SID], 'auditor' => [self::AUDIT_SID]],
            ['max_fails_user' => 3, 'max_fails_ip' => 10, 'window_minutes' => 15]);
    }

    public function testAdLoginCreatesUserWithRoles(): void
    {
        $u = $this->auth->verifyPassword('FIRMA\\jnovak', 'Heslo123!', '10.0.0.5');
        $this->assertSame('jnovak', $u['username']);
        $this->assertSame('ad', $u['source']);
        $this->assertSame('admin', $u['roles']);
        $this->assertNull($u['totp_secret']);
        $this->assertSame(1, (int) $this->db->value("SELECT count(*) FROM audit_log WHERE action = 'user.created'"));
    }

    public function testRolesRefreshedOnEveryLogin(): void
    {
        $this->auth->verifyPassword('jnovak', 'Heslo123!', '10.0.0.5');
        $this->db->exec("UPDATE users SET roles = 'auditor' WHERE username = 'jnovak'");
        $u = $this->auth->verifyPassword('jnovak', 'Heslo123!', '10.0.0.5');
        $this->assertSame('admin', $u['roles']);
        $this->assertSame(1, (int) $this->db->value("SELECT count(*) FROM audit_log WHERE action = 'user.roles_changed'"));
    }

    public function testNoRoleDenied(): void
    {
        $e = $this->assertThrows(AuthException::class, fn () => $this->auth->verifyPassword('nikdo', 'Heslo123!', '10.0.0.5'));
        $this->assertSame('no_role', $e->reason());
        $this->assertSame(0, (int) $this->db->value('SELECT count(*) FROM users'));
    }

    public function testGenericMessages(): void
    {
        $bad = $this->assertThrows(AuthException::class, fn () => $this->auth->verifyPassword('jnovak', 'spatne', '10.0.0.5'));
        $missing = $this->assertThrows(AuthException::class, fn () => $this->auth->verifyPassword('neexistuje', 'x', '10.0.0.5'));
        $locked = $this->assertThrows(AuthException::class, fn () => $this->auth->verifyPassword('zamceny', 'x', '10.0.0.5'));
        $this->assertSame($bad->getMessage(), $missing->getMessage(), 'neprozradit existenci účtu');
        $this->assertSame($bad->getMessage(), $locked->getMessage());
        $this->assertContains('ad_account_locked', $locked->reason());
        $row = $this->db->one("SELECT * FROM audit_log WHERE action = 'auth.password' AND username = 'zamceny'");
        $this->assertSame('fail', $row['result']);
        $this->assertContains('ad_account_locked', $row['details']);
    }

    public function testThrottlingAndUnlock(): void
    {
        for ($i = 0; $i < 3; $i++) {
            $this->assertThrows(AuthException::class, fn () => $this->auth->verifyPassword('jnovak', 'spatne', '10.0.0.5'));
        }
        $calls = $this->dir->calls;
        $e = $this->assertThrows(AuthException::class, fn () => $this->auth->verifyPassword('jnovak', 'Heslo123!', '10.0.0.6'));
        $this->assertSame('throttled', $e->reason());
        $this->assertSame($calls, $this->dir->calls, 'zablokovaný pokus nejde do AD');
        // jiný zápis jména limit neobejde
        $e = $this->assertThrows(AuthException::class, fn () => $this->auth->verifyPassword('FIRMA\\JNOVAK', 'Heslo123!', '10.0.0.7'));
        $this->assertSame('throttled', $e->reason());

        $this->auth->unlock('user:jnovak', 'cli:test');
        $u = $this->auth->verifyPassword('jnovak', 'Heslo123!', '10.0.0.5');
        $this->assertSame('jnovak', $u['username']);
    }

    public function testIpThrottling(): void
    {
        $auth = new Authenticator($this->db, $this->dir, $this->audit, $this->crypto, ['admin' => [self::ADMIN_SID]],
            ['max_fails_user' => 100, 'max_fails_ip' => 3]);
        foreach (['a', 'b', 'c'] as $n) {
            $this->assertThrows(AuthException::class, fn () => $auth->verifyPassword($n, 'x', '192.0.2.9'));
        }
        $e = $this->assertThrows(AuthException::class, fn () => $auth->verifyPassword('jnovak', 'Heslo123!', '192.0.2.9'));
        $this->assertSame('throttled', $e->reason(), 'password spraying z jedné IP');
        $this->assertSame('jnovak', $auth->verifyPassword('jnovak', 'Heslo123!', '192.0.2.10')['username']);
    }

    public function testMfaEnrollAndVerify(): void
    {
        $u = $this->auth->verifyPassword('jnovak', 'Heslo123!', '10.0.0.5');
        $id = (int) $u['id'];
        $secret = Totp::generateSecret();
        $this->assertThrows(AuthException::class, fn () => $this->auth->enrollMfa($id, $secret, '000000', '10.0.0.5'));
        $code = Totp::code($secret, intdiv(time(), 30));
        $u = $this->auth->enrollMfa($id, $secret, $code, '10.0.0.5');
        $this->assertTrue($u['totp_secret'] !== null && !str_contains($u['totp_secret'], $secret), 'tajemství je šifrované');
        $this->assertSame($secret, $this->crypto->decrypt($u['totp_secret']));

        // stejný kód podruhé neprojde (replay)
        $e = $this->assertThrows(AuthException::class, fn () => $this->auth->verifyMfa($id, $code, '10.0.0.5'));
        $this->assertSame('invalid_code', $e->reason());
        // kód z dalšího kroku projde
        $next = Totp::code($secret, intdiv(time(), 30) + 1);
        $u = $this->auth->verifyMfa($id, $next, '10.0.0.5');
        $this->assertSame('10.0.0.5', $u['last_login_ip']);
        $this->assertThrows(AuthException::class, fn () => $this->auth->enrollMfa($id, $secret, $next, '10.0.0.5'), 'už je nastaveno');

        $this->auth->resetMfa($id, 'admin');
        $this->assertNull($this->db->value('SELECT totp_secret FROM users WHERE id = ?', [$id]));
        $this->assertTrue($this->audit->verify()['ok']);
    }

    public function testLocalEmergencyAccount(): void
    {
        $this->assertThrows(AuthException::class, fn () => $this->auth->setLocalUser('nouze', 'kratke', '127.0.0.1', 'admin', 'cli'), '16 znaků');
        $this->assertThrows(AuthException::class, fn () => $this->auth->setLocalUser('nouze', str_repeat('x', 16), '', 'admin', 'cli'), 'IP');
        $this->auth->setLocalUser('nouze', 'Velmi-dlouhe-heslo-1', '127.0.0.1, 10.9.0.0/16', 'admin', 'cli');
        $u = $this->auth->verifyPassword('nouze', 'Velmi-dlouhe-heslo-1', '10.9.1.1');
        $this->assertSame('local', $u['source']);
        $this->assertSame(0, $this->dir->calls, 'lokální účet nejde do AD');
        $e = $this->assertThrows(AuthException::class, fn () => $this->auth->verifyPassword('nouze', 'Velmi-dlouhe-heslo-1', '10.10.0.1'));
        $this->assertSame('local_ip_not_allowed', $e->reason());
        $e = $this->assertThrows(AuthException::class, fn () => $this->auth->verifyPassword('nouze', 'spatne', '127.0.0.1'));
        $this->assertSame('local_bad_password', $e->reason());
        // lokální účet nesmí převzít jméno existujícího AD účtu
        $this->auth->verifyPassword('jnovak', 'Heslo123!', '10.0.0.5');
        $this->assertThrows(AuthException::class,
            fn () => $this->auth->setLocalUser('jnovak', 'Velmi-dlouhe-heslo-1', '127.0.0.1', 'admin', 'cli'), 'AD účet');
    }

    public function testDisabledUser(): void
    {
        $u = $this->auth->verifyPassword('jnovak', 'Heslo123!', '10.0.0.5');
        $this->db->update('users', ['is_active' => false], ['id' => $u['id']]);
        $e = $this->assertThrows(AuthException::class, fn () => $this->auth->verifyPassword('jnovak', 'Heslo123!', '10.0.0.5'));
        $this->assertSame('panel_disabled', $e->reason());
        $this->assertThrows(AuthException::class, fn () => $this->auth->activeUser((int) $u['id']));
    }
}
