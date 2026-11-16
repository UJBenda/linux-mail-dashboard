<?php

// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace MailPanel\Tests\Unit;

use MailPanel\Ad\AdClient;
use MailPanel\Ad\AdException;
use MailPanel\Auth\Authenticator;
use MailPanel\Auth\Roles;
use MailPanel\Tests\Support\TestCase;
use MailPanel\Web\HttpException;
use MailPanel\Web\Router;

final class AuthUnitTest extends TestCase
{
    public function testRoles(): void
    {
        $this->assertTrue(Roles::can(['admin'], 'users.manage'));
        $this->assertTrue(Roles::can(['admin'], 'message.body'));
        $this->assertFalse(Roles::can(['security'], 'queue.manage'), 'analytik nezasahuje do pošty');
        $this->assertTrue(Roles::can(['security'], 'logs.view'));
        $this->assertFalse(Roles::can(['auditor'], 'subject.view'), 'auditor nevidí předměty');
        $this->assertTrue(Roles::can(['auditor'], 'audit.view'));
        $this->assertFalse(Roles::can([], 'dashboard.view'));
        $this->assertThrows(\InvalidArgumentException::class, fn () => Roles::can(['security'], 'neexistuje'));
        $this->assertSame(['admin', 'auditor'], Roles::parse('admin, nesmysl,auditor,admin'));
    }

    public function testRolesFromSids(): void
    {
        $map = ['admin' => ['S-1-5-21-1-2-3-1101'], 'auditor' => 'S-1-5-21-1-2-3-1105', 'neznama' => ['S-1-5-21-1-2-3-1']];
        $this->assertSame(['admin'], Roles::fromSids(['S-1-5-21-1-2-3-513', 's-1-5-21-1-2-3-1101'], $map));
        $this->assertSame(['auditor'], Roles::fromSids(['S-1-5-21-1-2-3-1105'], $map));
        $this->assertSame([], Roles::fromSids(['S-1-5-21-1-2-3-1'], $map), 'neznámá role se ignoruje');
    }

    public function testSidToString(): void
    {
        // S-1-5-21-1004336348-1177238915-682003330-512
        $bin = pack('CC', 1, 5) . "\x00\x00\x00\x00\x00\x05" . pack('V*', 21, 1004336348, 1177238915, 682003330, 512);
        $this->assertSame('S-1-5-21-1004336348-1177238915-682003330-512', AdClient::sidToString($bin));
        $this->assertSame('', AdClient::sidToString('xx'));
    }

    public function testNormalizeLoginAndThrottleKey(): void
    {
        $this->assertSame('jnovak', AdClient::normalizeLogin('FIRMA\\jnovak'));
        $this->assertSame('jnovak', AdClient::normalizeLogin(' jnovak@Firma.Local ', 'firma.local'));
        $this->assertSame('jnovak@jina.cz', AdClient::normalizeLogin('jnovak@jina.cz', 'firma.local'));
        $this->assertSame('jnovak', Authenticator::throttleKey('FIRMA\\JNovak'));
        $this->assertSame('jnovak', Authenticator::throttleKey('jnovak@firma.local'));
    }

    public function testAccountExpires(): void
    {
        $now = 1_700_000_000;
        $toFiletime = fn (int $unix) => (string) (($unix + 11_644_473_600) * 10_000_000);
        $this->assertFalse(AdClient::isExpired('0', $now));
        $this->assertFalse(AdClient::isExpired('9223372036854775807', $now));
        $this->assertTrue(AdClient::isExpired($toFiletime($now - 60), $now));
        $this->assertFalse(AdClient::isExpired($toFiletime($now + 86400), $now));
    }

    public function testDiagnosticReasons(): void
    {
        $d = '80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data %s, v4563';
        $this->assertSame(AdException::INVALID_CREDENTIALS, AdClient::reasonFromDiagnostic(sprintf($d, '52e')));
        $this->assertSame(AdException::ACCOUNT_LOCKED, AdClient::reasonFromDiagnostic(sprintf($d, '775')));
        $this->assertSame(AdException::ACCOUNT_DISABLED, AdClient::reasonFromDiagnostic(sprintf($d, '533')));
        $this->assertSame(AdException::PASSWORD_EXPIRED, AdClient::reasonFromDiagnostic(sprintf($d, '532')));
        $this->assertSame(AdException::MUST_CHANGE_PASSWORD, AdClient::reasonFromDiagnostic(sprintf($d, '773')));
        $this->assertSame(AdException::INVALID_CREDENTIALS, AdClient::reasonFromDiagnostic('něco jiného'));
    }

    public function testEmptyPasswordNeverReachesLdap(): void
    {
        $ad = new AdClient([['host' => 'dc.invalid', 'port' => 636, 'mode' => 'ldaps']], 'DC=x', 'CN=svc', 'pw');
        $e = $this->assertThrows(AdException::class, fn () => $ad->authenticate('jnovak', ''));
        $this->assertSame(AdException::INVALID_CREDENTIALS, $e->reason());
    }

    public function testRouter(): void
    {
        $r = new Router();
        $r->add('GET', '/', ['C', 'index'], 'dashboard.view');
        $r->add('POST', '/admin/users/{id}/active', ['C', 'active'], 'users.manage');
        $m = $r->match('POST', '/admin/users/42/active');
        $this->assertSame('42', $m['params']['id']);
        $this->assertSame('users.manage', $m['permission']);
        $e = $this->assertThrows(HttpException::class, fn () => $r->match('POST', '/admin/users/x/active'));
        $this->assertSame(404, $e->status);
        $e = $this->assertThrows(HttpException::class, fn () => $r->match('GET', '/admin/users/1/active'));
        $this->assertSame(405, $e->status);
    }
}
