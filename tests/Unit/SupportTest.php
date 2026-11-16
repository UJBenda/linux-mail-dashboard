<?php

// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace MailPanel\Tests\Unit;

use MailPanel\Support\Config;
use MailPanel\Support\ConfigException;
use MailPanel\Support\Crypto;
use MailPanel\Support\Db;
use MailPanel\Support\IpMatcher;
use MailPanel\Tests\Support\TestCase;

final class SupportTest extends TestCase
{
    public function testIpMatcher(): void
    {
        $this->assertTrue(IpMatcher::matches('10.1.2.3', '10.0.0.0/8'));
        $this->assertTrue(IpMatcher::matches('10.1.2.3', '192.168.0.0/16, 10.1.2.3'));
        $this->assertFalse(IpMatcher::matches('11.1.2.3', '10.0.0.0/8'));
        $this->assertTrue(IpMatcher::matches('192.168.1.200', '192.168.1.128/25'));
        $this->assertFalse(IpMatcher::matches('192.168.1.100', '192.168.1.128/25'));
        $this->assertTrue(IpMatcher::matches('2001:db8::1', ['2001:db8::/32']));
        $this->assertFalse(IpMatcher::matches('2001:db9::1', ['2001:db8::/32']));
        $this->assertFalse(IpMatcher::matches('10.0.0.1', '::/0'), 'IPv4 neodpovídá IPv6 rozsahu');
        $this->assertTrue(IpMatcher::matches('1.2.3.4', '0.0.0.0/0'));
        $this->assertFalse(IpMatcher::matches('nesmysl', '0.0.0.0/0'));
        $this->assertFalse(IpMatcher::matches('10.0.0.1', '10.0.0.0/33'));
        $this->assertFalse(IpMatcher::matches('10.0.0.1', ''));
        $this->assertFalse(IpMatcher::isValidRange('10.0.0.0/x'));
    }

    public function testCrypto(): void
    {
        $c = new Crypto(Crypto::generateKey());
        $enc = $c->encrypt('tajné ž');
        $this->assertTrue(str_starts_with($enc, 'v1:'));
        $this->assertSame('tajné ž', $c->decrypt($enc));
        $this->assertTrue($c->encrypt('x') !== $c->encrypt('x'), 'náhodný nonce');
        $other = new Crypto(Crypto::generateKey());
        $this->assertThrows(\RuntimeException::class, fn () => $other->decrypt($enc), 'dešifrovat');
        $tampered = substr($enc, 0, -2) . (substr($enc, -2) === 'AA' ? 'BB' : 'AA');
        $this->assertThrows(\RuntimeException::class, fn () => $c->decrypt($tampered));
        $this->assertThrows(ConfigException::class, fn () => new Crypto('krátký'));
    }

    public function testConfig(): void
    {
        $c = new Config(['a' => ['b' => 5, 's' => 'x', 'f' => false], 'list' => [1, 2]]);
        $this->assertSame(5, $c->int('a.b'));
        $this->assertSame('x', $c->string('a.s'));
        $this->assertSame(false, $c->bool('a.f', true));
        $this->assertSame(7, $c->int('a.missing', 7));
        $this->assertSame([1, 2], $c->array('list'));
        $this->assertSame([], $c->array('a.s'));
    }

    public function testDbIdentAndLike(): void
    {
        $this->assertSame('users', Db::ident('users'));
        $this->assertThrows(\InvalidArgumentException::class, fn () => Db::ident('users; DROP TABLE x'));
        $this->assertSame('50\\%\\_a\\\\', Db::likeEscape('50%_a\\'));
    }
}
