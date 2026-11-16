<?php

// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace MailPanel\Tests\Unit;

use MailPanel\Auth\Totp;
use MailPanel\Tests\Support\TestCase;

final class TotpTest extends TestCase
{
    // RFC 6238, příloha B – SHA1, klíč "12345678901234567890"
    private const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    public function testRfc6238Vectors(): void
    {
        foreach ([59 => '94287082', 1111111109 => '07081804', 1111111111 => '14050471',
                  1234567890 => '89005924', 2000000000 => '69279037', 20000000000 => '65353130'] as $t => $code) {
            $this->assertSame($code, Totp::code(self::SECRET, intdiv($t, 30), 8), "T=$t");
        }
    }

    public function testBase32Roundtrip(): void
    {
        $this->assertSame(self::SECRET, Totp::base32Encode('12345678901234567890'));
        $this->assertSame('12345678901234567890', Totp::base32Decode(strtolower(self::SECRET)));
        $s = Totp::generateSecret();
        $this->assertSame(32, strlen($s));
        $this->assertSame(20, strlen(Totp::base32Decode($s)));
    }

    public function testVerifyWindowAndReplay(): void
    {
        $now = 1_700_000_000;
        $step = intdiv($now, 30);
        $code = Totp::code(self::SECRET, $step);
        $this->assertSame($step, Totp::verify(self::SECRET, $code, null, $now));
        $this->assertSame($step, Totp::verify(self::SECRET, substr($code, 0, 3) . ' ' . substr($code, 3), null, $now), 'mezera');
        $this->assertSame($step - 1, Totp::verify(self::SECRET, Totp::code(self::SECRET, $step - 1), null, $now), 'předchozí krok');
        $this->assertNull(Totp::verify(self::SECRET, Totp::code(self::SECRET, $step - 2), null, $now), 'mimo okno');
        $this->assertNull(Totp::verify(self::SECRET, $code, $step, $now), 'opakované použití');
        $this->assertNull(Totp::verify(self::SECRET, 'abcdef', null, $now));
        $this->assertNull(Totp::verify(self::SECRET, '', null, $now));
    }

    public function testUri(): void
    {
        $uri = Totp::uri(self::SECRET, 'jan novák', 'Mail Dashboard');
        $this->assertContains('otpauth://totp/Mail%20Dashboard:jan%20nov%C3%A1k?secret=' . self::SECRET, $uri);
    }
}
