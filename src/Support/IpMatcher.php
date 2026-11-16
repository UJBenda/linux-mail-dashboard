<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Support;

/** Porovnání IP adresy se seznamem adres/rozsahů CIDR (IPv4 i IPv6). */
final class IpMatcher
{
    /** @param string|list<string> $ranges seznam nebo text oddělený čárkami/mezerami */
    public static function matches(string $ip, string|array $ranges): bool
    {
        $addr = @inet_pton($ip);
        if ($addr === false) {
            return false;
        }
        if (is_string($ranges)) {
            $ranges = preg_split('/[\s,;]+/', $ranges, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        }
        foreach ($ranges as $range) {
            if (self::inRange($addr, trim($range))) {
                return true;
            }
        }
        return false;
    }

    public static function isValidRange(string $range): bool
    {
        [$net, $bits] = array_pad(explode('/', $range, 2), 2, null);
        $bin = @inet_pton((string) $net);
        if ($bin === false) {
            return false;
        }
        return $bits === null || (ctype_digit($bits) && (int) $bits <= strlen($bin) * 8);
    }

    private static function inRange(string $addr, string $range): bool
    {
        if (!self::isValidRange($range)) {
            return false;
        }
        [$net, $bits] = array_pad(explode('/', $range, 2), 2, null);
        $netBin = (string) inet_pton((string) $net);
        if (strlen($netBin) !== strlen($addr)) {
            return false;
        }
        $bits = $bits === null ? strlen($addr) * 8 : (int) $bits;
        $bytes = intdiv($bits, 8);
        if (substr($addr, 0, $bytes) !== substr($netBin, 0, $bytes)) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rest)) & 0xFF;
        return (ord($addr[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask);
    }
}
