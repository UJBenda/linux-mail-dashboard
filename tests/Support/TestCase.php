<?php

// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace MailPanel\Tests\Support;

final class SkipTest extends \RuntimeException
{
}

final class AssertionFailed extends \RuntimeException
{
}

abstract class TestCase
{
    public function setUp(): void
    {
    }

    public function tearDown(): void
    {
    }

    protected function assertSame(mixed $expected, mixed $actual, string $msg = ''): void
    {
        if ($expected !== $actual) {
            throw new AssertionFailed(($msg !== '' ? "$msg: " : '') . 'očekáváno ' . var_export($expected, true) . ', je ' . var_export($actual, true));
        }
    }

    protected function assertTrue(bool $v, string $msg = 'očekáváno true'): void
    {
        if (!$v) {
            throw new AssertionFailed($msg);
        }
    }

    protected function assertFalse(bool $v, string $msg = 'očekáváno false'): void
    {
        $this->assertTrue(!$v, $msg);
    }

    protected function assertNull(mixed $v, string $msg = ''): void
    {
        $this->assertSame(null, $v, $msg);
    }

    protected function assertContains(string $needle, string $haystack, string $msg = ''): void
    {
        if (!str_contains($haystack, $needle)) {
            throw new AssertionFailed(($msg !== '' ? "$msg: " : '') . "text neobsahuje „{$needle}“");
        }
    }

    /**
     * @param class-string<\Throwable> $class
     */
    protected function assertThrows(string $class, callable $fn, string $messagePart = ''): \Throwable
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            if (!$e instanceof $class) {
                throw new AssertionFailed("očekávána výjimka $class, přišla " . $e::class . ': ' . $e->getMessage());
            }
            if ($messagePart !== '' && !str_contains($e->getMessage(), $messagePart)) {
                throw new AssertionFailed("zpráva výjimky „{$e->getMessage()}“ neobsahuje „{$messagePart}“");
            }
            return $e;
        }
        throw new AssertionFailed("očekávána výjimka $class");
    }

    protected function skip(string $why): never
    {
        throw new SkipTest($why);
    }
}
