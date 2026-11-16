<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Support;

/**
 * Konfigurace z config/config.php (pole). Přístup tečkovou notací: get('session.idle_minutes').
 */
final class Config
{
    /** @param array<string,mixed> $data */
    public function __construct(private array $data)
    {
    }

    public static function load(string $file): self
    {
        if (!is_file($file)) {
            throw new ConfigException("Chybí konfigurace $file – zkopírujte config/config.example.php a upravte.");
        }
        if (!is_readable($file)) {
            throw new ConfigException("Konfiguraci $file nelze číst (práva: root:mailpanel 0640).");
        }
        $data = require $file;
        if (!is_array($data)) {
            throw new ConfigException("Konfigurace $file musí vracet pole.");
        }
        return new self($data);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $node = $this->data;
        foreach (explode('.', $key) as $part) {
            if (!is_array($node) || !array_key_exists($part, $node)) {
                return $default;
            }
            $node = $node[$part];
        }
        return $node;
    }

    public function string(string $key, string $default = ''): string
    {
        $v = $this->get($key, $default);
        return is_scalar($v) ? (string) $v : $default;
    }

    public function int(string $key, int $default = 0): int
    {
        $v = $this->get($key, $default);
        return is_numeric($v) ? (int) $v : $default;
    }

    public function bool(string $key, bool $default = false): bool
    {
        $v = $this->get($key, $default);
        return is_bool($v) ? $v : $default;
    }

    /** @return array<mixed> */
    public function array(string $key): array
    {
        $v = $this->get($key, []);
        return is_array($v) ? $v : [];
    }
}
