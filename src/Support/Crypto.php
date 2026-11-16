<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Support;

/**
 * Šifrování tajných hodnot v DB (TOTP tajemství, hesla služeb) – libsodium secretbox
 * (XSalsa20-Poly1305, autentizované). Klíč je jen v config.php, ne v DB.
 */
final class Crypto
{
    private const PREFIX = 'v1:';

    private string $key;

    public function __construct(string $base64Key)
    {
        $key = base64_decode($base64Key, true);
        if ($key === false || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new ConfigException('Neplatný secret_key v konfiguraci – vygenerujte: bin/mailpanel key:generate');
        }
        $this->key = $key;
    }

    public static function generateKey(): string
    {
        return base64_encode(sodium_crypto_secretbox_keygen());
    }

    public function encrypt(string $plain): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return self::PREFIX . base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, $this->key));
    }

    public function decrypt(string $stored): string
    {
        if (!str_starts_with($stored, self::PREFIX)) {
            throw new \RuntimeException('Neznámý formát šifrované hodnoty.');
        }
        $raw = base64_decode(substr($stored, strlen(self::PREFIX)), true);
        if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new \RuntimeException('Poškozená šifrovaná hodnota.');
        }
        $plain = sodium_crypto_secretbox_open(
            substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            $this->key,
        );
        if ($plain === false) {
            throw new \RuntimeException('Hodnotu nelze dešifrovat (jiný secret_key, nebo byla změněna).');
        }
        return $plain;
    }
}
