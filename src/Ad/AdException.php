<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Ad;

/**
 * Chyba adresářové služby. reason() je technický důvod pro audit a log,
 * uživatel vidí jen obecnou hlášku (neprozrazuje, zda účet existuje).
 */
final class AdException extends \RuntimeException
{
    public const INVALID_CREDENTIALS = 'invalid_credentials';
    public const NOT_FOUND = 'not_found';
    public const ACCOUNT_DISABLED = 'account_disabled';
    public const ACCOUNT_EXPIRED = 'account_expired';
    public const ACCOUNT_LOCKED = 'account_locked';
    public const PASSWORD_EXPIRED = 'password_expired';
    public const MUST_CHANGE_PASSWORD = 'must_change_password';
    public const UNAVAILABLE = 'unavailable';
    public const CONFIG = 'config';

    public function __construct(private string $reason, string $detail = '')
    {
        parent::__construct($detail !== '' ? "$reason: $detail" : $reason);
    }

    public function reason(): string
    {
        return $this->reason;
    }
}
