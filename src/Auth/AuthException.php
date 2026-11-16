<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Auth;

/**
 * Chyba přihlášení: getMessage() je pro uživatele (obecná), reason() pro audit a log.
 */
final class AuthException extends \RuntimeException
{
    public function __construct(string $publicMessage, private string $reason = '')
    {
        parent::__construct($publicMessage);
    }

    public function reason(): string
    {
        return $this->reason !== '' ? $this->reason : $this->getMessage();
    }
}
