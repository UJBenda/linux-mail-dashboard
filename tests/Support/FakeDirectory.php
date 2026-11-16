<?php

// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace MailPanel\Tests\Support;

use MailPanel\Ad\AdException;
use MailPanel\Ad\Directory;
use MailPanel\Ad\DirectoryUser;

/** Testovací adresář: login => [heslo, SID skupin, důvod chyby]. */
final class FakeDirectory implements Directory
{
    public int $calls = 0;

    /** @param array<string, array{password:string, sids?:list<string>, error?:string}> $users */
    public function __construct(private array $users)
    {
    }

    public function authenticate(string $login, string $password): DirectoryUser
    {
        $this->calls++;
        $login = strtolower(\MailPanel\Ad\AdClient::normalizeLogin($login));
        $u = $this->users[$login] ?? null;
        if ($u === null) {
            throw new AdException(AdException::NOT_FOUND, $login);
        }
        if (isset($u['error'])) {
            throw new AdException($u['error'], $login);
        }
        if ($password !== $u['password']) {
            throw new AdException(AdException::INVALID_CREDENTIALS, $login);
        }
        return new DirectoryUser("CN=$login,DC=test", $login, ucfirst($login), "$login@example.org", $u['sids'] ?? []);
    }
}
