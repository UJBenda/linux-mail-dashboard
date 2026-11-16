<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Ad;

/** Ověření uživatele proti adresáři (AD). Rozhraní kvůli testům. */
interface Directory
{
    /** @throws AdException */
    public function authenticate(string $login, string $password): DirectoryUser;
}
