<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Ad;

/** Ověřený uživatel z adresáře. */
final readonly class DirectoryUser
{
    /** @param list<string> $groupSids SID všech skupin (včetně vnořených) */
    public function __construct(
        public string $dn,
        public string $username,
        public string $displayName,
        public ?string $email,
        public array $groupSids,
    ) {
    }
}
