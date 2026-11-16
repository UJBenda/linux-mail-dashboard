<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Auth;

/**
 * Role a oprávnění. Role se přidělují skupinami AD (SID), oprávnění jsou pevně v kódu
 * – princip nejmenších oprávnění a oddělení rolí (NIS2).
 */
final class Roles
{
    public const ADMIN = 'admin';
    public const SECURITY = 'security';
    public const OPERATOR = 'operator';
    public const HELPDESK = 'helpdesk';
    public const AUDITOR = 'auditor';

    public const LABELS = [
        self::ADMIN    => 'Administrátor',
        self::SECURITY => 'Bezpečnostní analytik',
        self::OPERATOR => 'Operátor pošty',
        self::HELPDESK => 'Helpdesk',
        self::AUDITOR  => 'Auditor',
    ];

    public const DESCRIPTIONS = [
        self::ADMIN    => 'vše včetně uživatelů panelu, nastavení a obsahu zpráv (s auditem)',
        self::SECURITY => 'logy, bezpečnostní události, hledání útoků, audit – bez zásahů do pošty',
        self::OPERATOR => 'logy, trasování, fronta a karanténa včetně akcí',
        self::HELPDESK => 'trasování zpráv, schránky, uvolnění zprávy z karantény jednomu příjemci',
        self::AUDITOR  => 'jen čtení: přehledy, statistiky a auditní záznam, bez předmětů zpráv',
    ];

    /** Oprávnění → role, které ho mají. Admin má vše. */
    private const PERMISSIONS = [
        'dashboard.view'        => [self::SECURITY, self::OPERATOR, self::HELPDESK, self::AUDITOR],
        'audit.view'            => [self::SECURITY, self::AUDITOR],
        'logs.view'             => [self::SECURITY, self::OPERATOR],
        'trace.view'            => [self::SECURITY, self::OPERATOR, self::HELPDESK],
        'subject.view'          => [self::SECURITY, self::OPERATOR, self::HELPDESK],
        'security.view'         => [self::SECURITY],
        'mailbox.view'          => [self::SECURITY, self::OPERATOR, self::HELPDESK],
        'queue.view'            => [self::SECURITY, self::OPERATOR],
        'queue.manage'          => [self::OPERATOR],
        'quarantine.view'       => [self::SECURITY, self::OPERATOR, self::HELPDESK],
        'quarantine.release'    => [self::OPERATOR, self::HELPDESK],
        'quarantine.manage'     => [self::OPERATOR],
        'message.body'          => [],
        'users.manage'          => [],
        'settings.manage'       => [],
    ];

    /** @param list<string> $roles */
    public static function can(array $roles, string $permission): bool
    {
        if (in_array(self::ADMIN, $roles, true)) {
            return true;
        }
        if (!isset(self::PERMISSIONS[$permission])) {
            throw new \InvalidArgumentException("Neznámé oprávnění $permission");
        }
        return array_intersect($roles, self::PERMISSIONS[$permission]) !== [];
    }

    /** @return list<string> */
    public static function parse(string $roles): array
    {
        $out = [];
        foreach (explode(',', $roles) as $r) {
            $r = trim($r);
            if (isset(self::LABELS[$r]) && !in_array($r, $out, true)) {
                $out[] = $r;
            }
        }
        return $out;
    }

    /** @param list<string> $roles */
    public static function join(array $roles): string
    {
        return implode(',', self::parse(implode(',', $roles)));
    }

    /**
     * Role podle SID skupin uživatele.
     * @param list<string> $userSids
     * @param array<string, list<string>|string> $roleGroups role => SID nebo seznam SID
     * @return list<string>
     */
    public static function fromSids(array $userSids, array $roleGroups): array
    {
        $userSids = array_map('strtoupper', $userSids);
        $roles = [];
        foreach ($roleGroups as $role => $sids) {
            if (!isset(self::LABELS[$role])) {
                continue;
            }
            foreach ((array) $sids as $sid) {
                if (in_array(strtoupper(trim((string) $sid)), $userSids, true)) {
                    $roles[] = $role;
                    break;
                }
            }
        }
        return $roles;
    }
}
