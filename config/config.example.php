<?php
// Konfigurace Linux Mail Dashboard – zkopírujte do config/config.php a upravte.
// Obsahuje tajné údaje: vlastník root, skupina mailpanel, práva 0640.
// Změny tohoto souboru evidujte (změnové řízení) – soubor není v gitu.

return [
    'app_name' => 'Mail Dashboard',

    // Vlastní databáze panelu (PostgreSQL). Web se připojuje rolí mailpanel_web,
    // migrace (bin/mailpanel migrate) spouštějte s MAILPANEL_CONFIG na konfiguraci vlastníka.
    'db' => [
        'dsn'      => 'pgsql:host=/var/run/postgresql;dbname=mailpanel',
        'user'     => 'mailpanel_web',
        'password' => '',
    ],

    // Databáze iRedMailu – jen pro čtení (krok 2+). Účet bez přístupu ke sloupci password.
    // MariaDB: 'mysql:host=127.0.0.1;dbname=vmail;charset=utf8mb4'
    'iredmail' => [
        'vmail'   => ['dsn' => 'pgsql:host=127.0.0.1;dbname=vmail',   'user' => 'mailpanel_ro', 'password' => 'ZMENIT'],
        'amavisd' => ['dsn' => 'pgsql:host=127.0.0.1;dbname=amavisd', 'user' => 'mailpanel_ro', 'password' => 'ZMENIT'],
        'iredapd' => ['dsn' => 'pgsql:host=127.0.0.1;dbname=iredapd', 'user' => 'mailpanel_ro', 'password' => 'ZMENIT'],
    ],

    // Zdroje logů pro collector (krok 2) – ověřte cesty v /etc/rsyslog.d/ a /etc/dovecot/conf.d/
    'collector' => [
        'input'   => 'file',   // 'file' nebo 'journald'
        'sources' => [
            '/var/log/mail.log',
            '/var/log/dovecot/imap.log',
            '/var/log/dovecot/pop3.log',
            '/var/log/dovecot/lmtp.log',
            '/var/log/iredapd/iredapd.log',
        ],
    ],

    // Active Directory – přihlášení do panelu
    'ad' => [
        // Řadiče v pořadí; při nedostupnosti se zkouší další. mode: 'ldaps' (636) nebo 'starttls' (389).
        'servers' => [
            ['host' => 'dc1.firma.local', 'port' => 636, 'mode' => 'ldaps'],
            ['host' => 'dc2.firma.local', 'port' => 636, 'mode' => 'ldaps'],
        ],
        // CA, která podepsala certifikáty řadičů (PEM). Prázdné = systémové úložiště.
        'ca_file'       => '/etc/mailpanel/ad-ca.pem',
        'base_dn'       => 'DC=firma,DC=local',
        // Servisní účet jen pro čtení (vyhledání uživatele). Nedávejte mu žádná práva navíc.
        'bind_dn'       => 'CN=svc-mailpanel,OU=Service Accounts,DC=firma,DC=local',
        'bind_password' => '',
        // Přihlášení jako „jnovak“, „FIRMA\jnovak“ i „jnovak@firma.local“
        'upn_suffix'    => 'firma.local',
        'timeout'       => 5,
        // Role → SID skupin AD (zjistíte: bin/mailpanel ad:groups <název>).
        // SID se nemění při přejmenování skupiny. Vnořené skupiny se počítají.
        'role_groups' => [
            'admin'    => ['S-1-5-21-0000000000-0000000000-0000000000-1101'],
            'security' => [],
            'operator' => [],
            'helpdesk' => [],
            'auditor'  => [],
        ],
    ],

    // Dvoufázové ověření (TOTP) je povinné pro všechny účty.
    'mfa' => [
        'issuer' => 'Mail Dashboard',   // název v ověřovací aplikaci
    ],

    // Omezení pokusů o přihlášení
    'security' => [
        'max_fails_user'  => 5,
        'max_fails_ip'    => 20,
        'lockout_minutes' => 15,
    ],

    // Klíč pro šifrování tajných hodnot v DB (MFA tajemství, hesla služeb).
    // Vygenerujte: bin/mailpanel key:generate
    'secret_key' => '',

    'timezone'  => 'Europe/Prague',
    // URL prefix, pokud panel neběží v kořeni vhostu (např. '/mailpanel'). Prázdné = kořen.
    'base_path' => '',

    'session' => [
        'idle_minutes'   => 15,   // odhlášení po nečinnosti
        'absolute_hours' => 8,    // maximální délka přihlášení
        'cookie_secure'  => true, // jen přes HTTPS; false jen pro lokální test
    ],
];
