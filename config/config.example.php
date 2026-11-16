<?php
// Konfigurace Linux Mail Dashboard – zkopírujte do config/config.php a upravte.
// Soubor obsahuje tajné údaje: vlastník root, skupina mailpanel, práva 0640.
//
// Ostatní nastavení (AD, role, prahy upozornění, retence) se mění v portálu.

return [
    // Vlastní databáze panelu (PostgreSQL)
    'db' => [
        'dsn'      => 'pgsql:host=/var/run/postgresql;dbname=mailpanel',
        'user'     => 'mailpanel_web',
        'password' => '',
    ],

    // Databáze iRedMailu – jen pro čtení (samostatný účet s GRANT SELECT bez sloupce password).
    // MariaDB: 'mysql:host=127.0.0.1;dbname=vmail;charset=utf8mb4'
    'iredmail' => [
        'vmail'   => ['dsn' => 'pgsql:host=127.0.0.1;dbname=vmail',   'user' => 'mailpanel_ro', 'password' => 'ZMENIT'],
        'amavisd' => ['dsn' => 'pgsql:host=127.0.0.1;dbname=amavisd', 'user' => 'mailpanel_ro', 'password' => 'ZMENIT'],
        'iredapd' => ['dsn' => 'pgsql:host=127.0.0.1;dbname=iredapd', 'user' => 'mailpanel_ro', 'password' => 'ZMENIT'],
    ],

    // Zdroje logů pro collector – ověřte cesty v /etc/rsyslog.d/ a /etc/dovecot/conf.d/
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

    // Klíč pro šifrování tajných hodnot v DB (servisní účet AD, tokeny webhooků).
    // Vygenerujte: bin/mailpanel key:generate
    'secret_key' => '',

    'timezone'  => 'Europe/Prague',
    'base_path' => '',
    'var_dir'   => __DIR__ . '/../var',

    'session' => [
        'idle_minutes'   => 30,
        'absolute_hours' => 8,
        'cookie_secure'  => true,
    ],
];
