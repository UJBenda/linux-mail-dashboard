<?php

// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace MailPanel\Tests\Support;

use MailPanel\Support\Audit;
use MailPanel\Support\Db;
use MailPanel\Support\Migrator;

/** Testy nad skutečným PostgreSQL. Schéma se vytvoří jednou za běh, data se mažou před každým testem. */
abstract class DbTestCase extends TestCase
{
    private static bool $migrated = false;
    protected Db $db;
    protected Audit $audit;

    public function setUp(): void
    {
        $dsn = getenv('MAILPANEL_TEST_DSN');
        if ($dsn === false || $dsn === '') {
            $this->skip('MAILPANEL_TEST_DSN není nastaveno');
        }
        $this->db = new Db($dsn, (string) getenv('MAILPANEL_TEST_USER'), (string) getenv('MAILPANEL_TEST_PASSWORD'));
        if (!self::$migrated) {
            $this->db->pdo()->exec('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
            (new Migrator($this->db, dirname(__DIR__, 2) . '/db/migrations'))->migrate();
            self::$migrated = true;
        }
        // audit_log je chráněný proti TRUNCATE – pro testy dočasně vypnout trigger (vyžaduje vlastníka tabulky)
        $this->db->pdo()->exec('ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_truncate;
            TRUNCATE audit_log, users, login_attempts, login_unlock, settings RESTART IDENTITY;
            ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_truncate;');
        $this->audit = new Audit($this->db);
    }
}
