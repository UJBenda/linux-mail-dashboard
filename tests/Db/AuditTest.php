<?php

// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace MailPanel\Tests\Db;

use MailPanel\Support\ConfigException;
use MailPanel\Support\Migrator;
use MailPanel\Tests\Support\DbTestCase;

final class AuditTest extends DbTestCase
{
    public function testChainAndVerify(): void
    {
        $this->audit->log('a', ['x' => 1, 'text' => 'žluťoučký'], 'ok', 'jnovak', '10.0.0.1');
        $this->audit->setActor('pdvorak', '2001:db8::5');
        $this->audit->log('b', [], 'fail');
        $this->audit->log('c');
        $rows = $this->db->all('SELECT * FROM audit_log ORDER BY seq');
        $this->assertSame(3, count($rows));
        $this->assertSame(str_repeat('0', 64), $rows[0]['prev_hash']);
        $this->assertSame($rows[0]['hash'], $rows[1]['prev_hash']);
        $this->assertSame('pdvorak', $rows[2]['username']);
        $this->assertSame('2001:db8::5', $rows[2]['ip']);
        $v = $this->audit->verify();
        $this->assertTrue($v['ok']);
        $this->assertSame(3, $v['count']);
    }

    public function testImmutable(): void
    {
        $this->audit->log('a');
        $this->assertThrows(\PDOException::class, fn () => $this->db->exec("UPDATE audit_log SET action = 'x'"), 'jen pro zápis');
        $this->assertThrows(\PDOException::class, fn () => $this->db->exec('DELETE FROM audit_log'), 'jen pro zápis');
        $this->assertThrows(\PDOException::class, fn () => $this->db->exec('TRUNCATE audit_log'), 'jen pro zápis');
    }

    public function testTamperingDetected(): void
    {
        foreach (['a', 'b', 'c', 'd'] as $a) {
            $this->audit->log($a);
        }
        // útočník s právy vlastníka vypne ochranu a změní záznam
        $this->db->pdo()->exec("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update;
            UPDATE audit_log SET details = '{\"skryto\":true}' WHERE seq = 2;
            ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update;");
        $v = $this->audit->verify();
        $this->assertFalse($v['ok']);
        $this->assertSame(2, $v['seq']);

        // smazání záznamu uprostřed
        $this->db->pdo()->exec("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update;
            UPDATE audit_log SET details = '{}' WHERE seq = 2;
            DELETE FROM audit_log WHERE seq = 3;
            ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update;");
        $v = $this->audit->verify();
        $this->assertFalse($v['ok']);
        $this->assertSame(4, $v['seq']);
    }

    public function testMigratorDetectsChangedMigration(): void
    {
        $dir = sys_get_temp_dir() . '/mp-mig-' . bin2hex(random_bytes(4));
        mkdir($dir);
        try {
            $this->db->pdo()->exec('DROP TABLE IF EXISTS mig_test; DELETE FROM schema_migrations WHERE version LIKE \'900_%\'');
            file_put_contents("$dir/900_test.sql", 'CREATE TABLE mig_test (id int);');
            $m = new Migrator($this->db, $dir);
            $this->assertSame(['900_test'], $m->migrate());
            $this->assertSame([], $m->migrate());
            file_put_contents("$dir/900_test.sql", 'CREATE TABLE mig_test (id bigint);');
            $this->assertThrows(ConfigException::class, fn () => $m->migrate(), 'změněna');
        } finally {
            $this->db->pdo()->exec('DROP TABLE IF EXISTS mig_test; DELETE FROM schema_migrations WHERE version LIKE \'900_%\'');
            array_map('unlink', glob("$dir/*") ?: []);
            rmdir($dir);
        }
    }
}
