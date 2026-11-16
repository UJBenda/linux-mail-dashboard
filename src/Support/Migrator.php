<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Support;

/**
 * Spouští db/migrations/NNN_*.sql v pořadí, každou v transakci.
 * Kontrolní součet chrání proti tichému přepsání už aplikované migrace.
 */
final class Migrator
{
    public function __construct(private Db $db, private string $dir)
    {
    }

    /** @return list<string> aplikované migrace */
    public function migrate(): array
    {
        $this->db->exec('CREATE TABLE IF NOT EXISTS schema_migrations (
            version    text PRIMARY KEY,
            checksum   text NOT NULL,
            applied_at timestamptz NOT NULL DEFAULT now()
        )');
        $done = [];
        foreach ($this->db->all('SELECT version, checksum FROM schema_migrations') as $r) {
            $done[$r['version']] = $r['checksum'];
        }
        $applied = [];
        foreach ($this->files() as $version => $file) {
            $sql = (string) file_get_contents($file);
            $sum = hash('sha256', $sql);
            if (isset($done[$version])) {
                if ($done[$version] !== $sum) {
                    throw new ConfigException("Migrace $version byla po aplikaci změněna (jiný kontrolní součet). "
                        . 'Aplikované migrace se nemění – změnu udělejte novou migrací.');
                }
                continue;
            }
            $this->db->transaction(function (Db $db) use ($sql, $version, $sum): void {
                $db->pdo()->exec($sql);
                $db->insert('schema_migrations', ['version' => $version, 'checksum' => $sum], 'version');
            });
            $applied[] = $version;
        }
        return $applied;
    }

    /** @return list<string> */
    public function pending(): array
    {
        $exists = $this->db->value("SELECT to_regclass('schema_migrations') IS NOT NULL");
        $done = $exists ? array_column($this->db->all('SELECT version FROM schema_migrations'), 'version') : [];
        return array_values(array_diff(array_keys($this->files()), $done));
    }

    /** @return array<string,string> verze => soubor */
    private function files(): array
    {
        $files = [];
        foreach (glob(rtrim($this->dir, '/') . '/[0-9][0-9][0-9]_*.sql') ?: [] as $f) {
            $files[basename($f, '.sql')] = $f;
        }
        ksort($files, SORT_STRING);
        return $files;
    }
}
