<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Support;

use PDO;
use PDOStatement;
use Throwable;

/**
 * Tenká vrstva nad PDO (PostgreSQL). Vždy parametrizované dotazy;
 * jména tabulek a sloupců v insert()/update() se ověřují proti whitelistu znaků.
 */
final class Db
{
    private ?PDO $pdo = null;

    public function __construct(
        private string $dsn,
        private string $user = '',
        private string $password = '',
    ) {
    }

    public static function fromConfig(Config $config, string $section = 'db'): self
    {
        $dsn = $config->string("$section.dsn");
        if ($dsn === '') {
            throw new ConfigException("V konfiguraci chybí $section.dsn.");
        }
        return new self($dsn, $config->string("$section.user"), $config->string("$section.password"));
    }

    public function pdo(): PDO
    {
        if ($this->pdo === null) {
            $this->pdo = new PDO($this->dsn, $this->user ?: null, $this->password ?: null, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);
            $this->pdo->exec("SET TIME ZONE 'UTC'");
        }
        return $this->pdo;
    }

    /** @param array<int|string,mixed> $params */
    public function query(string $sql, array $params = []): PDOStatement
    {
        $stmt = $this->pdo()->prepare($sql);
        $list = array_is_list($params);
        foreach ($params as $k => $v) {
            $name = $list ? (int) $k + 1 : (str_starts_with((string) $k, ':') ? (string) $k : ":$k");
            $stmt->bindValue($name, $v, match (true) {
                is_int($v)  => PDO::PARAM_INT,
                is_bool($v) => PDO::PARAM_BOOL,
                $v === null => PDO::PARAM_NULL,
                default     => PDO::PARAM_STR,
            });
        }
        $stmt->execute();
        return $stmt;
    }

    /** @param array<int|string,mixed> $params @return array<string,mixed>|null */
    public function one(string $sql, array $params = []): ?array
    {
        $row = $this->query($sql, $params)->fetch();
        return $row === false ? null : $row;
    }

    /** @param array<int|string,mixed> $params @return list<array<string,mixed>> */
    public function all(string $sql, array $params = []): array
    {
        return $this->query($sql, $params)->fetchAll();
    }

    /** @param array<int|string,mixed> $params */
    public function value(string $sql, array $params = []): mixed
    {
        $v = $this->query($sql, $params)->fetchColumn();
        return $v === false ? null : $v;
    }

    /** @param array<int|string,mixed> $params */
    public function exec(string $sql, array $params = []): int
    {
        return $this->query($sql, $params)->rowCount();
    }

    /** @param array<string,mixed> $row */
    public function insert(string $table, array $row, string $returning = 'id'): mixed
    {
        $cols = array_map(self::ident(...), array_keys($row));
        $sql = sprintf(
            'INSERT INTO %s (%s) VALUES (%s) RETURNING %s',
            self::ident($table),
            implode(', ', $cols),
            implode(', ', array_fill(0, count($row), '?')),
            self::ident($returning),
        );
        return $this->value($sql, array_values($row));
    }

    /** @param array<string,mixed> $set @param array<string,mixed> $where */
    public function update(string $table, array $set, array $where): int
    {
        $sets = [];
        $conds = [];
        foreach (array_keys($set) as $c) {
            $sets[] = self::ident($c) . ' = ?';
        }
        foreach (array_keys($where) as $c) {
            $conds[] = self::ident($c) . ' = ?';
        }
        $sql = sprintf('UPDATE %s SET %s WHERE %s', self::ident($table), implode(', ', $sets), implode(' AND ', $conds));
        return $this->exec($sql, [...array_values($set), ...array_values($where)]);
    }

    /**
     * @template T
     * @param callable(self):T $fn
     * @return T
     */
    public function transaction(callable $fn): mixed
    {
        $pdo = $this->pdo();
        $pdo->beginTransaction();
        try {
            $result = $fn($this);
            $pdo->commit();
            return $result;
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
    }

    public static function ident(string $name): string
    {
        if (!preg_match('/^[a-z_][a-z0-9_]*$/', $name)) {
            throw new \InvalidArgumentException("Neplatný identifikátor: $name");
        }
        return $name;
    }

    /** Escapuje % a _ pro LIKE/ILIKE (s výchozím ESCAPE '\'). */
    public static function likeEscape(string $s): string
    {
        return addcslashes($s, '%_\\');
    }
}
