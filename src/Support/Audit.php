<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Support;

use Throwable;

/**
 * Auditní záznam. Integritu (hash chain) zajišťuje DB trigger – viz 001_init.sql.
 * Zápis auditu nesmí shodit požadavek, ale jeho selhání se musí projevit v logu systému.
 */
final class Audit
{
    private ?string $username = null;
    private ?string $ip = null;

    public function __construct(private Db $db)
    {
    }

    /** Výchozí kontext (přihlášený uživatel, IP) pro další záznamy. */
    public function setActor(?string $username, ?string $ip): void
    {
        $this->username = $username;
        $this->ip = $ip;
    }

    /** @param array<string,mixed> $details */
    public function log(string $action, array $details = [], string $result = 'ok', ?string $username = null, ?string $ip = null): void
    {
        try {
            $this->db->exec(
                'INSERT INTO audit_log (username, ip, action, result, details) VALUES (?, ?::inet, ?, ?, ?::jsonb)',
                [
                    $username ?? $this->username,
                    $ip ?? $this->ip,
                    $action,
                    $result,
                    // vždy JSON objekt (i prázdný), ne pole
                    json_encode((object) $details, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
                ],
            );
        } catch (Throwable $e) {
            error_log('[mailpanel] AUDIT ZÁPIS SELHAL: ' . $action . ' – ' . $e->getMessage());
            if (function_exists('syslog')) {
                syslog(LOG_ERR, 'mailpanel: audit write failed: ' . $action);
            }
        }
    }

    /** @return array{ok:bool, seq:?int, problem:?string, count:int, head:?string} */
    public function verify(): array
    {
        $bad = $this->db->one('SELECT seq, problem FROM audit_log_verify()');
        $head = $this->db->one('SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1');
        return [
            'ok'      => $bad === null,
            'seq'     => $bad !== null ? (int) $bad['seq'] : null,
            'problem' => $bad['problem'] ?? null,
            'count'   => (int) $this->db->value('SELECT count(*) FROM audit_log'),
            'head'    => $head !== null ? $head['seq'] . ':' . $head['hash'] : null,
        ];
    }

    /** Hlava řetězu do syslogu (authpriv) → centrální log/SIEM. */
    public function anchor(): ?string
    {
        $head = $this->db->one('SELECT seq, hash, created_at FROM audit_log ORDER BY seq DESC LIMIT 1');
        if ($head === null) {
            return null;
        }
        $msg = sprintf('mailpanel audit anchor seq=%d hash=%s at=%s', $head['seq'], $head['hash'], $head['created_at']);
        openlog('mailpanel', LOG_PID, LOG_AUTHPRIV);
        syslog(LOG_NOTICE, $msg);
        closelog();
        return $msg;
    }
}
