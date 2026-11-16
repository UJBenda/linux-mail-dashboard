<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Web\Controller\Admin;

use MailPanel\Support\Db;
use MailPanel\Support\IpMatcher;
use MailPanel\Web\Controller\Controller;
use MailPanel\Web\Response;

final class AuditController extends Controller
{
    private const PER_PAGE = 100;

    public function index(): Response
    {
        $f = [
            'user'   => $this->req->query('user'),
            'action' => $this->req->query('action'),
            'result' => $this->req->query('result'),
            'ip'     => $this->req->query('ip'),
            'from'   => $this->req->query('from'),
            'to'     => $this->req->query('to'),
        ];
        [$where, $params] = $this->filter($f);
        $db = $this->app->db();

        if ($this->req->query('format') === 'csv') {
            $this->audit('audit.export', ['filter' => array_filter($f)]);
            return $this->csv($db->all("SELECT * FROM audit_log $where ORDER BY seq", $params));
        }

        $verify = null;
        if ($this->req->query('verify') === '1') {
            $verify = $this->app->audit()->verify();
            $this->audit('audit.verify', ['ok' => $verify['ok'], 'seq' => $verify['seq']], $verify['ok'] ? 'ok' : 'fail');
        }

        $page = max(1, (int) $this->req->query('page', '1'));
        $total = (int) $db->value("SELECT count(*) FROM audit_log $where", $params);
        $rows = $db->all("SELECT * FROM audit_log $where ORDER BY seq DESC LIMIT " . self::PER_PAGE
            . ' OFFSET ' . (($page - 1) * self::PER_PAGE), $params);

        return $this->render('admin/audit', [
            'rows'    => $rows,
            'filter'  => $f,
            'page'    => $page,
            'pages'   => max(1, (int) ceil($total / self::PER_PAGE)),
            'total'   => $total,
            'verify'  => $verify,
            'actions' => array_column($db->all('SELECT DISTINCT action FROM audit_log ORDER BY action'), 'action'),
        ]);
    }

    /**
     * @param array<string,string> $f
     * @return array{0:string, 1:list<mixed>}
     */
    private function filter(array $f): array
    {
        $w = [];
        $p = [];
        if ($f['user'] !== '') {
            $w[] = "username ILIKE ? ESCAPE '\\'";
            $p[] = '%' . Db::likeEscape($f['user']) . '%';
        }
        if ($f['action'] !== '') {
            $w[] = 'action = ?';
            $p[] = $f['action'];
        }
        if (in_array($f['result'], ['ok', 'fail', 'denied'], true)) {
            $w[] = 'result = ?';
            $p[] = $f['result'];
        }
        if ($f['ip'] !== '' && IpMatcher::isValidRange($f['ip'])) {
            $w[] = 'ip <<= ?::inet';
            $p[] = $f['ip'];
        }
        foreach (['from' => '>=', 'to' => '<'] as $k => $op) {
            if ($f[$k] !== '' && ($d = \DateTimeImmutable::createFromFormat('!Y-m-d', $f[$k])) !== false) {
                $w[] = "created_at $op ?::timestamptz";
                $p[] = ($k === 'to' ? $d->modify('+1 day') : $d)->format('Y-m-d\TH:i:sP');
            }
        }
        return [$w !== [] ? 'WHERE ' . implode(' AND ', $w) : '', $p];
    }

    /** @param list<array<string,mixed>> $rows */
    private function csv(array $rows): Response
    {
        $out = fopen('php://temp', 'w+');
        fwrite($out, "\xEF\xBB\xBF");
        fputcsv($out, ['seq', 'created_at', 'username', 'ip', 'action', 'result', 'details', 'prev_hash', 'hash'], ';', '"', '');
        foreach ($rows as $r) {
            $line = [$r['seq'], $r['created_at'], $r['username'], $r['ip'], $r['action'], $r['result'], $r['details'], $r['prev_hash'], $r['hash']];
            // ochrana proti CSV/formula injection v Excelu
            $line = array_map(static fn ($v) => is_string($v) && preg_match('/^[=+\-@\t\r]/', $v) ? "'" . $v : $v, $line);
            fputcsv($out, $line, ';', '"', '');
        }
        rewind($out);
        $body = (string) stream_get_contents($out);
        return new Response($body, 200, [
            'Content-Type'        => 'text/csv; charset=utf-8',
            'Content-Disposition' => 'attachment; filename="audit-' . date('Ymd-His') . '.csv"',
        ]);
    }
}
