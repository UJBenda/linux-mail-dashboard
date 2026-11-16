<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Web\Controller;

use MailPanel\Auth\Roles;
use MailPanel\Support\Migrator;
use MailPanel\Web\Response;
use Throwable;

final class DashboardController extends Controller
{
    public function index(): Response
    {
        $roles = Roles::parse((string) $this->user['roles']);
        $db = $this->app->db();
        $status = [
            'db'      => true,
            'pending' => (new Migrator($db, $this->app->root() . '/db/migrations'))->pending(),
            'audit'   => null,
        ];
        if (Roles::can($roles, 'audit.view')) {
            $status['audit'] = $this->app->audit()->verify();
        }
        $recent = $db->all("SELECT created_at, ip, action, result FROM audit_log
                             WHERE username = ? AND action LIKE 'auth.%' ORDER BY seq DESC LIMIT 5",
            [$this->user['username']]);
        return $this->render('dashboard', ['roles' => $roles, 'status' => $status, 'recent' => $recent]);
    }

    /** Pro dohled (Zabbix apod.): jen „ok“ / „db“, žádné citlivé údaje. */
    public function health(): Response
    {
        try {
            $this->app->db()->value('SELECT 1');
            return Response::text("ok\n");
        } catch (Throwable) {
            return Response::text("db\n", 503);
        }
    }
}
