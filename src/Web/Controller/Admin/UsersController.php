<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Web\Controller\Admin;

use MailPanel\Web\Controller\Controller;
use MailPanel\Web\HttpException;
use MailPanel\Web\Response;

/**
 * Uživatelé panelu. AD účty vznikají při prvním přihlášení (role z AD), lokální nouzový
 * účet jen z CLI. Zde: přehled, reset MFA, zakázání přístupu do panelu.
 */
final class UsersController extends Controller
{
    public function index(): Response
    {
        $users = $this->app->db()->all('SELECT id, username, display_name, email, source, roles, is_active,
                mfa_enrolled_at, last_login_at, last_login_ip, created_at FROM users ORDER BY username');
        return $this->render('admin/users', ['users' => $users]);
    }

    /** @param array<string,string> $p */
    public function mfaReset(array $p): Response
    {
        $target = $this->target($p);
        $this->app->authenticator()->resetMfa((int) $target['id'], (string) $this->user['username'], $this->req->ip());
        $this->session->flash("MFA uživatele {$target['username']} zrušeno – při příštím přihlášení si ho nastaví znovu.", 'success');
        return $this->redirect('/admin/users');
    }

    /** @param array<string,string> $p */
    public function setActive(array $p): Response
    {
        $target = $this->target($p);
        if ((int) $target['id'] === (int) $this->user['id']) {
            throw new HttpException(400, 'Sám sebe zakázat nelze.');
        }
        $active = $this->req->post('active') === '1';
        $this->app->db()->update('users', ['is_active' => $active], ['id' => $target['id']]);
        $this->audit($active ? 'user.enabled' : 'user.disabled', ['user' => $target['username']]);
        $this->session->flash(($active ? 'Povolen' : 'Zakázán') . " přístup uživatele {$target['username']}.", 'success');
        return $this->redirect('/admin/users');
    }

    /** @param array<string,string> $p @return array<string,mixed> */
    private function target(array $p): array
    {
        $u = $this->app->db()->one('SELECT id, username FROM users WHERE id = ?', [(int) ($p['id'] ?? 0)]);
        if ($u === null) {
            throw new HttpException(404);
        }
        return $u;
    }
}
