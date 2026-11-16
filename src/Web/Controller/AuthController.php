<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Web\Controller;

use MailPanel\Auth\AuthException;
use MailPanel\Auth\Totp;
use MailPanel\Web\Response;

/** Přihlášení: heslo (AD / nouzový účet) → TOTP (povinné pro všechny). */
final class AuthController extends Controller
{
    public function loginForm(): Response
    {
        if ($this->session->userId() !== null) {
            return $this->redirect('/');
        }
        return $this->render('auth/login', ['expired' => $this->session->wasExpired(), 'error' => null, 'username' => '']);
    }

    public function login(): Response
    {
        $username = $this->req->post('username');
        try {
            $user = $this->app->authenticator()->verifyPassword($username, $this->req->post('password'), $this->req->ip());
        } catch (AuthException $e) {
            return $this->render('auth/login', ['expired' => false, 'error' => $e->getMessage(), 'username' => $username], 401);
        }
        $this->session->beginPending((int) $user['id']);
        return $this->redirect($user['totp_secret'] === null ? '/login/mfa-setup' : '/login/mfa');
    }

    public function mfaForm(): Response
    {
        $uid = $this->session->pendingUserId();
        if ($uid === null) {
            return $this->redirect('/login');
        }
        return $this->render('auth/mfa', ['error' => null]);
    }

    public function mfa(): Response
    {
        $uid = $this->session->pendingUserId();
        if ($uid === null) {
            return $this->redirect('/login');
        }
        try {
            $this->app->authenticator()->verifyMfa($uid, $this->req->post('code'), $this->req->ip());
        } catch (AuthException $e) {
            if (in_array($e->reason(), ['throttled', 'inactive', 'mfa_not_enrolled'], true)) {
                $this->session->logout();
                return $this->render('auth/login', ['expired' => false, 'error' => $e->getMessage(), 'username' => ''], 401);
            }
            return $this->render('auth/mfa', ['error' => $e->getMessage()], 401);
        }
        $this->session->login($uid);
        return $this->redirect('/');
    }

    public function mfaSetupForm(): Response
    {
        $uid = $this->session->pendingUserId();
        if ($uid === null) {
            return $this->redirect('/login');
        }
        $user = $this->app->authenticator()->activeUser($uid);
        if ($user['totp_secret'] !== null) {
            return $this->redirect('/login/mfa');
        }
        $enc = $this->session->pendingSecret();
        if ($enc === null) {
            $enc = $this->app->crypto()->encrypt(Totp::generateSecret());
            $this->session->setPendingSecret($enc);
        }
        return $this->setupView($user, $this->app->crypto()->decrypt($enc), null);
    }

    public function mfaSetup(): Response
    {
        $uid = $this->session->pendingUserId();
        $enc = $this->session->pendingSecret();
        if ($uid === null || $enc === null) {
            return $this->redirect('/login');
        }
        $secret = $this->app->crypto()->decrypt($enc);
        try {
            $this->app->authenticator()->enrollMfa($uid, $secret, $this->req->post('code'), $this->req->ip());
        } catch (AuthException $e) {
            if (in_array($e->reason(), ['throttled', 'inactive', 'mfa_already_enrolled'], true)) {
                $this->session->logout();
                return $this->render('auth/login', ['expired' => false, 'error' => $e->getMessage(), 'username' => ''], 401);
            }
            return $this->setupView($this->app->authenticator()->activeUser($uid), $secret, $e->getMessage());
        }
        $this->session->login($uid);
        $this->session->flash('Dvoufázové ověření je nastavené.', 'success');
        return $this->redirect('/');
    }

    public function logout(): Response
    {
        $this->audit('auth.logout');
        $this->session->logout();
        return $this->redirect('/login');
    }

    /** @param array<string,mixed> $user */
    private function setupView(array $user, string $secret, ?string $error): Response
    {
        $issuer = $this->app->config()->string('mfa.issuer', 'Mail Dashboard');
        return $this->render('auth/mfa_setup', [
            'error'  => $error,
            'uri'    => Totp::uri($secret, (string) $user['username'], $issuer),
            'secret' => trim(chunk_split($secret, 4, ' ')),
        ], $error === null ? 200 : 401);
    }
}
