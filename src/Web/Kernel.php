<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Web;

use MailPanel\App;
use MailPanel\Auth\AuthException;
use MailPanel\Auth\Roles;
use MailPanel\Web\Controller\Admin\AuditController;
use MailPanel\Web\Controller\Admin\UsersController;
use MailPanel\Web\Controller\AuthController;
use MailPanel\Web\Controller\DashboardController;
use Throwable;

/** Zpracování požadavku: routa → session → uživatel → oprávnění → CSRF → controller. */
final class Kernel
{
    private Router $router;

    public function __construct(private App $app, private Request $req, private Session $session, private View $view)
    {
        $this->router = new Router();
        $this->routes($this->router);
    }

    private function routes(Router $r): void
    {
        $r->add('GET', '/healthz', [DashboardController::class, 'health'], null);
        $r->add('GET', '/login', [AuthController::class, 'loginForm'], null);
        $r->add('POST', '/login', [AuthController::class, 'login'], null);
        $r->add('GET', '/login/mfa', [AuthController::class, 'mfaForm'], null);
        $r->add('POST', '/login/mfa', [AuthController::class, 'mfa'], null);
        $r->add('GET', '/login/mfa-setup', [AuthController::class, 'mfaSetupForm'], null);
        $r->add('POST', '/login/mfa-setup', [AuthController::class, 'mfaSetup'], null);
        $r->add('POST', '/logout', [AuthController::class, 'logout'], 'auth');

        $r->add('GET', '/', [DashboardController::class, 'index'], 'dashboard.view');

        $r->add('GET', '/admin/audit', [AuditController::class, 'index'], 'audit.view');
        $r->add('GET', '/admin/users', [UsersController::class, 'index'], 'users.manage');
        $r->add('POST', '/admin/users/{id}/mfa-reset', [UsersController::class, 'mfaReset'], 'users.manage');
        $r->add('POST', '/admin/users/{id}/active', [UsersController::class, 'setActive'], 'users.manage');
    }

    public function handle(): Response
    {
        try {
            $response = $this->dispatch();
        } catch (HttpException $e) {
            $response = $this->error($e->status, $e->getMessage());
        } catch (Throwable $e) {
            error_log('[mailpanel] ' . $e::class . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
            $response = $this->error(500, '');
        }
        return $response->withSecurityHeaders($this->req->isHttps());
    }

    private function dispatch(): Response
    {
        $route = $this->router->match($this->req->method, $this->req->path);
        if ($route['permission'] === null && $route['handler'][1] === 'health') {
            return $this->call($route, null); // bez session a DB uživatelů
        }

        $this->session->start();
        $user = null;
        if (($uid = $this->session->userId()) !== null) {
            try {
                $user = $this->app->authenticator()->activeUser($uid);
                if (Roles::parse((string) $user['roles']) === []) {
                    throw new AuthException('Bez role.', 'no_role');
                }
            } catch (AuthException) {
                $this->session->logout();
                $user = null;
            }
        }
        $this->app->audit()->setActor($user['username'] ?? null, $this->req->ip());
        $this->view->share('user', $user);
        $this->view->share('csrfToken', $this->session->csrfToken());
        $this->view->share('flash', $this->session->flash());
        $this->view->share('path', $this->req->path);

        $perm = $route['permission'];
        if ($perm !== null) {
            if ($user === null) {
                if ($this->req->method === 'GET') {
                    return Response::redirect($this->view->url('/login'));
                }
                throw new HttpException(401, 'Nejste přihlášen.');
            }
            if ($perm !== 'auth' && !Roles::can(Roles::parse((string) $user['roles']), $perm)) {
                $this->app->audit()->log('access.denied', ['path' => $this->req->path, 'permission' => $perm], 'denied');
                throw new HttpException(403);
            }
        }

        if ($this->req->isPost() && !$this->session->checkCsrf($this->req->post('_csrf'))) {
            throw new HttpException(400, 'Formulář vypršel nebo nepochází z tohoto panelu. Načtěte stránku znovu.');
        }

        return $this->call($route, $user);
    }

    /** @param array{handler:array{0:class-string,1:string}, params:array<string,string>} $route */
    private function call(array $route, ?array $user): Response
    {
        [$class, $method] = $route['handler'];
        $controller = new $class($this->app, $this->req, $this->session, $this->view, $user);
        return $controller->$method($route['params']);
    }

    private function error(int $status, string $message): Response
    {
        $titles = [400 => 'Neplatný požadavek', 401 => 'Nepřihlášen', 403 => 'Přístup odepřen',
            404 => 'Stránka neexistuje', 405 => 'Nepovolená metoda', 500 => 'Chyba serveru'];
        try {
            $body = $this->view->render('error', [
                'status'  => $status,
                'title'   => $titles[$status] ?? 'Chyba',
                'message' => $message,
            ]);
        } catch (Throwable) {
            $body = '<h1>' . $status . '</h1>';
        }
        return Response::html($body, $status);
    }
}
