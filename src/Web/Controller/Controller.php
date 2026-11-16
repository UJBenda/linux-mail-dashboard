<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Web\Controller;

use MailPanel\App;
use MailPanel\Web\Request;
use MailPanel\Web\Response;
use MailPanel\Web\Session;
use MailPanel\Web\View;

abstract class Controller
{
    /** @param array<string,mixed>|null $user */
    public function __construct(
        protected App $app,
        protected Request $req,
        protected Session $session,
        protected View $view,
        protected ?array $user,
    ) {
    }

    /** @param array<string,mixed> $vars */
    protected function render(string $template, array $vars = [], int $status = 200): Response
    {
        return Response::html($this->view->render($template, $vars), $status);
    }

    protected function redirect(string $path, array $query = []): Response
    {
        return Response::redirect($this->view->url($path, $query));
    }

    protected function audit(string $action, array $details = [], string $result = 'ok'): void
    {
        $this->app->audit()->log($action, $details, $result);
    }
}
