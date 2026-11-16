<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

use MailPanel\App;
use MailPanel\Support\ConfigException;
use MailPanel\Web\Kernel;
use MailPanel\Web\Request;
use MailPanel\Web\Session;
use MailPanel\Web\View;

$root = dirname(__DIR__);
require $root . '/src/bootstrap.php';

try {
    $app = App::fromRoot($root);
} catch (ConfigException $e) {
    error_log('[mailpanel] konfigurace: ' . $e->getMessage());
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Panel není nakonfigurován. Podrobnosti v logu serveru, kontrola: bin/mailpanel check\n";
    exit;
}

$config = $app->config();
$basePath = rtrim($config->string('base_path'), '/');
$request = Request::fromGlobals($basePath);
$session = new Session(
    $config->int('session.idle_minutes', 15),
    $config->int('session.absolute_hours', 8),
    $config->bool('session.cookie_secure', true),
    $basePath === '' ? '/' : $basePath . '/',
);
$view = new View($root . '/templates', $basePath);
$view->share('appName', $config->string('app_name', 'Mail Dashboard'));

(new Kernel($app, $request, $session, $view))->handle()->send();
