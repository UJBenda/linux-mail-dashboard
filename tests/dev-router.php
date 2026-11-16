<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Router pro vestavěný server PHP (jen vývoj a testy):
//   MAILPANEL_CONFIG=/cesta/config.php php -S 127.0.0.1:8080 -t public tests/dev-router.php

declare(strict_types=1);

$path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
if ($path !== '/' && is_file(__DIR__ . '/../public' . $path) && !str_ends_with($path, '.php')) {
    return false;
}
require __DIR__ . '/../public/index.php';
