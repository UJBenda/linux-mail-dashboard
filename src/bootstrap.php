<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

// Autoloader bez Composeru (PSR-4, namespace MailPanel\ → src/).
spl_autoload_register(static function (string $class): void {
    if (str_starts_with($class, 'MailPanel\\')) {
        $file = __DIR__ . '/' . str_replace('\\', '/', substr($class, 10)) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});
