<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Spuštění testů: php tests/run.php [filtr]
// Testy s databází běží jen s MAILPANEL_TEST_DSN (např. "pgsql:host=/var/run/postgresql;dbname=mailpanel_test")
// a MAILPANEL_TEST_USER / MAILPANEL_TEST_PASSWORD. Testovací DB se při startu ZCELA SMAŽE.

declare(strict_types=1);

$root = dirname(__DIR__);
ini_set('error_log', getenv('MAILPANEL_TEST_ERROR_LOG') ?: '/dev/null');
require $root . '/src/bootstrap.php';
require __DIR__ . '/Support/TestCase.php';
require __DIR__ . '/Support/DbTestCase.php';
require __DIR__ . '/Support/FakeDirectory.php';

$filter = $argv[1] ?? '';
$files = array_merge(glob(__DIR__ . '/Unit/*Test.php') ?: [], glob(__DIR__ . '/Db/*Test.php') ?: []);
$passed = $failed = $skipped = 0;
$failures = [];

foreach ($files as $file) {
    require_once $file;
    $class = 'MailPanel\\Tests\\' . basename(dirname($file)) . '\\' . basename($file, '.php');
    $ref = new ReflectionClass($class);
    foreach ($ref->getMethods(ReflectionMethod::IS_PUBLIC) as $m) {
        if (!str_starts_with($m->name, 'test') || ($filter !== '' && !str_contains("$class::{$m->name}", $filter))) {
            continue;
        }
        $t = new $class();
        try {
            $t->setUp();
            $t->{$m->name}();
            $t->tearDown();
            $passed++;
            echo '.';
        } catch (MailPanel\Tests\Support\SkipTest $e) {
            $skipped++;
            echo 'S';
        } catch (Throwable $e) {
            $failed++;
            echo 'F';
            $failures[] = sprintf("%s::%s\n  %s: %s\n  %s:%d", $class, $m->name, $e::class, $e->getMessage(), $e->getFile(), $e->getLine());
        }
    }
}
echo PHP_EOL . PHP_EOL;
foreach ($failures as $f) {
    echo $f . PHP_EOL . PHP_EOL;
}
printf("Úspěšné: %d, selhané: %d, přeskočené: %d%s\n", $passed, $failed, $skipped,
    $skipped > 0 && getenv('MAILPANEL_TEST_DSN') === false ? ' (DB testy: nastavte MAILPANEL_TEST_DSN)' : '');
exit($failed > 0 ? 1 : 0);
