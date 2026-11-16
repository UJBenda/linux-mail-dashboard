<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Web;

/**
 * Jednoduchý router: metoda + cesta se zástupnými parametry {id} (jen číslice) / {name}.
 * Každá routa nese oprávnění: null = veřejná, 'auth' = jen přihlášený, jinak oprávnění z Roles.
 */
final class Router
{
    /** @var list<array{method:string, regex:string, handler:array{0:class-string,1:string}, permission:?string}> */
    private array $routes = [];

    /** @param array{0:class-string,1:string} $handler */
    public function add(string $method, string $pattern, array $handler, ?string $permission): void
    {
        $regex = preg_replace_callback('/\{(\w+)\}/', static fn ($m) => $m[1] === 'id'
            ? '(?P<id>\d+)'
            : '(?P<' . $m[1] . '>[^/]+)', $pattern);
        $this->routes[] = ['method' => $method, 'regex' => '#^' . $regex . '$#', 'handler' => $handler, 'permission' => $permission];
    }

    /**
     * @return array{handler:array{0:class-string,1:string}, permission:?string, params:array<string,string>}
     * @throws HttpException
     */
    public function match(string $method, string $path): array
    {
        $allowed = false;
        foreach ($this->routes as $r) {
            if (!preg_match($r['regex'], $path, $m)) {
                continue;
            }
            if ($r['method'] !== $method) {
                $allowed = true;
                continue;
            }
            $params = array_filter($m, 'is_string', ARRAY_FILTER_USE_KEY);
            return ['handler' => $r['handler'], 'permission' => $r['permission'], 'params' => $params];
        }
        throw new HttpException($allowed ? 405 : 404);
    }
}
