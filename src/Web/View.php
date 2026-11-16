<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Web;

use MailPanel\Auth\Roles;

/** Šablony v čistém PHP. Vše, co jde do HTML, prochází e(). */
final class View
{
    /** @var array<string,mixed> */
    private array $shared = [];

    public function __construct(private string $dir, private string $basePath)
    {
    }

    public function share(string $key, mixed $value): void
    {
        $this->shared[$key] = $value;
    }

    /** @param array<string,mixed> $vars */
    public function render(string $template, array $vars = [], ?string $layout = 'layout'): string
    {
        $content = $this->renderFile($template, $vars);
        if ($layout === null) {
            return $content;
        }
        return $this->renderFile($layout, $vars + ['content' => $content]);
    }

    /** @param array<string,mixed> $vars */
    public function partial(string $template, array $vars = []): string
    {
        return $this->renderFile('partials/' . $template, $vars);
    }

    /** @param array<string,mixed> $vars */
    private function renderFile(string $template, array $vars): string
    {
        $file = $this->dir . '/' . $template . '.php';
        if (!preg_match('#^[a-z0-9_/-]+$#', $template) || !is_file($file)) {
            throw new \RuntimeException("Šablona $template neexistuje.");
        }
        $view = $this;
        extract($this->shared + $vars, EXTR_SKIP);
        ob_start();
        try {
            require $file;
            return (string) ob_get_clean();
        } catch (\Throwable $e) {
            ob_end_clean();
            throw $e;
        }
    }

    public function e(mixed $v): string
    {
        return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public function url(string $path, array $query = []): string
    {
        $url = rtrim($this->basePath, '/') . '/' . ltrim($path, '/');
        return $query !== [] ? $url . '?' . http_build_query($query) : $url;
    }

    public function asset(string $path): string
    {
        $file = dirname($this->dir) . '/public/assets/' . $path;
        $v = is_file($file) ? substr(md5((string) filemtime($file)), 0, 8) : '0';
        return $this->url('assets/' . $path) . '?v=' . $v;
    }

    public function csrf(): string
    {
        $token = $this->shared['csrfToken'] ?? '';
        return '<input type="hidden" name="_csrf" value="' . $this->e($token) . '">';
    }

    public function can(string $permission): bool
    {
        $user = $this->shared['user'] ?? null;
        return is_array($user) && Roles::can(Roles::parse((string) $user['roles']), $permission);
    }

    public function dt(?string $ts): string
    {
        if ($ts === null || $ts === '') {
            return '–';
        }
        return (new \DateTimeImmutable($ts))->setTimezone(new \DateTimeZone(date_default_timezone_get()))->format('j. n. Y H:i:s');
    }
}
