<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel;

use MailPanel\Ad\AdClient;
use MailPanel\Ad\Directory;
use MailPanel\Auth\Authenticator;
use MailPanel\Support\Audit;
use MailPanel\Support\Config;
use MailPanel\Support\Crypto;
use MailPanel\Support\Db;

/** Kontejner služeb aplikace (líná inicializace). */
final class App
{
    private ?Db $db = null;
    private ?Audit $audit = null;
    private ?Crypto $crypto = null;
    private ?Directory $directory = null;
    private ?Authenticator $auth = null;

    public function __construct(private Config $config, private string $root)
    {
        date_default_timezone_set($config->string('timezone', 'Europe/Prague'));
    }

    public static function fromRoot(string $root): self
    {
        $file = getenv('MAILPANEL_CONFIG') ?: $root . '/config/config.php';
        return new self(Config::load($file), $root);
    }

    public function config(): Config
    {
        return $this->config;
    }

    public function root(): string
    {
        return $this->root;
    }

    public function db(): Db
    {
        return $this->db ??= Db::fromConfig($this->config);
    }

    public function audit(): Audit
    {
        return $this->audit ??= new Audit($this->db());
    }

    public function crypto(): Crypto
    {
        return $this->crypto ??= new Crypto($this->config->string('secret_key'));
    }

    public function directory(): Directory
    {
        return $this->directory ??= AdClient::fromConfig($this->config);
    }

    public function setDirectory(Directory $d): void
    {
        $this->directory = $d;
        $this->auth = null;
    }

    public function authenticator(): Authenticator
    {
        /** @var array<string, list<string>|string> $roleGroups */
        $roleGroups = $this->config->array('ad.role_groups');
        return $this->auth ??= new Authenticator(
            $this->db(),
            $this->directory(),
            $this->audit(),
            $this->crypto(),
            $roleGroups,
            [
                'max_fails_user' => $this->config->int('security.max_fails_user', 5),
                'max_fails_ip'   => $this->config->int('security.max_fails_ip', 20),
                'window_minutes' => $this->config->int('security.lockout_minutes', 15),
            ],
        );
    }
}
