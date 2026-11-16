<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Web;

/**
 * Session: dvoufázové přihlášení (heslo → MFA), limity nečinnosti a celkové délky,
 * CSRF token, nové ID session po každé změně oprávnění.
 */
final class Session
{
    private const PENDING_SECONDS = 300;

    public function __construct(
        private int $idleMinutes,
        private int $absoluteHours,
        private bool $cookieSecure,
        private string $cookiePath,
    ) {
    }

    public function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');
        ini_set('session.sid_length', '48');
        ini_set('session.sid_bits_per_character', '6');
        ini_set('session.gc_maxlifetime', (string) ($this->idleMinutes * 60));
        session_cache_limiter(''); // Cache-Control posílá Response
        session_name($this->cookieSecure ? '__Host-mailpanel' : 'mailpanel');
        session_set_cookie_params([
            'lifetime' => 0,
            // prefix __Host- vyžaduje Path=/ a Secure
            'path'     => $this->cookieSecure ? '/' : ($this->cookiePath ?: '/'),
            'secure'   => $this->cookieSecure,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();

        $now = time();
        $created = (int) ($_SESSION['created'] ?? 0);
        $last = (int) ($_SESSION['last'] ?? 0);
        if ($created > 0 && ($now - $last > $this->idleMinutes * 60 || $now - $created > $this->absoluteHours * 3600)) {
            $_SESSION = ['expired' => true];
            session_regenerate_id(true);
        }
        $_SESSION['created'] ??= $now;
        $_SESSION['last'] = $now;
    }

    public function userId(): ?int
    {
        return isset($_SESSION['uid']) && ($_SESSION['auth'] ?? '') === 'full' ? (int) $_SESSION['uid'] : null;
    }

    public function wasExpired(): bool
    {
        $v = (bool) ($_SESSION['expired'] ?? false);
        unset($_SESSION['expired']);
        return $v;
    }

    /** Po ověření hesla: čeká se na MFA. */
    public function beginPending(int $userId): void
    {
        session_regenerate_id(true);
        $_SESSION = ['created' => time(), 'last' => time(), 'pending_uid' => $userId, 'pending_until' => time() + self::PENDING_SECONDS];
    }

    public function pendingUserId(): ?int
    {
        if (!isset($_SESSION['pending_uid']) || (int) ($_SESSION['pending_until'] ?? 0) < time()) {
            return null;
        }
        return (int) $_SESSION['pending_uid'];
    }

    public function setPendingSecret(?string $encrypted): void
    {
        $_SESSION['pending_secret'] = $encrypted;
    }

    public function pendingSecret(): ?string
    {
        return $_SESSION['pending_secret'] ?? null;
    }

    /** Plné přihlášení po MFA. */
    public function login(int $userId): void
    {
        session_regenerate_id(true);
        $_SESSION = ['created' => time(), 'last' => time(), 'uid' => $userId, 'auth' => 'full'];
    }

    public function logout(): void
    {
        $_SESSION = [];
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }
    }

    public function csrfToken(): string
    {
        return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
    }

    public function checkCsrf(string $token): bool
    {
        return isset($_SESSION['csrf']) && $token !== '' && hash_equals($_SESSION['csrf'], $token);
    }

    public function flash(?string $message = null, string $type = 'info'): ?array
    {
        if ($message !== null) {
            $_SESSION['flash'] = ['message' => $message, 'type' => $type];
            return null;
        }
        $f = $_SESSION['flash'] ?? null;
        unset($_SESSION['flash']);
        return $f;
    }
}
