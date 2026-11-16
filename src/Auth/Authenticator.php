<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Auth;

use MailPanel\Ad\AdException;
use MailPanel\Ad\Directory;
use MailPanel\Support\Audit;
use MailPanel\Support\Crypto;
use MailPanel\Support\Db;
use MailPanel\Support\IpMatcher;

/**
 * Přihlášení ve dvou krocích: 1) heslo (AD nebo nouzový lokální účet), 2) TOTP.
 * Omezení pokusů na uživatele i IP, každý pokus do auditu.
 */
final class Authenticator
{
    private const GENERIC = 'Neplatné jméno nebo heslo.';

    /**
     * @param array<string, list<string>|string> $roleGroups role => SID skupin AD
     * @param array{max_fails_user?:int, max_fails_ip?:int, window_minutes?:int} $limits
     */
    public function __construct(
        private Db $db,
        private Directory $directory,
        private Audit $audit,
        private Crypto $crypto,
        private array $roleGroups,
        private array $limits = [],
    ) {
    }

    /**
     * Krok 1: jméno a heslo. Vrací řádek uživatele; MFA se ověřuje zvlášť.
     * @return array<string,mixed>
     * @throws AuthException
     */
    public function verifyPassword(string $username, string $password, string $ip): array
    {
        $username = trim($username);
        if ($username === '' || $password === '') {
            throw new AuthException('Zadejte jméno i heslo.', 'empty');
        }
        $key = self::throttleKey($username);
        $this->throttle($key, $ip);

        try {
            $local = $this->db->one("SELECT * FROM users WHERE username = ? AND source = 'local'", [strtolower($username)]);
            $user = $local !== null ? $this->verifyLocal($local, $password, $ip) : $this->verifyAd($username, $password);
        } catch (AuthException $e) {
            $this->attempt($key, $ip, 'password', false);
            $this->audit->log('auth.password', ['reason' => $e->reason()], 'fail', $key, $ip);
            error_log(sprintf('[mailpanel] přihlášení selhalo: uživatel=%s ip=%s důvod=%s', $key, $ip, $e->reason()));
            throw $e;
        }
        $this->attempt($user['username'], $ip, 'password', true);
        $this->audit->log('auth.password', ['source' => $user['source'], 'roles' => $user['roles']], 'ok', $user['username'], $ip);
        return $user;
    }

    /**
     * Krok 2: kód TOTP.
     * @return array<string,mixed>
     * @throws AuthException
     */
    public function verifyMfa(int $userId, string $code, string $ip): array
    {
        $user = $this->activeUser($userId);
        $this->throttle($user['username'], $ip);
        if ($user['totp_secret'] === null) {
            throw new AuthException('MFA není nastaveno.', 'mfa_not_enrolled');
        }
        $step = Totp::verify($this->crypto->decrypt($user['totp_secret']), $code,
            $user['totp_last_step'] !== null ? (int) $user['totp_last_step'] : null);
        if ($step === null) {
            $this->attempt($user['username'], $ip, 'mfa', false);
            $this->audit->log('auth.mfa', ['reason' => 'invalid_code'], 'fail', $user['username'], $ip);
            throw new AuthException('Neplatný ověřovací kód.', 'invalid_code');
        }
        $this->attempt($user['username'], $ip, 'mfa', true);
        $this->db->exec('UPDATE users SET totp_last_step = ?, last_login_at = now(), last_login_ip = ?::inet WHERE id = ?',
            [$step, $ip, $userId]);
        $this->audit->log('auth.login', [], 'ok', $user['username'], $ip);
        return $this->activeUser($userId);
    }

    /**
     * Nastavení MFA: uživatel opíše tajemství do aplikace a potvrdí prvním kódem.
     * @return array<string,mixed>
     * @throws AuthException
     */
    public function enrollMfa(int $userId, string $secret, string $code, string $ip): array
    {
        $user = $this->activeUser($userId);
        if ($user['totp_secret'] !== null) {
            throw new AuthException('MFA už je nastaveno.', 'mfa_already_enrolled');
        }
        $this->throttle($user['username'], $ip);
        $step = Totp::verify($secret, $code);
        if ($step === null) {
            $this->attempt($user['username'], $ip, 'mfa', false);
            $this->audit->log('auth.mfa_enroll', ['reason' => 'invalid_code'], 'fail', $user['username'], $ip);
            throw new AuthException('Kód nesouhlasí – zkontrolujte čas v telefonu a zkuste to znovu.', 'invalid_code');
        }
        $this->attempt($user['username'], $ip, 'mfa', true);
        $this->db->exec('UPDATE users SET totp_secret = ?, totp_last_step = ?, mfa_enrolled_at = now(),
                                last_login_at = now(), last_login_ip = ?::inet WHERE id = ?',
            [$this->crypto->encrypt($secret), $step, $ip, $userId]);
        $this->audit->log('auth.mfa_enroll', [], 'ok', $user['username'], $ip);
        $this->audit->log('auth.login', [], 'ok', $user['username'], $ip);
        return $this->activeUser($userId);
    }

    /** @return array<string,mixed> */
    public function activeUser(int $userId): array
    {
        $user = $this->db->one('SELECT * FROM users WHERE id = ?', [$userId]);
        if ($user === null || !$user['is_active']) {
            throw new AuthException('Účet je zakázán.', 'inactive');
        }
        return $user;
    }

    /** Vytvoří nebo změní nouzový lokální účet (jen z CLI). */
    public function setLocalUser(string $username, string $password, string $allowedIps, string $roles, string $by): int
    {
        $username = strtolower(trim($username));
        if (!preg_match('/^[a-z0-9._-]{3,64}$/', $username)) {
            throw new AuthException('Jméno: 3–64 znaků a-z, 0-9, tečka, pomlčka, podtržítko.');
        }
        if (strlen($password) < 16) {
            throw new AuthException('Heslo nouzového účtu musí mít aspoň 16 znaků.');
        }
        $ips = array_filter(array_map('trim', preg_split('/[\s,;]+/', $allowedIps) ?: []));
        if ($ips === []) {
            throw new AuthException('Nouzový účet musí mít omezení na IP adresy (--ips=10.0.0.0/24,...).');
        }
        foreach ($ips as $r) {
            if (!IpMatcher::isValidRange($r)) {
                throw new AuthException("Neplatný rozsah IP: $r");
            }
        }
        $roleList = Roles::parse($roles);
        if ($roleList === []) {
            throw new AuthException('Zadejte aspoň jednu platnou roli: ' . implode(', ', array_keys(Roles::LABELS)));
        }
        $hash = password_hash($password, defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT);
        $existing = $this->db->one('SELECT * FROM users WHERE username = ?', [$username]);
        if ($existing !== null && $existing['source'] !== 'local') {
            throw new AuthException("Uživatel $username už existuje jako AD účet.");
        }
        $row = [
            'password_hash' => $hash,
            'allowed_ips'   => implode(',', $ips),
            'roles'         => Roles::join($roleList),
            'is_active'     => true,
        ];
        if ($existing !== null) {
            $this->db->update('users', $row, ['id' => $existing['id']]);
            $id = (int) $existing['id'];
        } else {
            $id = (int) $this->db->insert('users', $row + [
                'username'     => $username,
                'display_name' => 'Nouzový účet',
                'source'       => 'local',
            ]);
        }
        $this->audit->log('user.local_set', ['user' => $username, 'roles' => $row['roles'], 'ips' => $row['allowed_ips']], 'ok', $by);
        return $id;
    }

    public function resetMfa(int $userId, string $by, ?string $ip = null): void
    {
        $user = $this->db->one('SELECT username FROM users WHERE id = ?', [$userId]);
        if ($user === null) {
            throw new AuthException('Uživatel neexistuje.');
        }
        $this->db->exec('UPDATE users SET totp_secret = NULL, totp_last_step = NULL, mfa_enrolled_at = NULL WHERE id = ?', [$userId]);
        $this->audit->log('user.mfa_reset', ['user' => $user['username']], 'ok', $by, $ip);
    }

    /** Odemkne uživatele nebo IP zablokované po neúspěšných pokusech. */
    public function unlock(string $subject, string $by, ?string $ip = null): void
    {
        $this->db->exec('INSERT INTO login_unlock (subject, unlocked_at, unlocked_by) VALUES (?, now(), ?)
                         ON CONFLICT (subject) DO UPDATE SET unlocked_at = now(), unlocked_by = EXCLUDED.unlocked_by',
            [$subject, $by]);
        $this->audit->log('auth.unlock', ['subject' => $subject], 'ok', $by, $ip);
    }

    /** @return array<string,mixed> */
    private function verifyLocal(array $user, string $password, string $ip): array
    {
        if (!$user['is_active']) {
            password_verify($password, (string) $user['password_hash']);
            throw new AuthException(self::GENERIC, 'local_inactive');
        }
        if (!IpMatcher::matches($ip, (string) $user['allowed_ips'])) {
            throw new AuthException(self::GENERIC, 'local_ip_not_allowed');
        }
        if (!password_verify($password, (string) $user['password_hash'])) {
            throw new AuthException(self::GENERIC, 'local_bad_password');
        }
        if (password_needs_rehash((string) $user['password_hash'], defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT)) {
            $this->db->update('users', ['password_hash' => password_hash($password, defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT)], ['id' => $user['id']]);
        }
        return $user;
    }

    /** @return array<string,mixed> */
    private function verifyAd(string $username, string $password): array
    {
        try {
            $du = $this->directory->authenticate($username, $password);
        } catch (AdException $e) {
            $public = match ($e->reason()) {
                AdException::UNAVAILABLE, AdException::CONFIG => 'Ověření v AD není dostupné. Zkuste to později nebo kontaktujte správce.',
                AdException::PASSWORD_EXPIRED, AdException::MUST_CHANGE_PASSWORD => 'Heslo je potřeba změnit – změňte ho ve Windows a přihlaste se znovu.',
                default => self::GENERIC,
            };
            throw new AuthException($public, 'ad_' . $e->reason() . ': ' . $e->getMessage());
        }

        $roles = Roles::fromSids($du->groupSids, $this->roleGroups);
        $existing = $this->db->one('SELECT * FROM users WHERE username = ?', [$du->username]);
        if ($existing !== null && $existing['source'] !== 'ad') {
            throw new AuthException(self::GENERIC, 'name_collision_with_local');
        }
        if ($existing !== null && !$existing['is_active']) {
            throw new AuthException('Účet je v panelu zakázán.', 'panel_disabled');
        }
        if ($roles === []) {
            if ($existing !== null && $existing['roles'] !== '') {
                $this->db->update('users', ['roles' => ''], ['id' => $existing['id']]);
            }
            throw new AuthException('Nemáte přidělenou žádnou roli v panelu (skupina v AD).', 'no_role');
        }
        $row = [
            'display_name' => $du->displayName,
            'email'        => $du->email,
            'ad_dn'        => $du->dn,
            'roles'        => Roles::join($roles),
        ];
        if ($existing !== null) {
            if ($existing['roles'] !== $row['roles']) {
                $this->audit->log('user.roles_changed', ['user' => $du->username, 'from' => $existing['roles'], 'to' => $row['roles']], 'ok', 'ad-sync');
            }
            $this->db->update('users', $row, ['id' => $existing['id']]);
            $id = (int) $existing['id'];
        } else {
            $id = (int) $this->db->insert('users', $row + ['username' => $du->username, 'source' => 'ad']);
            $this->audit->log('user.created', ['user' => $du->username, 'roles' => $row['roles']], 'ok', 'ad-sync');
        }
        return (array) $this->db->one('SELECT * FROM users WHERE id = ?', [$id]);
    }

    /** „FIRMA\jnovak“, „JNovak“, „jnovak@firma.cz“ → „jnovak“ – různé zápisy jména nesmí obejít limit pokusů. */
    public static function throttleKey(string $username): string
    {
        $u = strtolower(trim($username));
        if (str_contains($u, '\\')) {
            $u = substr($u, strrpos($u, '\\') + 1);
        }
        return explode('@', $u, 2)[0];
    }

    private function throttle(string $username, string $ip): void
    {
        $window = (int) ($this->limits['window_minutes'] ?? 15);
        $maxUser = (int) ($this->limits['max_fails_user'] ?? 5);
        $maxIp = (int) ($this->limits['max_fails_ip'] ?? 20);
        $since = "greatest(now() - make_interval(mins => $window),
                          coalesce((SELECT unlocked_at FROM login_unlock WHERE subject = ?), '-infinity'))";
        $userFails = (int) $this->db->value("SELECT count(*) FROM login_attempts
            WHERE username = ? AND NOT success AND created_at > $since", [$username, "user:$username"]);
        $ipFails = (int) $this->db->value("SELECT count(*) FROM login_attempts
            WHERE ip = ?::inet AND NOT success AND created_at > $since", [$ip, "ip:$ip"]);
        if ($userFails >= $maxUser || $ipFails >= $maxIp) {
            $this->audit->log('auth.blocked', ['user_fails' => $userFails, 'ip_fails' => $ipFails], 'denied', $username, $ip);
            throw new AuthException("Příliš mnoho neúspěšných pokusů. Zkuste to za $window minut.", 'throttled');
        }
    }

    private function attempt(string $username, string $ip, string $stage, bool $ok): void
    {
        $this->db->exec('INSERT INTO login_attempts (username, ip, stage, success) VALUES (?, ?::inet, ?, ?)',
            [$username, $ip, $stage, $ok]);
    }
}
