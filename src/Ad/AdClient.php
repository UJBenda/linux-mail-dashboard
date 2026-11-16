<?php

// SPDX-License-Identifier: GPL-3.0-or-later
// Linux Mail Dashboard – https://github.com/UJBenda/linux-mail-dashboard

declare(strict_types=1);

namespace MailPanel\Ad;

use LDAP\Connection;
use MailPanel\Support\Config;

/**
 * Klient Active Directory: LDAPS (636) nebo StartTLS (389), více řadičů s fallbackem.
 *
 * Postup přihlášení:
 *   1. bind servisním účtem (jen čtení) → vyhledání uživatele podle sAMAccountName / UPN,
 *   2. bind jako uživatel s jeho heslem (heslo se nikam neukládá),
 *   3. kontrola stavu účtu (zakázaný, vypršelý),
 *   4. tokenGroups = SID všech skupin včetně vnořených → role podle SID.
 *
 * Certifikát serveru se vždy ověřuje (TLS_REQUIRE_CERT = hard); prázdné heslo se odmítá
 * (LDAP by ho jinak vzal jako anonymní bind a „přihlásil“ kohokoli).
 */
final class AdClient implements Directory
{
    private const UAC_ACCOUNTDISABLE = 0x2;
    private const NEVER_EXPIRES = '9223372036854775807';
    private const LDAP_CANT_CONTACT = -1;
    private const LDAP_INVALID_CREDENTIALS = 49;

    /**
     * @param list<array{host:string, port?:int, mode?:string}> $servers
     * @param array<string,mixed> $options
     */
    public function __construct(
        private array $servers,
        private string $baseDn,
        private string $bindDn,
        private string $bindPassword,
        private array $options = [],
    ) {
    }

    public static function fromConfig(Config $c): self
    {
        $servers = [];
        foreach ($c->array('ad.servers') as $s) {
            if (is_array($s) && !empty($s['host'])) {
                $servers[] = [
                    'host' => (string) $s['host'],
                    'port' => (int) ($s['port'] ?? (($s['mode'] ?? 'ldaps') === 'starttls' ? 389 : 636)),
                    'mode' => (string) ($s['mode'] ?? 'ldaps'),
                ];
            }
        }
        return new self($servers, $c->string('ad.base_dn'), $c->string('ad.bind_dn'), $c->string('ad.bind_password'), [
            'ca_file'    => $c->string('ad.ca_file'),
            'upn_suffix' => $c->string('ad.upn_suffix'),
            'timeout'    => $c->int('ad.timeout', 5),
        ]);
    }

    public function isConfigured(): bool
    {
        return $this->servers !== [] && $this->baseDn !== '' && $this->bindDn !== '' && $this->bindPassword !== '';
    }

    public function authenticate(string $login, string $password): DirectoryUser
    {
        if (!$this->isConfigured()) {
            throw new AdException(AdException::CONFIG, 'AD není nakonfigurováno (ad.servers, base_dn, bind_dn, bind_password)');
        }
        $login = self::normalizeLogin($login, (string) ($this->options['upn_suffix'] ?? ''));
        if ($login === '' || $password === '') {
            throw new AdException(AdException::INVALID_CREDENTIALS, 'prázdné jméno nebo heslo');
        }

        $lastError = null;
        foreach ($this->servers as $server) {
            try {
                return $this->authenticateOn($server, $login, $password);
            } catch (AdException $e) {
                if ($e->reason() !== AdException::UNAVAILABLE) {
                    throw $e; // špatné heslo apod. – jiný řadič nezkoušet (zbytečné zamykání účtu)
                }
                $lastError = $e;
            }
        }
        throw $lastError ?? new AdException(AdException::UNAVAILABLE, 'žádný řadič');
    }

    /** @param array{host:string, port:int, mode:string} $server */
    private function authenticateOn(array $server, string $login, string $password): DirectoryUser
    {
        $link = $this->connect($server);
        $this->bindService($link, $server);

        $entry = $this->findUser($link, $login);
        if ($entry === null) {
            throw new AdException(AdException::NOT_FOUND, $login);
        }
        $dn = $entry['dn'];

        if (!@ldap_bind($link, $dn, $password)) {
            throw $this->bindFailure($link, 'uživatel ' . $login);
        }

        $uac = (int) ($entry['useraccountcontrol'] ?? 0);
        if ($uac & self::UAC_ACCOUNTDISABLE) {
            throw new AdException(AdException::ACCOUNT_DISABLED, $login);
        }
        if (self::isExpired((string) ($entry['accountexpires'] ?? '0'))) {
            throw new AdException(AdException::ACCOUNT_EXPIRED, $login);
        }

        $sids = $this->tokenGroups($link, $dn);
        if ($sids === []) {
            // uživatel nemusí mít právo číst vlastní tokenGroups – zkusit servisním účtem
            $this->bindService($link, $server);
            $sids = $this->tokenGroups($link, $dn);
        }
        @ldap_unbind($link);

        return new DirectoryUser(
            $dn,
            strtolower((string) ($entry['samaccountname'] ?? $login)),
            (string) ($entry['displayname'] ?? $login),
            isset($entry['mail']) ? strtolower((string) $entry['mail']) : null,
            $sids,
        );
    }

    /**
     * Test spojení na všechny řadiče (pro CLI / diagnostiku).
     * @return list<array{server:string, ok:bool, ms:int, message:string}>
     */
    public function testServers(): array
    {
        $out = [];
        foreach ($this->servers as $server) {
            $t = microtime(true);
            $name = sprintf('%s://%s:%d', $server['mode'], $server['host'], $server['port']);
            try {
                $link = $this->connect($server);
                $this->bindService($link, $server);
                @ldap_unbind($link);
                $out[] = ['server' => $name, 'ok' => true, 'ms' => (int) ((microtime(true) - $t) * 1000), 'message' => 'TLS a bind servisního účtu OK'];
            } catch (AdException $e) {
                $out[] = ['server' => $name, 'ok' => false, 'ms' => (int) ((microtime(true) - $t) * 1000), 'message' => $e->getMessage()];
            }
        }
        return $out;
    }

    /**
     * Vyhledání skupin podle jména (CLI – zjištění SID pro konfiguraci rolí).
     * @return list<array{name:string, dn:string, sid:string}>
     */
    public function searchGroups(string $query, int $limit = 50): array
    {
        $lastError = null;
        foreach ($this->servers as $server) {
            try {
                $link = $this->connect($server);
                $this->bindService($link, $server);
                $q = ldap_escape($query, '', LDAP_ESCAPE_FILTER);
                $res = @ldap_search($link, $this->baseDn, "(&(objectClass=group)(|(cn=*$q*)(sAMAccountName=*$q*)))",
                    ['cn', 'objectSid'], 0, $limit);
                if ($res === false) {
                    throw new AdException(AdException::CONFIG, 'hledání skupin selhalo: ' . ldap_error($link));
                }
                $out = [];
                $entries = ldap_get_entries($link, $res);
                for ($i = 0; $i < ($entries['count'] ?? 0); $i++) {
                    $e = $entries[$i];
                    $out[] = [
                        'name' => (string) ($e['cn'][0] ?? ''),
                        'dn'   => (string) $e['dn'],
                        'sid'  => isset($e['objectsid'][0]) ? self::sidToString($e['objectsid'][0]) : '',
                    ];
                }
                @ldap_unbind($link);
                usort($out, fn ($a, $b) => strcmp($a['name'], $b['name']));
                return $out;
            } catch (AdException $e) {
                if ($e->reason() !== AdException::UNAVAILABLE) {
                    throw $e;
                }
                $lastError = $e;
            }
        }
        throw $lastError ?? new AdException(AdException::CONFIG, 'žádný řadič');
    }

    /** @param array{host:string, port:int, mode:string} $server */
    private function connect(array $server): Connection
    {
        $scheme = $server['mode'] === 'starttls' ? 'ldap' : 'ldaps';
        $link = @ldap_connect(sprintf('%s://%s:%d', $scheme, $server['host'], $server['port']));
        if ($link === false) {
            throw new AdException(AdException::CONFIG, 'neplatná adresa řadiče ' . $server['host']);
        }
        $timeout = (int) ($this->options['timeout'] ?? 5);
        ldap_set_option($link, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($link, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($link, LDAP_OPT_NETWORK_TIMEOUT, $timeout);
        ldap_set_option($link, LDAP_OPT_TIMELIMIT, $timeout);
        ldap_set_option($link, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_HARD);
        $ca = (string) ($this->options['ca_file'] ?? '');
        if ($ca !== '') {
            if (!is_readable($ca)) {
                throw new AdException(AdException::CONFIG, "CA certifikát $ca nelze číst");
            }
            ldap_set_option($link, LDAP_OPT_X_TLS_CACERTFILE, $ca);
        }
        ldap_set_option($link, LDAP_OPT_X_TLS_NEWCTX, 0);

        if ($server['mode'] === 'starttls' && !@ldap_start_tls($link)) {
            throw new AdException(AdException::UNAVAILABLE, sprintf('%s: StartTLS selhalo – %s', $server['host'], self::diagnostic($link)));
        }
        return $link;
    }

    /** @param array{host:string, port:int, mode:string} $server */
    private function bindService(Connection $link, array $server): void
    {
        if (!@ldap_bind($link, $this->bindDn, $this->bindPassword)) {
            $errno = ldap_errno($link);
            if ($errno === self::LDAP_CANT_CONTACT) {
                throw new AdException(AdException::UNAVAILABLE, sprintf('%s nedostupný nebo TLS selhalo (certifikát?) – %s',
                    $server['host'], self::diagnostic($link)));
            }
            throw new AdException(AdException::CONFIG, sprintf('bind servisního účtu na %s selhal – %s',
                $server['host'], self::diagnostic($link)));
        }
    }

    /** @return array<string,mixed>|null */
    private function findUser(Connection $link, string $login): ?array
    {
        $v = ldap_escape($login, '', LDAP_ESCAPE_FILTER);
        $attr = str_contains($login, '@') ? 'userPrincipalName' : 'sAMAccountName';
        $filter = "(&(objectCategory=person)(objectClass=user)($attr=$v))";
        $res = @ldap_search($link, $this->baseDn, $filter,
            ['sAMAccountName', 'userPrincipalName', 'displayName', 'mail', 'userAccountControl', 'accountExpires'], 0, 2);
        if ($res === false) {
            throw new AdException(AdException::CONFIG, 'hledání uživatele selhalo – ' . self::diagnostic($link));
        }
        $entries = ldap_get_entries($link, $res);
        if (($entries['count'] ?? 0) === 0) {
            return null;
        }
        if ($entries['count'] > 1) {
            throw new AdException(AdException::CONFIG, "nejednoznačné jméno $login (více účtů)");
        }
        $e = $entries[0];
        $out = ['dn' => (string) $e['dn']];
        foreach (['samaccountname', 'userprincipalname', 'displayname', 'mail', 'useraccountcontrol', 'accountexpires'] as $a) {
            if (isset($e[$a][0])) {
                $out[$a] = $e[$a][0];
            }
        }
        return $out;
    }

    /** @return list<string> */
    private function tokenGroups(Connection $link, string $dn): array
    {
        $res = @ldap_read($link, $dn, '(objectClass=*)', ['tokenGroups']);
        if ($res === false) {
            return [];
        }
        $entry = @ldap_first_entry($link, $res);
        if ($entry === false) {
            return [];
        }
        $values = @ldap_get_values_len($link, $entry, 'tokenGroups');
        if ($values === false) {
            return [];
        }
        $sids = [];
        for ($i = 0; $i < ($values['count'] ?? 0); $i++) {
            $sids[] = self::sidToString($values[$i]);
        }
        return $sids;
    }

    private function bindFailure(Connection $link, string $who): AdException
    {
        $errno = ldap_errno($link);
        $diag = self::diagnostic($link);
        if ($errno === self::LDAP_CANT_CONTACT) {
            return new AdException(AdException::UNAVAILABLE, $diag);
        }
        if ($errno === self::LDAP_INVALID_CREDENTIALS) {
            return new AdException(self::reasonFromDiagnostic($diag), "$who – $diag");
        }
        return new AdException(AdException::CONFIG, "$who – $diag");
    }

    /** AD vrací v diagnostice „data 52e“ apod. – převod na důvod. */
    public static function reasonFromDiagnostic(string $diag): string
    {
        if (!preg_match('/data ([0-9a-f]{3})/i', $diag, $m)) {
            return AdException::INVALID_CREDENTIALS;
        }
        return match (strtolower($m[1])) {
            '530', '531', '52e' => AdException::INVALID_CREDENTIALS,
            '525' => AdException::NOT_FOUND,
            '532' => AdException::PASSWORD_EXPIRED,
            '533' => AdException::ACCOUNT_DISABLED,
            '701' => AdException::ACCOUNT_EXPIRED,
            '773' => AdException::MUST_CHANGE_PASSWORD,
            '775' => AdException::ACCOUNT_LOCKED,
            default => AdException::INVALID_CREDENTIALS,
        };
    }

    private static function diagnostic(Connection $link): string
    {
        $msg = ldap_error($link);
        if (@ldap_get_option($link, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extra) && is_string($extra) && $extra !== '') {
            $msg .= " ($extra)";
        }
        return $msg;
    }

    /** „FIRMA\jnovak“ → „jnovak“, „jnovak@firma.local“ → „jnovak“ (když sedí přípona). */
    public static function normalizeLogin(string $login, string $upnSuffix = ''): string
    {
        $login = trim($login);
        if (str_contains($login, '\\')) {
            $login = substr($login, strrpos($login, '\\') + 1);
        }
        if ($upnSuffix !== '' && str_ends_with(strtolower($login), '@' . strtolower($upnSuffix))) {
            $login = substr($login, 0, -strlen($upnSuffix) - 1);
        }
        return $login;
    }

    /** accountExpires: FILETIME (100 ns od 1601-01-01); 0 nebo max = nikdy. */
    public static function isExpired(string $filetime, ?int $now = null): bool
    {
        if ($filetime === '' || $filetime === '0' || $filetime === self::NEVER_EXPIRES || !ctype_digit($filetime)) {
            return false;
        }
        $unix = intdiv((int) $filetime, 10_000_000) - 11_644_473_600;
        return $unix <= ($now ?? time());
    }

    public static function sidToString(string $bin): string
    {
        if (strlen($bin) < 8) {
            return '';
        }
        $rev = ord($bin[0]);
        $count = ord($bin[1]);
        $auth = 0;
        for ($i = 2; $i < 8; $i++) {
            $auth = ($auth << 8) | ord($bin[$i]);
        }
        $sid = "S-$rev-$auth";
        for ($i = 0; $i < $count && strlen($bin) >= 12 + $i * 4; $i++) {
            $sid .= '-' . unpack('V', substr($bin, 8 + $i * 4, 4))[1];
        }
        return $sid;
    }
}
