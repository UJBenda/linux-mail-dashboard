<?php

// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace MailPanel\Tests\Db;

use MailPanel\Auth\Authenticator;
use MailPanel\Auth\Totp;
use MailPanel\Support\Crypto;
use MailPanel\Tests\Support\DbTestCase;
use MailPanel\Tests\Support\FakeDirectory;

/**
 * End-to-end přes vestavěný server PHP: přihlášení nouzovým účtem, nastavení MFA,
 * oprávnění, CSRF, bezpečnostní hlavičky, audit.
 */
final class WebTest extends DbTestCase
{
    private const PASSWORD = 'Velmi-dlouhe-heslo-1';

    /** @var resource|null */
    private static $server = null;
    private static int $port = 0;
    private static string $configFile = '';
    private static string $key = '';
    /** @var array<string,string> */
    private array $cookies = [];

    public function setUp(): void
    {
        parent::setUp();
        if (self::$server === null) {
            self::$key = Crypto::generateKey();
            self::$configFile = sys_get_temp_dir() . '/mailpanel-test-' . getmypid() . '.php';
            file_put_contents(self::$configFile, '<?php return ' . var_export([
                'db'         => ['dsn' => getenv('MAILPANEL_TEST_DSN'), 'user' => getenv('MAILPANEL_TEST_USER'), 'password' => getenv('MAILPANEL_TEST_PASSWORD')],
                'secret_key' => self::$key,
                'session'    => ['cookie_secure' => false],
                'ad'         => ['role_groups' => ['admin' => ['S-1-5-21-1-2-3-1101']]],
            ], true) . ';');
            chmod(self::$configFile, 0600);
            self::$port = random_int(20000, 40000);
            $root = dirname(__DIR__, 2);
            $cmd = sprintf('exec php -d error_log=/dev/null -S 127.0.0.1:%d -t %s %s', self::$port,
                escapeshellarg("$root/public"), escapeshellarg("$root/tests/dev-router.php"));
            self::$server = proc_open($cmd, [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes,
                null, ['MAILPANEL_CONFIG' => self::$configFile] + getenv());
            register_shutdown_function(static function (): void {
                if (is_resource(self::$server)) {
                    proc_terminate(self::$server);
                }
                @unlink(self::$configFile);
            });
            for ($i = 0; $i < 50 && @fsockopen('127.0.0.1', self::$port) === false; $i++) {
                usleep(100_000);
            }
        }
        $auth = new Authenticator($this->db, new FakeDirectory([]), $this->audit, new Crypto(self::$key), []);
        $auth->setLocalUser('nouze', self::PASSWORD, '127.0.0.1', 'admin', 'test');
    }

    public function testFullLoginFlow(): void
    {
        $r = $this->get('/healthz');
        $this->assertSame(200, $r['status']);
        $this->assertSame("ok\n", $r['body']);

        $r = $this->get('/');
        $this->assertSame(303, $r['status'], 'nepřihlášený → přihlášení');
        $this->assertSame('/login', $r['headers']['location']);
        $this->assertContains('HttpOnly', $r['headers']['set-cookie']);
        $this->assertContains('SameSite=Strict', $r['headers']['set-cookie']);

        $r = $this->get('/login');
        $this->assertSame(200, $r['status']);
        $this->assertContains("frame-ancestors 'none'", $r['headers']['content-security-policy']);
        $this->assertSame('nosniff', $r['headers']['x-content-type-options']);
        $this->assertSame('no-store', $r['headers']['cache-control']);
        $csrf = $this->csrf($r['body']);

        $r = $this->post('/login', ['username' => 'nouze', 'password' => self::PASSWORD]);
        $this->assertSame(400, $r['status'], 'bez CSRF tokenu');

        $r = $this->post('/login', ['_csrf' => $csrf, 'username' => 'nouze', 'password' => 'spatne']);
        $this->assertSame(401, $r['status']);
        $this->assertContains('Neplatné jméno nebo heslo', $r['body']);

        $r = $this->post('/login', ['_csrf' => $csrf, 'username' => 'nouze', 'password' => self::PASSWORD]);
        $this->assertSame(303, $r['status']);
        $this->assertSame('/login/mfa-setup', $r['headers']['location']);

        $r = $this->get('/');
        $this->assertSame(303, $r['status'], 'bez MFA není přístup');

        $r = $this->get('/login/mfa-setup');
        $this->assertSame(200, $r['status']);
        $this->assertContains('data-qr="otpauth://totp/', $r['body']);
        preg_match('#<code class="secret">([A-Z2-7 ]+)</code>#', $r['body'], $m);
        $secret = str_replace(' ', '', $m[1] ?? '');
        $this->assertSame(32, strlen($secret));
        $csrf = $this->csrf($r['body']);

        $r = $this->post('/login/mfa-setup', ['_csrf' => $csrf, 'code' => '000000']);
        $this->assertSame(401, $r['status']);

        $step = intdiv(time(), 30);
        $r = $this->post('/login/mfa-setup', ['_csrf' => $csrf, 'code' => Totp::code($secret, $step)]);
        $this->assertSame(303, $r['status']);
        $this->assertSame('/', $r['headers']['location']);

        $r = $this->get('/');
        $this->assertSame(200, $r['status']);
        $this->assertContains('Integrita auditu', $r['body']);
        $this->assertContains('v pořádku', $r['body']);
        $csrf = $this->csrf($r['body']);

        $r = $this->get('/admin/users');
        $this->assertSame(200, $r['status']);
        $this->assertContains('nouze', $r['body']);

        $r = $this->get('/admin/audit?verify=1');
        $this->assertContains('Řetěz integrity je v pořádku', $r['body']);
        $this->assertContains('auth.mfa_enroll', $r['body']);

        $r = $this->get('/admin/audit?ip=999.1.1.1&user=%25_x&from=nesmysl');
        $this->assertSame(200, $r['status'], 'neplatné filtry se ignorují');
        $r = $this->get('/admin/audit?ip=127.0.0.0/8');
        $this->assertContains('auth.login', $r['body']);

        $r = $this->get('/admin/audit?format=csv');
        $this->assertSame(200, $r['status']);
        $this->assertContains('text/csv', $r['headers']['content-type']);
        $this->assertContains('auth.login', $r['body']);

        $r = $this->get('/neexistuje');
        $this->assertSame(404, $r['status']);

        $r = $this->post('/logout', ['_csrf' => $csrf]);
        $this->assertSame(303, $r['status']);
        $this->assertSame(303, $this->get('/')['status']);

        // druhé přihlášení: heslo → kód (stejný kód znovu neprojde)
        $csrf = $this->csrf($this->get('/login')['body']);
        $r = $this->post('/login', ['_csrf' => $csrf, 'username' => 'nouze', 'password' => self::PASSWORD]);
        $this->assertSame('/login/mfa', $r['headers']['location']);
        $csrf = $this->csrf($this->get('/login/mfa')['body']);
        $r = $this->post('/login/mfa', ['_csrf' => $csrf, 'code' => Totp::code($secret, $step)]);
        $this->assertSame(401, $r['status'], 'replay kódu');
        $r = $this->post('/login/mfa', ['_csrf' => $csrf, 'code' => Totp::code($secret, $step + 1)]);
        $this->assertSame(303, $r['status']);
        $this->assertSame(200, $this->get('/')['status']);

        $this->assertTrue($this->audit->verify()['ok']);
        $this->assertSame(2, (int) $this->db->value("SELECT count(*) FROM audit_log WHERE action = 'auth.login' AND result = 'ok'"));
    }

    public function testForbiddenForRoleWithoutPermission(): void
    {
        $auth = new Authenticator($this->db, new FakeDirectory([]), $this->audit, new Crypto(self::$key), []);
        $auth->setLocalUser('auditor', self::PASSWORD, '127.0.0.1', 'auditor', 'test');
        $secret = Totp::generateSecret();
        $this->db->exec("UPDATE users SET totp_secret = ?, mfa_enrolled_at = now() WHERE username = 'auditor'",
            [(new Crypto(self::$key))->encrypt($secret)]);

        $csrf = $this->csrf($this->get('/login')['body']);
        $this->post('/login', ['_csrf' => $csrf, 'username' => 'auditor', 'password' => self::PASSWORD]);
        $csrf = $this->csrf($this->get('/login/mfa')['body']);
        $r = $this->post('/login/mfa', ['_csrf' => $csrf, 'code' => Totp::code($secret, intdiv(time(), 30))]);
        $this->assertSame(303, $r['status']);
        $this->assertSame(200, $this->get('/admin/audit')['status']);
        $r = $this->get('/admin/users');
        $this->assertSame(403, $r['status']);
        $this->assertSame(1, (int) $this->db->value("SELECT count(*) FROM audit_log WHERE action = 'access.denied'"));
    }

    private function csrf(string $html): string
    {
        preg_match('/name="_csrf" value="([0-9a-f]+)"/', $html, $m);
        return $m[1] ?? '';
    }

    /** @return array{status:int, headers:array<string,string>, body:string} */
    private function get(string $path): array
    {
        return $this->request('GET', $path);
    }

    /** @param array<string,string> $data @return array{status:int, headers:array<string,string>, body:string} */
    private function post(string $path, array $data): array
    {
        return $this->request('POST', $path, http_build_query($data));
    }

    /** @return array{status:int, headers:array<string,string>, body:string} */
    private function request(string $method, string $path, string $body = ''): array
    {
        $headers = ['Content-Type: application/x-www-form-urlencoded'];
        if ($this->cookies !== []) {
            $headers[] = 'Cookie: ' . implode('; ', array_map(fn ($k, $v) => "$k=$v", array_keys($this->cookies), $this->cookies));
        }
        $ctx = stream_context_create(['http' => [
            'method' => $method, 'header' => implode("\r\n", $headers), 'content' => $body,
            'ignore_errors' => true, 'follow_location' => 0, 'timeout' => 10,
        ]]);
        $resp = file_get_contents('http://127.0.0.1:' . self::$port . $path, false, $ctx);
        $status = 0;
        $out = [];
        foreach ($http_response_header as $h) {
            if (preg_match('#^HTTP/\S+ (\d+)#', $h, $m)) {
                $status = (int) $m[1];
                continue;
            }
            [$k, $v] = array_pad(explode(':', $h, 2), 2, '');
            $k = strtolower(trim($k));
            $out[$k] = isset($out[$k]) ? $out[$k] . "\n" . trim($v) : trim($v);
            if ($k === 'set-cookie' && preg_match('/^([^=]+)=([^;]*)/', trim($v), $c)) {
                $this->cookies[$c[1]] = $c[2];
            }
        }
        return ['status' => $status, 'headers' => $out, 'body' => (string) $resp];
    }
}
