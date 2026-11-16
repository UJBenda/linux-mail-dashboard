# Instalace (krok 1 – přihlášení, role, audit)

Postup pro Ubuntu 22.04 / 24.04 s iRedMail. Panel běží na mail serveru jako samostatná aplikace
pod vlastním uživatelem `mailpanel`. Příkazy se spouštějí jako root.

## 1. Balíčky

```bash
apt install php8.3-fpm php8.3-cli php8.3-pgsql php8.3-ldap php8.3-mbstring php8.3-intl postgresql
```

(Ubuntu 22.04 má PHP 8.1 – je potřeba 8.3, např. z PPA `ondrej/php`.)
Pokud iRedMail používá PostgreSQL, druhý PostgreSQL neinstalujte – panel dostane vlastní DB ve stejném clusteru.

## 2. Uživatel a soubory

```bash
useradd --system --home /opt/mailpanel --shell /usr/sbin/nologin mailpanel
```

```bash
git clone https://github.com/UJBenda/linux-mail-dashboard.git /opt/mailpanel
```

```bash
install -d -o mailpanel -g mailpanel -m 0700 /var/lib/mailpanel/sessions /var/log/mailpanel
```

```bash
install -d -o root -g mailpanel -m 0750 /etc/mailpanel
```

Kód patří rootovi, `mailpanel` ho jen čte (útočník přes web nemůže kód změnit):

```bash
chown -R root:root /opt/mailpanel && chmod -R go-w /opt/mailpanel
```

## 3. Databáze

```bash
sudo -u postgres psql
```

```sql
CREATE ROLE mailpanel_owner LOGIN PASSWORD 'silne-heslo-1';
CREATE ROLE mailpanel_web   LOGIN PASSWORD 'silne-heslo-2';
CREATE ROLE mailpanel_collector LOGIN PASSWORD 'silne-heslo-3';
CREATE ROLE mailpanel_agent LOGIN PASSWORD 'silne-heslo-4';
CREATE DATABASE mailpanel OWNER mailpanel_owner;
\c mailpanel
ALTER SCHEMA public OWNER TO mailpanel_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

Role vytvořte **před** migrací – migrace jim nastaví práva.

## 4. Konfigurace

```bash
cp /opt/mailpanel/config/config.example.php /opt/mailpanel/config/config.php
```

```bash
chown root:mailpanel /opt/mailpanel/config/config.php && chmod 0640 /opt/mailpanel/config/config.php
```

```bash
php /opt/mailpanel/bin/mailpanel key:generate
```

Do `config.php` doplňte `secret_key`, přihlášení k DB (`mailpanel_web`) a sekci `ad`.
CA certifikát řadičů domény (PEM) uložte do `/etc/mailpanel/ad-ca.pem`.

Migrace se spouštějí jako vlastník DB – samostatná konfigurace jen pro root:

```bash
install -m 0600 /dev/null /etc/mailpanel/owner.php
```

```php
<?php // /etc/mailpanel/owner.php
$c = require '/opt/mailpanel/config/config.php';
$c['db']['user'] = 'mailpanel_owner';
$c['db']['password'] = 'silne-heslo-1';
return $c;
```

```bash
MAILPANEL_CONFIG=/etc/mailpanel/owner.php php /opt/mailpanel/bin/mailpanel migrate
```

## 5. Active Directory

1. Servisní účet (např. `svc-mailpanel`) – běžný uživatel bez práv navíc, heslo bez expirace, zákaz interaktivního přihlášení.
2. Skupiny pro role, např. `GG-MailPanel-Admin`, `GG-MailPanel-Security`, `GG-MailPanel-Operator`, `GG-MailPanel-Helpdesk`, `GG-MailPanel-Auditor`.
3. SID skupin zjistíte a doplníte do `ad.role_groups`:

```bash
sudo -u mailpanel php /opt/mailpanel/bin/mailpanel ad:groups MailPanel
```

4. Test spojení a přihlášení konkrétního uživatele (vypíše jeho role):

```bash
sudo -u mailpanel php /opt/mailpanel/bin/mailpanel ad:test jnovak
```

## 6. Nouzový účet

Pro případ výpadku AD. Jen z uvedených IP, heslo min. 16 znaků, MFA povinné. Heslo uložte do trezoru.

```bash
sudo -u mailpanel php /opt/mailpanel/bin/mailpanel user:local nouze --ips=10.0.50.0/24 --roles=admin
```

## 7. PHP-FPM a Nginx

```bash
cp /opt/mailpanel/deploy/php-fpm-mailpanel.conf /etc/php/8.3/fpm/pool.d/mailpanel.conf
```

```bash
cp /opt/mailpanel/deploy/nginx-mailpanel.conf /etc/nginx/sites-available/mailpanel.conf
```

Upravte adresu, `server_name`, certifikát a povolené sítě, pak:

```bash
ln -s /etc/nginx/sites-available/mailpanel.conf /etc/nginx/sites-enabled/ && nginx -t && systemctl reload nginx php8.3-fpm
```

## 8. Ukotvení auditu a přeposílání logů

```bash
cp /opt/mailpanel/deploy/mailpanel-audit-anchor.{service,timer} /etc/systemd/system/
```

```bash
systemctl daemon-reload && systemctl enable --now mailpanel-audit-anchor.timer
```

Přeposílání na centrální log server / SIEM – vzor `deploy/rsyslog-mailpanel-forward.conf`
(upravte cíl a CA, pak `systemctl restart rsyslog`).

## 9. Kontrola

```bash
sudo -u mailpanel php /opt/mailpanel/bin/mailpanel check
```

Pak se přihlaste v prohlížeči. Při prvním přihlášení si každý uživatel nastaví MFA.

## Testy (vývoj)

```bash
php tests/run.php
```

Testy s databází potřebují prázdnou testovací DB (při startu se celá smaže):

```bash
MAILPANEL_TEST_DSN="pgsql:host=127.0.0.1;dbname=mailpanel_test" MAILPANEL_TEST_USER=mp_owner MAILPANEL_TEST_PASSWORD=test php tests/run.php
```
