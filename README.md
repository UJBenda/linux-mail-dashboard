# Linux Mail Dashboard

Vlastní dohledový a administrační panel pro mail server postavený na **iRedMail**
(Postfix, Dovecot, Amavis, SpamAssassin, ClamAV, iRedAPD) na Ubuntu.

Slouží k hledání provozních problémů pošty **a k detekci a vyšetřování útoků**; navržen s ohledem
na požadavky **NIS2** (zákon č. 264/2025 Sb.) – viz [docs/NIS2.md](docs/NIS2.md).

> Stav: **krok 1 hotový** – přihlášení přes AD s povinným MFA, role, auditní záznam s ochranou integrity,
> CLI, testy. Data o poště (logy, fronta, statistiky) přibudou v dalších krocích – viz [docs/NAVRH.md](docs/NAVRH.md).

## Co bude umět

- **Přihlášení přes Active Directory** (LDAPS / StartTLS) s **povinným dvoufázovým ověřením (TOTP)**, role podle
  skupin AD, nouzový lokální účet, auditní záznam chráněný proti změnám (hash chain).
- **Dashboard:** provoz in/out, odmítnuté zprávy, spam a viry, fronta, stav služeb, grafy (Chart.js).
- **Logy v PostgreSQL:** hledání, filtry, fulltext, živé sledování.
- **Trasování zprávy:** celá cesta zprávy (příjem → Amavis → doručení) na jedné stránce.
- **Fronta Postfixu:** přehled, důvody odkladu, graf v čase, akce (hold, release, requeue, delete).
- **Karanténa Amavisu:** přehled, náhled, uvolnění.
- **Schránky:** velikost, kvóta, poslední přihlášení, stav v AD, opuštěné schránky.
- **Bezpečnost a hledání útoků:** brute force, password spraying, kompromitovaný účet, pivot podle IP a účtu,
  časová osa, vlastní IP na RBL.
- **Upozornění** přes webhook (SMS brána, Teams, Slack, ntfy…) a e-mail přes externí SMTP.

## Architektura v kostce

| Komponenta | Úkol |
|------------|------|
| web (Nginx + PHP-FPM 8.3+) | portál; data jen čte, akce zapisuje jako úkoly do DB |
| collector (systemd) | čte logy, páruje záznamy podle Queue-ID, plní PostgreSQL (jen zápis) a hodinové statistiky |
| sampler (systemd timer) | vzorky fronty, stav služeb, synchronizace schránek a stavu v AD |
| agent (systemd, root) | provádí jen povolené akce (`postsuper`, `doveadm`, …) z tabulky úkolů – žádné sudo pro web |

Databáze iRedMailu (`vmail`, `amavisd`, `iredapd`) panel jen čte; vlastní data má v PostgreSQL DB `mailpanel`.

## Požadavky

- Ubuntu 22.04 / 24.04 s iRedMail
- PHP 8.3+ (`php-fpm`, `php-pgsql`, `php-ldap`, `php-mbstring`, `php-intl`; sodium je součástí PHP)
- PostgreSQL 14+ (rozšíření `pg_trgm`)
- Active Directory dostupná přes LDAPS nebo StartTLS

## Struktura

```
bin/mailpanel      CLI: migrace, collector, sampler, agent, kontroly, nouzový admin
config/            konfigurace (config.php není v gitu)
db/migrations/     SQL schéma
deploy/            Nginx, PHP-FPM pool, systemd služby
docs/              návrh a dokumentace
public/            webový kořen (index.php, CSS, JS)
src/               aplikace
templates/         šablony portálu
tests/             testy (hlavně parsery logů)
var/               běhová data (certifikáty AD, zámky) – není v gitu
```

## Dokumentace

- [Návrh řešení](docs/NAVRH.md)
- [Instalace](docs/INSTALACE.md)
- [NIS2 – mapování požadavků](docs/NIS2.md)
- [Hlášení zranitelností](SECURITY.md)

## Vývoj

```bash
php tests/run.php
```

Lokální spuštění (vestavěný server PHP, jen pro vývoj):

```bash
MAILPANEL_CONFIG=/cesta/k/config.php php -S 127.0.0.1:8080 -t public tests/dev-router.php
```

Knihovny třetích stran: [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4
(Kazuhiko Arase, MIT) v `public/assets/vendor/`.

## Licence

Copyright (C) 2026 UJBenda

Tento program je svobodný software: můžete jej šířit a upravovat podle podmínek
[GNU General Public License](LICENSE) vydané Free Software Foundation, a to buď verze 3, nebo
(podle vaší volby) kterékoli pozdější verze (`GPL-3.0-or-later`).

Zjednodušeně (závazné je znění v souboru `LICENSE`):

- **Smíte:** používat zdarma (i ve firmě), upravovat, šířit, i za úplatu.
- **Musíte:** při šíření (původní i upravené verze) zachovat informaci o autorovi a licenci,
  zpřístupnit úplný zdrojový kód včetně svých úprav a šířit ho pod stejnou licencí GPL.
- **Nesmíte:** z programu ani z jeho úprav udělat uzavřený software.

Program je poskytován BEZ JAKÉKOLI ZÁRUKY.
