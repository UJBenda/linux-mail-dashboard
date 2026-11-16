# Linux Mail Dashboard

Vlastní dohledový a administrační panel pro mail server postavený na **iRedMail**
(Postfix, Dovecot, Amavis, SpamAssassin, ClamAV, iRedAPD) na Ubuntu.

> Stav: **návrh** – viz [docs/NAVRH.md](docs/NAVRH.md). Kód zatím není.

## Co bude umět

- **Přihlášení přes Active Directory** (LDAPS / StartTLS), role podle skupin AD, nouzový lokální účet, audit.
- **Dashboard:** provoz in/out, odmítnuté zprávy, spam a viry, fronta, stav služeb, grafy (Chart.js).
- **Logy v PostgreSQL:** hledání, filtry, fulltext, živé sledování.
- **Trasování zprávy:** celá cesta zprávy (příjem → Amavis → doručení) na jedné stránce.
- **Fronta Postfixu:** přehled, důvody odkladu, graf v čase, akce (hold, release, requeue, delete).
- **Karanténa Amavisu:** přehled, náhled, uvolnění.
- **Schránky:** velikost, kvóta, poslední přihlášení, stav v AD, opuštěné schránky.
- **Bezpečnost:** brute force, podezření na kompromitovaný účet, vlastní IP na RBL.
- **Upozornění** přes SMS bránu (API) a e-mailem.

## Architektura v kostce

| Komponenta | Úkol |
|------------|------|
| web (Nginx + PHP-FPM 8.3+) | portál; data jen čte, akce zapisuje jako úkoly do DB |
| collector (systemd) | čte logy, páruje záznamy podle Queue-ID, plní PostgreSQL a hodinové statistiky |
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

## Licence

[MIT s doložkou Commons Clause](LICENSE). Zjednodušeně (závazné je znění v souboru `LICENSE`):

- **Smíte:** používat zdarma, i ve firmě pro vlastní mail server; upravovat; šířit původní i upravené verze.
- **Musíte:** zachovat informaci o autorovi a text licence (včetně doložky Commons Clause) ve všech kopiích
  a odvozených dílech.
- **Nesmíte:** software prodávat – ani jako produkt, ani jako placený hosting nebo placenou podporu,
  jejichž hodnota stojí hlavně na tomto softwaru.

Kvůli zákazu prodeje nejde o open source licenci podle definice OSI, ale o licenci se zveřejněným zdrojovým
kódem (*source-available*).
