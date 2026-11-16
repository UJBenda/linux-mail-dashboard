# Linux Mail Dashboard – návrh dohledového a administračního panelu pro iRedMail

> Stav: **krok 1 hotový** (přihlášení přes AD + MFA, role, audit s ochranou integrity), další kroky viz kap. 11
> Účel: hledání provozních problémů **a detekce a vyšetřování útoků**; požadavky NIS2 viz [NIS2.md](NIS2.md)
> Prostředí: Ubuntu, iRedMail (free) – Postfix, Dovecot, Amavis, SpamAssassin, ClamAV, iRedAPD, Nginx
> Panel: Nginx + PHP-FPM 8.3+, PostgreSQL, přihlášení přes Active Directory
> Schéma DB: [db/migrations/001_init.sql](../db/migrations/001_init.sql) (ověřeno na PostgreSQL 16)

---

## 1. Cíle a rozsah

| # | Co | Fáze |
|---|----|------|
| 1 | Přihlášení přes AD (LDAPS/StartTLS) + **povinné MFA (TOTP)**, role podle skupin AD, nouzový lokální účet, audit s ochranou integrity | 1 |
| 2 | Dashboard: provoz in/out, odmítnuté, spam/viry, fronta, stav služeb, grafy | 1 |
| 3 | Logy v PostgreSQL: hledání, filtry, fulltext, živé sledování | 1 |
| 4 | **Trasování zprávy** – celá cesta zprávy (příjem → Amavis → doručení) na jedné stránce | 1 |
| 5 | Fronta Postfixu: přehled, filtry, důvody odkladu, graf v čase | 1 (čtení) / 2 (akce) |
| 6 | Karanténa Amavisu: přehled, náhled hlaviček, uvolnění, smazání | 1 (čtení) / 2 (akce) |
| 7 | Schránky: velikost, kvóta, poslední přihlášení, stav v AD, **opuštěné schránky** | 1 |
| 8 | Bezpečnost a **hledání útoků**: brute force, password spraying, kompromitovaný účet, pivot podle IP/účtu, časová osa | 2 |
| 9 | Upozornění: e-mail přes externí SMTP a obecný **webhook** (SMS brána, Teams, Slack, ntfy…) | 2 |
| 10 | Kontroly: RBL listování vlastní IP, expirace certifikátů, SPF/DKIM/DMARC, disk | 2 |
| 11 | (volitelně) Správa domén, schránek, aliasů – náhrada iRedAdmin | 3 |

Mimo rozsah fáze 1–2: zápisy do databází iRedMailu (vmail). Panel je **čte**; správu účtů dál dělá iRedAdmin,
dokud se nerozhodne o fázi 3.

---

## 2. Co z návrhu Gemini platí a co ne

Kostra je rozumná, ale pár věcí je u iRedMailu zbytečných a jedna je nebezpečná.

### 2.1 Spousta dat už v iRedMailu je – nevymýšlet znovu

iRedMail zakládá SQL databáze `vmail`, `amavisd` a `iredapd` i při backendu OpenLDAP (v LDAPu jsou pak jen
účty; tabulky níže zůstávají v SQL):

| Data | Kde už jsou | Poznámka |
|------|-------------|----------|
| Obsazenost schránek | `vmail.used_quota` (`username`, `bytes`, `messages`) | Dovecot `quota = dict:…` – **už to dělá**, `doveadm quota get -A` ani sudo nepotřebujeme |
| Poslední přihlášení | `vmail.last_login` (`username`, `imap`, `pop3`, `lda` jako epoch) | Dovecot plugin `last_login` – v novějších iRedMail zapnutý ve výchozím stavu |
| Spam/viry, skóre | `amavisd.msgs`, `msgrcpt`, `maddr` | Amavis SQL logging – zapnutý |
| Karanténa | `amavisd.quarantine` | iRedMail karanténuje do SQL; cron ji promazává (výchozí řádově dny) |
| Greylisting, throttling | `iredapd.*` | iRedAPD |

**Ověřit na serveru** (podle backendu MariaDB / PostgreSQL):

```bash
grep -E '^(quota|last_login)' -r /etc/dovecot/dovecot.conf /etc/dovecot/conf.d/ 2>/dev/null
```

```bash
grep -E 'storage_sql_dsn|lookup_sql_dsn|@storage_sql' /etc/amavis/conf.d/50-user
```

Důsledek: panel tyto tabulky jen **čte** (read-only DB účet) a do své DB si dělá kopii/agregace – amavisd data
iRedMail po pár dnech maže, takže dlouhodobé statistiky musíme mít u sebe (`stats_hourly`).

### 2.2 Sudoers s hvězdičkou – nepoužívat

```
www-data ALL=(ALL) NOPASSWD: … /usr/sbin/postsuper -d *, …
```

- `*` v sudoers zahrnuje i mezery a cokoli: `sudo postsuper -d ALL` **smaže celou frontu**,
  `postsuper -d - ` čte ID ze stdin, `-d X -r ALL` přidá další přepínače.
- Kdokoli, kdo najde chybu v PHP (RCE, upload), dostane tyto akce zadarmo.
- `www-data` je na iRedMail serveru sdílený s Roundcube/SOGo/iRedAdmin.

**Místo toho:** agent (kap. 5) – web jen zapíše úkol do DB, agent ho znovu zvaliduje a provede.

### 2.3 Fronta nepotřebuje sudo

`postqueue -j` (i `-p`) smí volat každý uživatel, pokud to neomezuje `authorized_mailq_users`. Čtení fronty
tedy jde bez roota. Při velké frontě (desítky tisíc zpráv) číst výstup proudově přes `proc_open`, ne
`shell_exec` celý do paměti. Pro dashboard se fronta **vzorkuje každou minutu** do `queue_sample`
(počty, nejstarší zpráva, top důvody odkladu) – stránka pak nečeká na `postqueue`.

### 2.4 Validace Queue-ID nestačí regulárním výrazem

Krátká ID jsou hex proměnné délky, dlouhá (`enable_long_queue_ids`) alfanumerická. Regex
`^[0-9A-Za-z]{6,20}$` je jen první síto. Agent navíc **ověří, že ID ve frontě opravdu je** (aktuální
`postqueue -j`), a příkaz spouští přes `proc_open([...])` s polem argumentů – **bez shellu**, takže
`escapeshellarg` ani není potřeba.

### 2.5 rsyslog `ompgsql` nestačí

`ompgsql` uloží surové řádky, ale nic nespojí. Hledání „co se stalo se zprávou od X pro Y“ potřebuje
**korelaci podle Queue-ID** napříč procesy (smtpd → cleanup → qmgr → smtp-amavis → Amavis → nové Queue-ID →
lmtp/smtp). To dělá vlastní collector (kap. 4). Surové řádky ukládáme také (fulltext), ale navíc
strukturovaně.

### 2.6 Materialized views → inkrementální agregace

`REFRESH MATERIALIZED VIEW` přepočítává vše od nuly; nad měsíci logů to trvá a drží zámky. Collector místo
toho při zpracování řádku rovnou přičte do `stats_hourly` (`INSERT … ON CONFLICT DO UPDATE SET value = value + n`).
Agregace pak přežijí i smazání surových dat po retenci.

### 2.7 PHP 8.5

Nic z návrhu PHP 8.5 nepotřebuje. Ubuntu 24.04 má v balíčcích **8.3** – doporučuji ji (bezpečnostní updaty
z distribuce bez PPA). 8.5 přes PPA `ondrej/php` jde, ale není důvod.

### 2.8 Opuštěné schránky

Pohled z Gemini je v pořádku jako nápad, vylepšení v [001_init.sql](../db/migrations/001_init.sql) (`abandoned_mailboxes()`):

- prahy (dny, MB) jako parametry – nastavitelné v portálu,
- „poslední přihlášení“ = max z IMAP, POP3 a **SMTP SASL** (kdo jen odesílá z telefonu, není opuštěný),
- AD stav nejen `ACCOUNTDISABLE` v `userAccountControl`, ale i `accountExpires` a **účet v AD neexistuje** –
  (bit `ACCOUNTDISABLE` v `userAccountControl`, `accountExpires`, účet nenalezen),
- sloupec `reason` – proč je schránka v seznamu.

---

## 3. Architektura

```
                       ┌─────────────────────── mail server (Ubuntu, iRedMail) ───────────────────────┐
                       │                                                                              │
 Admin (prohlížeč) ────┼─► Nginx (vnitřní vhost, jen LAN/VPN) ─► PHP-FPM pool „mailpanel“ (uživatel    │
                       │                                          mailpanel, ne www-data)             │
                       │                                            │  │  │                           │
                       │                 AD (LDAPS) ◄───────────────┘  │  │                           │
                       │                                               │  │ read-only                 │
                       │   PostgreSQL „mailpanel“ ◄────────────────────┘  └──► vmail, amavisd, iredapd │
                       │     ▲      ▲        │ NOTIFY agent_task                (MariaDB nebo PG)     │
                       │     │      │        ▼                                                        │
                       │     │      │   mailpanel-agent (root, systemd)                               │
                       │     │      │     postsuper / postqueue / postcat / doveadm / amavisd-release │
                       │     │      │                                                                 │
                       │     │   mailpanel-collector (systemd, skupina adm)                           │
                       │     │     tail /var/log/mail.log, dovecot, iredapd → parse → korelace        │
                       │     │                                                                        │
                       │   mailpanel-sampler (systemd timer, 1 min / 1 h / 1 den)                     │
                       │     fronta, služby, used_quota+last_login → mailbox_stats, AD sync, RBL      │
                       │            │                                                                 │
                       └────────────┼─────────────────────────────────────────────────────────────────┘
                                    └──► upozornění: webhook (HTTP POST) / e-mail přes externí SMTP
```

### 3.1 Komponenty

| Komponenta | Běží jako | Práva | Úkol |
|------------|-----------|-------|------|
| **web** | PHP-FPM pool `mailpanel` | DB role `mailpanel_web`; read-only k iRedMail DB | portál, čtení dat, zápis úkolů |
| **collector** | `mailpanel` + skupina `adm` | čte logy; DB `mailpanel_collector` | parsování logů, korelace, agregace |
| **sampler** | `mailpanel` | `postqueue -j`, `systemctl is-active`, DNS | vzorky fronty, health, sync schránek |
| **agent** | root | jen whitelist akcí; DB `mailpanel_agent` | akce nad frontou, karanténou, Dovecotem |

Collector, sampler i agent jsou CLI příkazy jednoho vstupního skriptu `bin/mailpanel`:
`bin/mailpanel collect`, `bin/mailpanel sample --every=1m`, `bin/mailpanel agent`, `bin/mailpanel migrate`,
`bin/mailpanel check`, `bin/mailpanel user:local`, `bin/mailpanel login:unlock`.

### 3.2 Kde panel běží

**Na mail serveru**, protože potřebuje logy, frontu a lokální příkazy. Ale:

- **samostatný Nginx vhost na vnitřní adrese/portu** (např. `https://mailpanel.firma.local` nebo `:8443`),
  `allow` jen pro admin VLAN/VPN, `deny all`. Ne pod veřejným hostname, kde je Roundcube/SOGo,
- **samostatný PHP-FPM pool** s vlastním uživatelem `mailpanel`, `open_basedir`, bez přístupu k `/var/vmail`,
- vlastní PostgreSQL DB. Pokud iRedMail běží na MariaDB, PostgreSQL se doinstaluje vedle (malá zátěž);
  pokud iRedMail běží na PostgreSQL, jen nová DB a role ve stejném clusteru.

Alternativa pro větší prostředí: panel na samostatné VM, na mail serveru jen collector+agent zapisující do
vzdáleného PG. Návrh to umožňuje beze změny (všechno jde přes DB), ale pro jeden server je to zbytečné.

### 3.3 Technologie

- **PHP 8.3+ bez frameworku**, Composer jen pro autoload (žádné runtime závislosti) – méně aktualizací,
  menší plocha pro útok, snadný audit kódu.
- Vlastní tenká web vrstva: router, request/response, session, CSRF, šablony v čistém PHP s escapováním.
- `ext-ldap` pro AD, `ext-pdo_pgsql` pro DB, `ext-sodium` pro šifrování tajných hodnot v DB.
- Frontend: vlastní CSS + vanilla JS, **Chart.js** uložený lokálně (žádné CDN – panel běží ve vnitřní síti).

### 3.4 Přihlášení přes Active Directory

- LDAPS (636) nebo StartTLS (389), více řadičů domény s pořadím (fallback), vlastní CA certifikát
  nahraný přes portál,
- servisní účet jen pro vyhledání uživatele (`sAMAccountName` nebo UPN), pak **bind jako uživatel**
  s jeho heslem; heslo se nikam neukládá,
- kontrola stavu účtu (zakázaný, vypršelý, uzamčený),
- skupiny přes `tokenGroups` (včetně vnořených skupin) → **role podle SID skupin** (přejmenování skupiny
  nic nerozbije); role se obnovují při každém přihlášení,
- omezení pokusů na uživatele i IP, audit každého přihlášení,
- **druhý faktor (TOTP) povinný pro všechny účty** – NIS2 vyžaduje vícefaktorovou autentizaci
  privilegovaných přístupů; kód lze použít jen jednou,
- **nouzový lokální účet** (CLI `bin/mailpanel user:local`) jen z povolených IP – pro výpadek AD, také s MFA,
- nastavení AD je v `config.php` (root:mailpanel 0640), ne v DB – změny konfigurace podléhají změnovému
  řízení a útočník s přístupem do portálu nemůže přesměrovat ověřování na vlastní server,
- diagnostika z CLI: `bin/mailpanel ad:test [jméno]` (spojení, certifikát, přihlášení, role),
  `ad:groups` (SID skupin), `check`.

---

## 4. Sběr logů (collector)

### 4.1 Zdroje

iRedMail na Ubuntu loguje přes rsyslog; část služeb do vlastních souborů. Seznam zdrojů v konfiguraci:

```php
'collector' => [
    'sources' => [
        '/var/log/mail.log',              // postfix, amavis
        '/var/log/dovecot/imap.log',      // podle /etc/rsyslog.d/ iRedMailu
        '/var/log/dovecot/pop3.log',
        '/var/log/dovecot/lmtp.log',
        '/var/log/iredapd/iredapd.log',
    ],
],
```

Skutečné cesty ověřit v `/etc/rsyslog.d/` a `/etc/dovecot/conf.d/` (iRedMail je v různých verzích mění).
Alternativa: číst **journald** (`journalctl -f -o json --cursor-file`) – jednodušší rotace, přesné časy
s rokem a mikrosekundami. Collector má dva vstupy (soubor / journal), vybírá se v konfiguraci.

### 4.2 Spolehlivé čtení

- pro každý soubor se drží `(inode, offset)` v `collector_state`,
- **dávka řádků + nový offset se zapíší v jedné transakci** → po pádu nic nezmizí ani se nezdvojí,
- rotace: změna inode → dočíst starý soubor (`mail.log.1`) do konce, pak nový od 0,
- zpoždění pod 2 s (inotify nebo polling 1 s), dávky po ≤ 1000 řádcích,
- import historie: `bin/mailpanel collect --import /var/log/mail.log.2.gz` (při nasazení naplní grafy zpětně).

### 4.3 Co se z řádků vytahuje

Ukázky (Postfix, iRedMail – Amavis jako content_filter na `smtp-amavis:[127.0.0.1]:10024`, návrat na 10025):

```
postfix/smtpd[1234]: 4XyZ1abc: client=mx.google.com[209.85.1.2]
postfix/cleanup[1240]: 4XyZ1abc: message-id=<CA...@mail.gmail.com>
postfix/qmgr[900]: 4XyZ1abc: from=<jan@gmail.com>, size=48213, nrcpt=1 (queue active)
amavis[2001]: (02001-05) Passed CLEAN {RelayedInbound}, [209.85.1.2]:41234 <jan@gmail.com> -> <petr@firma.cz>,
   Queue-ID: 4XyZ1abc, Message-ID: <CA...>, mail_id: aB3dE5fG7hJ9, Hits: -1.2, size: 48213,
   queued_as: 4XyZ2def, 1503 ms
postfix/smtp[1250]: 4XyZ1abc: to=<petr@firma.cz>, relay=127.0.0.1[127.0.0.1]:10024, delay=1.6, … status=sent
   (250 2.0.0 from MTA(smtp:[127.0.0.1]:10025): 250 2.0.0 Ok: queued as 4XyZ2def)
postfix/lmtp[1260]: 4XyZ2def: to=<petr@firma.cz>, relay=private/dovecot-lmtp, delay=0.1, dsn=2.0.0, status=sent (…)
postfix/qmgr[900]: 4XyZ2def: removed
postfix/smtpd[1300]: NOQUEUE: reject: RCPT from unknown[1.2.3.4]: 554 5.7.1 Service unavailable;
   Client host [1.2.3.4] blocked using zen.spamhaus.org; from=<x@y> to=<a@firma.cz> proto=ESMTP helo=<x>
postfix/submission/smtpd[1400]: 4XyZ3ghi: client=…, sasl_method=LOGIN, sasl_username=petr@firma.cz
dovecot: imap-login: Login: user=<petr@firma.cz>, method=PLAIN, rip=10.0.0.5, lip=…, TLS, session=<…>
dovecot: auth: … (petr@firma.cz,1.2.3.4): Password mismatch      → auth_event success=false
```

| Řádek | Cílová tabulka |
|-------|----------------|
| `client=`, `sasl_username=` | `mail_message` (nová instance, `client_ip`, `sasl_username`) |
| `message-id=` | `mail_message.message_id` |
| `qmgr … from=, size=, nrcpt=` | `mail_message.sender`, `size`, `nrcpt` |
| `to=…, status=` | `mail_delivery` (+ `mail_message.status`) |
| Amavis `Passed/Blocked …, queued_as:` | `amavis_result`, `spam_score`, `amavis_mail_id`; **`queued_as` → `parent_id` nové instance** |
| `removed` | uzavření instance, smazání z `mail_open` |
| `NOQUEUE: reject`, `postscreen … DNSBL/PREGREET` | `mail_reject` + `category` |
| `postsuper … removed / placed on hold` | `status = deleted / held` |
| Dovecot login / auth fail, SASL `authentication failed` | `auth_event` |
| vše | `log_line` (surově, s `queue_id` pokud je) |

**Směr zprávy:** `sasl_username` nebo klient z `mynetworks` = `out`/`internal` (podle domény příjemce),
jinak `in`. Lokální domény se načtou z vmail DB (`domain` + `alias_domain`).

**Recyklace krátkých Queue-ID:** stejné ID se může po čase objevit znovu → identita je
`(host, queue_id, first_seen)`; „otevřené“ instance drží `mail_open`.

**Předmět zprávy:** Postfix ho sám neloguje. Pokud je potřeba hledat podle předmětu:
`header_checks = regexp:/etc/postfix/header_checks` s `/^Subject:/ WARN` – ale je to **osobní údaj** (GDPR),
viz kap. 8. Alternativa bez zásahu do Postfixu: předmět z `amavisd.msgs.subject` (jen pro zprávy přes Amavis).

### 4.4 Objem a retence

Orientačně: 10 000 zpráv/den ≈ 150 000 řádků logu/den ≈ 50–80 MB/den v `log_line` vč. indexů.

| Data | Retence (výchozí, nastavitelné) |
|------|---------------------------------|
| `log_line` (surové) | 18 měsíců |
| `mail_reject`, `auth_event` (bezpečnostní události) | 18 měsíců |
| `mail_message`, `mail_delivery` | 18 měsíců |
| `stats_hourly`, `queue_sample` (agregace) | natrvalo / `queue_sample` 1 rok |
| `audit_log` (činnost v panelu) | 2 roky |

Výchozí 18 měsíců vychází z požadavků na uchovávání bezpečnostních záznamů – konkrétní lhůtu pro váš
režim ověřte ve vyhlášce NÚKIB (viz [NIS2.md](NIS2.md)). Proti tomu stojí minimalizace osobních údajů
(GDPR) – proto jsou lhůty nastavitelné po tabulkách. Při 10 000 zprávách/den počítejte s ~30–45 GB
pro 18 měsíců surových logů; pokud je to moc, zkraťte retenci `log_line` a nechte delší retenci
strukturovaných bezpečnostních tabulek.

Měsíční partitions (`ensure_partitions()`, `drop_old_partitions()` ve schématu) – mazání starých dat je
`DROP TABLE` jedné partition, okamžité a bez bloatu.

---

## 5. Akce s právy roota (agent)

### 5.1 Princip

```
web:   INSERT INTO agent_task (action, args, requested_by, requested_ip) VALUES ('queue.delete', '{"queue_ids":[…]}', …)
       ← DB trigger → NOTIFY agent_task
agent: LISTEN agent_task → SELECT … FOR UPDATE SKIP LOCKED → validace → proc_open([...]) → UPDATE status/result
web:   stránka se dotazuje na stav úkolu (polling 1 s) a zobrazí výsledek
```

- web **nemůže** změnit `status` úkolu (sloupcová práva v PG) → nepodvrhne „hotovo“,
- agent **nevěří** ničemu z DB: znovu validuje akci (whitelist), formát argumentů a existenci ID ve frontě,
- žádný shell: `proc_open(['/usr/sbin/postsuper', '-d', $id], …)`. Hromadné mazání přes `postsuper -d -`
  se seznamem ID na stdin (ID od agenta ověřená, ne `ALL`),
- limity: max. 1000 ID na úkol, max. N úkolů za minutu na uživatele,
- každá akce → `audit_log` (kdo, odkud, co, výsledek),
- agent se neotevírá do sítě – jen lokální spojení do PG (unix socket, `peer`/`scram`).

### 5.2 Whitelist akcí

| Akce | Příkaz | Role |
|------|--------|------|
| `queue.show` | `postcat -hq <id>` (jen hlavičky; tělo jen pro roli `admin` a s auditem) | operator |
| `queue.hold` / `queue.release` | `postsuper -h` / `-H` | operator |
| `queue.requeue` | `postsuper -r` | operator |
| `queue.delete` | `postsuper -d` (seznam ověřených ID) | operator |
| `queue.flush` | `postqueue -f` / `postqueue -i <id>` | operator |
| `quarantine.release` | `amavisd-release` / AM.PDP na `127.0.0.1:9998` | operator |
| `mailbox.quota_recalc` | `doveadm quota recalc -u <user>` | admin |
| `mailbox.kick` | `doveadm kick <user>` (např. po kompromitaci) | admin |
| `service.status` | `systemctl is-active postfix dovecot amavis clamav-daemon iredapd fail2ban …` | – (sampler) |

Uvolnění z karantény přes AM.PDP (TCP na localhostu, `request=release`, `mail_id`, `secret_id`,
`partition_tag`) nepotřebuje roota – může to dělat přímo web, stejně jako iRedAdmin. Pro jednotný audit
a omezení přesto doporučuji přes agenta.

### 5.3 systemd

```ini
# /etc/systemd/system/mailpanel-agent.service
[Service]
ExecStart=/usr/bin/php /opt/mailpanel/bin/mailpanel agent
User=root
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/spool/postfix /var/lib/amavis /run
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER CAP_SETUID CAP_SETGID CAP_KILL
Restart=always
```

(Přesný seznam `ReadWritePaths`/capabilities doladit při nasazení – `postsuper` potřebuje zapisovat do
spoolu jako `postfix`, `doveadm` přes socket Dovecotu.)

---

## 6. Portál – obrazovky

### 6.1 Dashboard

- **Dlaždice (24 h):** přijato, odesláno, odmítnuto, spam, viry, ve frontě (active/deferred/hold),
  nejstarší zpráva ve frontě, neúspěšná přihlášení.
- **Grafy:** provoz in/out po hodinách (7 dní), odmítnutí podle kategorie (RBL, neznámý příjemce,
  greylisting, SPF…), spam/čisté/viry (podíl), velikost fronty v čase (`queue_sample`).
- **Stav:** služby (zelená/červená), disk `/var/vmail`, certifikát (dní do expirace), RBL listování
  vlastní IP, aktivní upozornění.
- **Top 10:** odesílatelé ven, domény příjemců s chybami, IP s nejvíc odmítnutími.

Knihovna grafů: **Chart.js** (lokálně v `public/assets`, žádná CDN).
Data přes JSON endpointy z `stats_hourly`, odpověď v řádu ms.

### 6.2 Hledání zpráv (trasování)

Filtry: čas od–do, odesílatel, příjemce (i část, `@domena.cz`), Queue-ID, Message-ID, IP klienta,
SASL uživatel, stav (doručeno / odloženo / vráceno / odmítnuto / spam / karanténa), směr.

Výsledek: tabulka zpráv → **detail**: časová osa všech instancí (před a po Amavisu) a všech pokusů
o doručení, odpověď vzdáleného serveru, Amavis výsledek a skóre, odkaz do karantény, surové řádky logu.
To je nejčastější helpdesk dotaz („nepřišel mi mail od…“) – odpověď na jednom místě.

### 6.3 Logy

Surový log s filtry: čas, program (postfix/*, dovecot, amavis, iredapd), závažnost, host, text
(trigramový index – `ILIKE '%…%'` je rychlé i nad miliony řádků), Queue-ID (klik → trasování).
**Živé sledování**: stránka se dotazuje `?after_id=` každé 2 s (bez WebSocketů). Export CSV.

### 6.4 Fronta

Tabulka z aktuálního `postqueue -j`: Queue-ID, fronta, čas příchodu, odesílatel, příjemci, velikost,
**důvod odkladu** (`delay_reason`). Filtry (fronta, odesílatel, doména, text důvodu), seskupení podle
důvodu („1 240× connection timed out – seznam.cz“). Akce na jednu zprávu i hromadně podle filtru –
vždy s potvrzením a počtem („Opravdu smazat 1 240 zpráv?“).

### 6.5 Karanténa

Ze `amavisd.msgs` + `msgrcpt` + `maddr` (`quar_type = 'Q'`): čas, od, komu, předmět, typ
(spam/virus/banned), skóre. Náhled hlaviček; tělo jen pro `admin` (audit). Uvolnit / smazat /
uvolnit + whitelist odesílatele (iRedAPD). Graf: karanténa podle typu za 30 dní.

### 6.6 Schránky

Tabulka: adresa, jméno, velikost, % kvóty, počet zpráv, poslední IMAP/POP3/SMTP, poslední doručení,
stav AD. Řazení a filtry (doména, > 90 % kvóty, neaktivní). Detail: graf růstu (`mailbox_size_daily`),
posledních 50 přihlášení (IP), posledních 50 zpráv.

**Opuštěné schránky:** `abandoned_mailboxes(dní, MB)` – export CSV pro úklid.

Mapování schránka ↔ AD účet (nastavení): podle `mail`, `proxyAddresses` (`smtp:` i `SMTP:`)
nebo `userPrincipalName`. Denní sync (sampler): jeden LDAP dotaz na všechny uživatele s e-mailem
(stránkování), ne dotaz na každou schránku.

### 6.7 Bezpečnost

- neúspěšná přihlášení podle IP / účtu, graf; IP aktuálně zabanované fail2banem,
- **podezření na kompromitovaný účet:** SASL uživatel poslal > N zpráv za hodinu, na > M různých domén,
  nebo přihlášení ze zemí/IP mimo obvyklé → upozornění (+ volitelně akce `mailbox.kick`),
- vlastní IP na RBL (Spamhaus ZEN, Barracuda, SpamCop…) – kontrola po hodině z sampleru,
- odchozí bounce rate (vysoký = špatné adresy nebo spam).

Pozor: Spamhaus neodpovídá na dotazy přes veřejné resolvery (Google, Cloudflare) – kontrolu dělat přes
lokální resolver (iRedMail ho kvůli postscreenu stejně potřebuje).

### 6.8 Administrace

Uživatelé panelu (role, MFA, zakázání), auditní záznam s ověřením integrity a exportem; nastavení prahů
(upozornění, opuštěné schránky, retence); auditní log.

---

## 7. Role

| Role | Co smí |
|------|--------|
| `auditor` | jen čtení: dashboard, statistiky, audit; **bez předmětů** zpráv |
| `helpdesk` | trasování zpráv, schránky (čtení), karanténa – uvolnit zprávu jednomu příjemci |
| `operator` | logy, trasování, akce nad frontou a karanténou (hromadně) |
| `security` | bezpečnostní analytik: logy, bezpečnostní přehled, hledání útoků, audit – **bez zásahů do pošty** |
| `admin` | vše: uživatelé panelu, nastavení, tělo zpráv ve frontě/karanténě, `mailbox.kick` |

Oprávnění jsou pevně v kódu (`src/Auth/Roles.php`) – role nejde v portálu „rozšířit“.

Role se přidělují skupinami AD (viz 3.4 – SID skupin, `tokenGroups`, obnova při
každém přihlášení). Nouzový lokální účet jen z povolených IP.

---

## 8. Bezpečnost, NIS2 a GDPR

Mapování na požadavky NIS2 je v [NIS2.md](NIS2.md). Shrnutí:


- panel jen z vnitřní sítě (Nginx `allow/deny`), HTTPS, `cookie_secure`, CSRF, session limity (nečinnost, maximální délka),
- logy pošty jsou **osobní údaje** (kdo komu píše). Retence omezená (kap. 4.4), přístup podle rolí,
  **každé hledání se zapisuje do auditu** (kdo hledal čí poštu),
- předmět a tělo zprávy: předmět jen pro `helpdesk`+, tělo jen `admin` s auditem,
- read-only účet do iRedMail DB bez přístupu ke sloupci `password` (`GRANT SELECT (sloupce…)`),
- tajné hodnoty (heslo servisního účtu AD, tokeny webhooků) šifrované v DB (libsodium),
- `config.php` mimo webroot, `root:mailpanel 0640`,
- auditní záznam chráněný hash chainem, hlava řetězu každou hodinu do syslogu → centrální log/SIEM,
- logy pošty se kopírují i na centrální log server – při kompromitaci mail serveru zůstanou jinde.

---

## 9. Upozornění

Sampler každou minutu vyhodnotí pravidla a stav uloží do `alert_state` (změna stavu = notifikace,
ne každou minutu znovu):

| Pravidlo | Výchozí práh | Závažnost |
|----------|--------------|-----------|
| služba postfix/dovecot/amavis neběží | 2 min | critical |
| fronta deferred | > 500 zpráv | warning |
| nejstarší zpráva ve frontě | > 4 h | warning |
| vlastní IP na RBL | ihned | critical |
| podezření na kompromitovaný účet | viz 6.7 | critical |
| collector neběží / log stojí | 10 min | warning |
| certifikát expiruje | < 14 dní | warning |
| disk `/var/vmail` | > 85 % / > 95 % | warning / critical |

Kanály (nastavují se v portálu, každé pravidlo může jít jiným kanálem podle závažnosti):

- **Webhook** – obecný HTTP POST s JSON tělem, volitelnou hlavičkou `Authorization` a šablonou těla.
  Napojí se tak libovolná SMS brána, MS Teams, Slack, ntfy, Zabbix… bez úprav kódu:

  ```json
  {"source": "linux-mail-dashboard", "host": "mail1", "key": "queue.deferred",
   "severity": "warning", "status": "problem",
   "text": "Fronta deferred 812 (top: example.com connection timed out)"}
  ```

- **E-mail** – přes **externí** SMTP server (relay), ne přes vlastní Postfix: když stojí pošta,
  upozornění poslané tou samou poštou nedorazí.

Kanál pro závažnost `critical` by neměl záviset na funkčnosti mail serveru (webhook na SMS/chat).

---

## 10. Struktura projektu

Tento repozitář:

```
bin/mailpanel          CLI: migrate, collect, sample, agent, check, user:local, login:unlock, import
config/                config.php (DB, iRedMail DB DSN, zdroje logů) – není v gitu
db/migrations/         001_init.sql
deploy/                nginx vhost, php-fpm pool, systemd: collector, agent, sampler.timer
public/                index.php, assets (Chart.js lokálně)
src/
  Ad/         AdClient, AdDiagnostics, CertificateStore
  Auth/       Authenticator, Roles
  Web/        Kernel, Router, Request, Response, Session, View
  Support/    Db, Config, Crypto, Settings, Audit, Migrator
  Collector/  LogReader, PostfixParser, DovecotParser, AmavisParser, Correlator, StatsWriter
  Queue/      PostqueueReader (proudově), QueueService
  Quarantine/ AmavisRepository, ReleaseClient (AM.PDP)
  Mailbox/    MailboxSync (used_quota, last_login, AD)
  Agent/      Agent, TaskValidator, Actions/*
  Alert/      Rules, Channels/Webhook, Channels/Email
  Web/Controller/  Dashboard, Trace, Logs, Queue, Quarantine, Mailboxes, Security, Admin/*
templates/
tests/                 parsery logů testované na reálných (anonymizovaných) řádcích
```

---

## 11. Postup implementace

| Krok | Obsah | Výsledek |
|------|-------|----------|
| 1 ✅ | Kostra: web vrstva, DB (PostgreSQL), migrace, login přes AD + MFA, role, audit s hash chainem, CLI, testy, CI | přihlášení funguje |
| 2 | Collector: čtení souborů s offsetem, parser Postfixu + Amavisu, korelace, `stats_hourly`, import historie | data v DB |
| 3 | Dashboard + grafy, Logy, Trasování | **použitelné pro helpdesk** |
| 4 | Sampler: fronta, služby, schránky (used_quota, last_login), AD sync; obrazovky Fronta, Schránky, Karanténa (čtení) | celý přehled |
| 5 | Agent + akce (fronta, karanténa) | správa |
| 6 | Upozornění (webhook, e-mail, syslog pro SIEM), detekční pravidla, hledání útoků (pivot IP/účet, časová osa), RBL/cert/DNS kontroly | dohled a bezpečnost |
| 7 | (volitelně) správa domén/schránek/aliasů | náhrada iRedAdmin |

Parsery jsou nejrizikovější část – začít sbírkou reálných řádků ze serveru (`grep` vzorky každého typu)
a psát na ně testy dřív než parser.

---

## 12. Otevřené otázky

1. **Backend iRedMailu:** MariaDB, PostgreSQL, nebo OpenLDAP? (určuje read-only připojení a jestli se
   PostgreSQL doinstaluje vedle).
2. **Verze iRedMailu a Ubuntu** (cesty logů, zapnutý `last_login`, PHP 8.3 z distribuce?).
3. Mapování schránka ↔ AD účet: `mail`, `proxyAddresses`, nebo UPN? Jsou schránky 1:1 s AD účty?
4. Objem pošty (zpráv/den) a požadovaná retence logů.
5. Má se logovat **předmět** (header_checks WARN), nebo stačí předmět z Amavisu?
6. Panel na mail serveru (doporučeno), nebo samostatná VM?
7. Jsou žádoucí akce na schránky (kick, recalc) a správa účtů (fáze 3), nebo jen dohled + fronta + karanténa?
8. Které skupiny AD pro role `admin` / `operator` / `helpdesk` / `auditor`?
