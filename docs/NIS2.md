# Linux Mail Dashboard a požadavky NIS2

Panel slouží ke **dvěma účelům**: hledání provozních problémů pošty a **detekci a vyšetřování útoků**.
Je tedy součástí bezpečnostních opatření organizace – a zároveň sám je aktivem, které musí opatření splňovat.

> **Právní rámec (ČR):** zákon č. 264/2025 Sb., o kybernetické bezpečnosti (transpozice směrnice
> NIS2, účinný od 1. 11. 2025) a vyhlášky NÚKIB o bezpečnostních opatřeních – č. 409/2025 Sb. (režim
> vyšších povinností) a č. 410/2025 Sb. (režim nižších povinností).
>
> Tento dokument mapuje funkce panelu na oblasti opatření. **Není právním výkladem.** Konkrétní
> povinnosti (zejména lhůty uchovávání záznamů a rozsah zaznamenávaných událostí) ověřte v příslušné
> vyhlášce pro režim, do kterého organizace spadá. Všechny lhůty jsou proto v panelu **nastavitelné**.

Stav: ✅ hotovo · 🔜 plánováno (krok v [NAVRH.md](NAVRH.md)) · 🏢 organizační opatření mimo panel

---

## 1. Řízení přístupu a autentizace

| Požadavek | Řešení v panelu | Stav |
|-----------|-----------------|------|
| Jednoznačná identita uživatelů | přihlášení účty AD, žádné sdílené účty; nouzový lokální účet jen z CLI a jen z povolených IP | ✅ |
| **Vícefaktorová autentizace** privilegovaných přístupů | TOTP **povinné pro všechny** účty včetně nouzového; ochrana proti opakovanému použití kódu; reset jen administrátorem s auditem | ✅ |
| Nejmenší oprávnění, oddělení rolí | 5 rolí (admin, bezpečnostní analytik, operátor, helpdesk, auditor), oprávnění pevně v kódu; analytik nemůže zasahovat do pošty, auditor nevidí předměty zpráv | ✅ |
| Řízení přístupu centrálně | role ze skupin AD (podle SID, včetně vnořených), obnova při každém přihlášení; odebrání ze skupiny = ztráta přístupu při dalším přihlášení | ✅ |
| Okamžité odebrání přístupu | zakázání účtu v panelu (web/CLI) platí okamžitě i pro běžící session; zakázaný účet v AD se nepřihlásí | ✅ |
| Ochrana proti hádání hesel | limit pokusů na účet i IP (password spraying), různé zápisy jména limit neobejdou, odblokování s auditem | ✅ |
| Bezpečná session | HttpOnly, Secure, SameSite=Strict, prefix `__Host-`, nové ID po přihlášení, odhlášení po nečinnosti (výchozí 15 min) a po max. době (8 h) | ✅ |
| Přezkoumání oprávnění | přehled uživatelů, rolí, MFA a posledního přihlášení; export auditu | ✅ / 🏢 pravidelná revize |

## 2. Zaznamenávání událostí (logování)

| Požadavek | Řešení | Stav |
|-----------|--------|------|
| Záznam činností uživatelů panelu | auditní záznam: přihlášení (i neúspěšná, s technickým důvodem), MFA, odhlášení, odepřený přístup, změny uživatelů a rolí, export, ověření integrity, migrace | ✅ |
| Záznam přístupu k osobním údajům | každé hledání v logech pošty a zobrazení obsahu zprávy se zapíše do auditu | 🔜 krok 3 |
| Obsah záznamu | čas (UTC, mikrosekundy), uživatel, IP, akce, výsledek, podrobnosti | ✅ |
| **Ochrana integrity záznamů** | hash chain (SHA-256) počítaný triggerem v DB; UPDATE/DELETE/TRUNCATE zakázané; ověření `bin/mailpanel audit:verify` i z webu | ✅ |
| Ochrana proti správci systému | hlava řetězu se každou hodinu zapisuje do syslogu → centrální log/SIEM (`audit:anchor`); přepsání historie se pozná porovnáním | ✅ (nutné nastavit přeposílání) |
| Logy pošty jen pro zápis | collector má do logových tabulek jen INSERT; retenci (mazání) dělá jen vlastník DB | ✅ schéma / 🔜 collector |
| Kopie logů mimo server | přeposílání rsyslogem přes TLS na centrální log server (`deploy/rsyslog-mailpanel-forward.conf`) – při kompromitaci mail serveru zůstanou logy jinde | 🏢 + vzor v repozitáři |
| Synchronizace času | `bin/mailpanel check` hlídá NTP; časy v DB v UTC; dohled na chrony | ✅ / 🔜 dohled |
| **Doba uchovávání** | nastavitelná retence po měsících (partitions). Výchozí návrh: bezpečnostně relevantní záznamy (přihlášení, odmítnutí, surové logy) **18 měsíců**, audit panelu 2 roky – ověřte ve vyhlášce | 🔜 krok 2 |

## 3. Detekce kybernetických bezpečnostních událostí

| Událost | Jak se pozná | Stav |
|---------|--------------|------|
| Útok hrubou silou na schránky (IMAP/POP3/SMTP AUTH) | neúspěšná přihlášení z IP / na účet za čas | 🔜 krok 6 |
| Password spraying | jedna IP, mnoho různých účtů, málo pokusů na účet | 🔜 krok 6 |
| Úspěšné přihlášení po sérii neúspěchů | korelace v `auth_event` | 🔜 krok 6 |
| Kompromitovaný účet rozesílá spam | SASL uživatel: náhlý nárůst zpráv, mnoho domén příjemců, vysoký bounce rate | 🔜 krok 6 |
| Přihlášení z neobvyklé IP / země | nová IP / ASN / země oproti historii účtu | 🔜 krok 6 |
| Vlastní IP na blacklistu (RBL) | pravidelná kontrola | 🔜 krok 6 |
| Útok na panel samotný | neúspěšná přihlášení a odepřené přístupy v auditu panelu | ✅ záznam / 🔜 upozornění |
| Narušení integrity auditu | `audit:verify` + upozornění | ✅ / 🔜 upozornění |

Upozornění odchází kanálem nezávislým na mail serveru (webhook – SMS, chat) a zároveň jako událost
v syslogu pro SIEM.

## 4. Hledání útoků a vyšetřování (threat hunting)

Plánováno v krocích 3 a 6 (viz [NAVRH.md](NAVRH.md)):

- **pivot podle IP / rozsahu CIDR** napříč všemi záznamy (přihlášení, odmítnutí, odeslaná pošta),
- **časová osa účtu** – přihlášení, odeslané zprávy, změny,
- hledání podle odesílatele, příjemce, Message-ID, Queue-ID, SASL uživatele,
- fulltext v surových lozích,
- export výsledků (CSV) pro hlášení incidentu a předání vyšetřovatelům; každý export v auditu.

## 5. Řešení incidentů

| Požadavek | Řešení | Stav |
|-----------|--------|------|
| Podklady pro hlášení (včasné varování 24 h, oznámení 72 h, závěrečná zpráva) | časová osa, export dotčených účtů a zpráv, audit kroků obsluhy | 🔜 |
| Zásah | odhlášení uživatele ze všech zařízení (`doveadm kick`), zadržení fronty | 🔜 krok 5 |
| Postup a kontakty | plán řešení incidentů organizace | 🏢 |

## 6. Bezpečnost panelu samotného

| Oblast | Řešení | Stav |
|--------|--------|------|
| Síťová izolace | samostatný vhost jen pro správcovskou síť/VPN (`allow/deny`), ne na veřejném hostname | ✅ vzor `deploy/` |
| Šifrování přenosu | jen HTTPS (TLS 1.2+), HSTS; AD jen přes LDAPS/StartTLS s ověřením certifikátu | ✅ |
| Šifrování uložených tajemství | MFA tajemství a hesla služeb šifrované (libsodium), klíč mimo DB | ✅ |
| Oddělení oprávnění | vlastní uživatel `mailpanel`, vlastní PHP-FPM pool, `open_basedir`, zakázané spouštění příkazů z webu; akce s právy roota jen přes agenta s whitelistem | ✅ / 🔜 agent |
| Oddělení DB rolí | web / collector / agent / vlastník s minimálními GRANTy | ✅ schéma |
| Bezpečný vývoj | žádné runtime závislosti třetích stran (kromě lokální knihovny QR kódu), parametrizované SQL, escapování výstupu, CSP bez inline skriptů, CSRF, testy v CI | ✅ |
| Hlášení zranitelností | [SECURITY.md](../SECURITY.md) | ✅ |
| Změnové řízení | konfigurace mimo git, migrace s kontrolním součtem, audit migrací | ✅ / 🏢 |
| Zálohování | DB panelu (`pg_dump`) včetně auditu | 🏢 |

## 7. Ochrana osobních údajů (GDPR)

Logy pošty obsahují osobní údaje (kdo komu píše). Panel proto:
přístup řídí rolemi, předměty zpráv nevidí auditor, obsah zpráv jen administrátor s auditem,
každé hledání zapisuje do auditu a data maže po uplynutí retence. Právní titul zpracování
(plnění právní povinnosti podle ZKB, oprávněný zájem) a informování zaměstnanců jsou 🏢.
