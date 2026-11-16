-- =====================================================================
-- Linux Mail Dashboard – schéma vlastní databáze `mailpanel` (PostgreSQL 14+)
--
-- Vlastní DB panelu. Databáze iRedMailu (vmail, amavisd, iredapd) se
-- NEMĚNÍ – panel je čte přes samostatný read-only účet.
--
-- Role:
--   mailpanel_owner      vlastník schématu (migrace)
--   mailpanel_web        PHP-FPM portál (čtení, zápis úkolů, audit)
--   mailpanel_collector  sběr logů a vzorků (zápis log/stat tabulek)
--   mailpanel_agent      vykonavatel akcí (čte/aktualizuje agent_task)
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---------------------------------------------------------------------
-- 1. Uživatelé, MFA, nastavení, audit
-- ---------------------------------------------------------------------

CREATE TABLE users (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username         text NOT NULL UNIQUE,              -- lower(sAMAccountName) / lokální jméno
    display_name     text NOT NULL DEFAULT '',
    email            text,
    source           text NOT NULL CHECK (source IN ('ad', 'local')),
    ad_dn            text,
    password_hash    text,                               -- jen 'local' (Argon2id / bcrypt)
    allowed_ips      text,                               -- jen 'local': CIDR seznam oddělený čárkou
    roles            text NOT NULL DEFAULT '',           -- 'admin,security' – u AD se obnovuje při každém loginu
    is_active        boolean NOT NULL DEFAULT true,
    totp_secret      text,                               -- šifrováno (libsodium secretbox), NULL = MFA nenastaveno
    totp_last_step   bigint,                             -- ochrana proti opakovanému použití kódu
    mfa_enrolled_at  timestamptz,
    last_login_at    timestamptz,
    last_login_ip    inet,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_local_hash CHECK (source <> 'local' OR password_hash IS NOT NULL)
);

CREATE TABLE login_attempts (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username    text NOT NULL,
    ip          inet NOT NULL,
    stage       text NOT NULL DEFAULT 'password' CHECK (stage IN ('password', 'mfa')),
    success     boolean NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_attempts_user_idx ON login_attempts (username, created_at);
CREATE INDEX login_attempts_ip_idx   ON login_attempts (ip, created_at);

-- Odemčení po zablokování: pokusy starší než tento čas se nepočítají.
CREATE TABLE login_unlock (
    subject     text PRIMARY KEY,                       -- 'user:jnovak' / 'ip:10.0.0.5'
    unlocked_at timestamptz NOT NULL DEFAULT now(),
    unlocked_by text NOT NULL
);

CREATE TABLE settings (
    name        text PRIMARY KEY,
    value       text NOT NULL,                          -- tajné hodnoty šifrované (libsodium)
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text
);

-- Auditní záznam s ochranou integrity (NIS2): každý řádek nese SHA-256 z obsahu
-- a hashe předchozího řádku (hash chain). Řetěz počítá DB trigger, ne aplikace;
-- UPDATE/DELETE/TRUNCATE jsou zakázané triggerem. Hlavu řetězu (seq + hash)
-- pravidelně odesílá `bin/mailpanel audit:anchor` do syslogu → centrální log/SIEM,
-- takže ani správce DB nemůže historii nepozorovaně přepsat.
CREATE TABLE audit_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    seq         bigint NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL,
    username    text,
    ip          inet,
    action      text NOT NULL,                          -- 'auth.login', 'queue.delete', 'log.search' …
    result      text NOT NULL DEFAULT 'ok' CHECK (result IN ('ok', 'fail', 'denied')),
    details     jsonb NOT NULL DEFAULT '{}',
    prev_hash   text NOT NULL,
    hash        text NOT NULL
);
CREATE INDEX audit_log_time_idx   ON audit_log (created_at);
CREATE INDEX audit_log_action_idx ON audit_log (action, created_at);
CREATE INDEX audit_log_user_idx   ON audit_log (username, created_at);

CREATE FUNCTION audit_log_payload(p_seq bigint, p_created timestamptz, p_username text, p_ip inet,
                                  p_action text, p_result text, p_details jsonb, p_prev text)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT concat_ws('|', p_prev, p_seq::text,
                     to_char(p_created AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                     coalesce(p_username, ''), coalesce(host(p_ip), ''),
                     p_action, p_result, p_details::text)
$$;

CREATE FUNCTION audit_log_chain() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    last record;
BEGIN
    -- serializace zápisů: pořadí v řetězu = pořadí commitů
    PERFORM pg_advisory_xact_lock(7243501);
    SELECT seq, hash INTO last FROM audit_log ORDER BY seq DESC LIMIT 1;
    NEW.seq        := coalesce(last.seq, 0) + 1;
    NEW.prev_hash  := coalesce(last.hash, repeat('0', 64));
    NEW.created_at := clock_timestamp();
    NEW.hash := encode(sha256(convert_to(audit_log_payload(NEW.seq, NEW.created_at, NEW.username, NEW.ip,
                                                           NEW.action, NEW.result, NEW.details,
                                                           NEW.prev_hash), 'UTF8')), 'hex');
    RETURN NEW;
END $$;
CREATE TRIGGER audit_log_chain BEFORE INSERT ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_chain();

CREATE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log je jen pro zápis (operace % zakázána)', TG_OP;
END $$;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

-- Ověření řetězu: vrací první porušený řádek (nebo nic, když je vše v pořádku).
CREATE FUNCTION audit_log_verify()
RETURNS TABLE (seq bigint, problem text) LANGUAGE plpgsql STABLE AS $$
DECLARE
    r        record;
    expected text;
    prev     text := NULL;
    prev_seq bigint := NULL;
BEGIN
    FOR r IN SELECT * FROM audit_log a ORDER BY a.seq LOOP
        IF prev IS NOT NULL AND r.prev_hash <> prev THEN
            seq := r.seq; problem := 'prev_hash nenavazuje na předchozí záznam'; RETURN NEXT; RETURN;
        END IF;
        IF prev_seq IS NOT NULL AND r.seq <> prev_seq + 1 THEN
            seq := r.seq; problem := format('chybí záznamy %s–%s', prev_seq + 1, r.seq - 1); RETURN NEXT; RETURN;
        END IF;
        expected := encode(sha256(convert_to(audit_log_payload(r.seq, r.created_at, r.username, r.ip,
                                                               r.action, r.result, r.details, r.prev_hash),
                                             'UTF8')), 'hex');
        IF expected <> r.hash THEN
            seq := r.seq; problem := 'obsah záznamu neodpovídá hashi (změněno)'; RETURN NEXT; RETURN;
        END IF;
        prev := r.hash;
        prev_seq := r.seq;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- 2. Sběr logů
-- ---------------------------------------------------------------------

-- Pozice čtení každého zdrojového souboru. Ukládá se ve STEJNÉ transakci
-- jako vložené řádky => po restartu ani rotaci se nic neztratí a nic se
-- nezdvojí.
CREATE TABLE collector_state (
    source      text PRIMARY KEY,                      -- '/var/log/mail.log'
    inode       bigint NOT NULL,
    "offset"    bigint NOT NULL,
    line_ts     timestamptz,                           -- čas posledního zpracovaného řádku
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Surové řádky (fulltext + kontext pro trasování). Měsíční partitions,
-- retence = DROP staré partition (okamžité, bez VACUUM).
CREATE TABLE log_line (
    id        bigint GENERATED ALWAYS AS IDENTITY,
    ts        timestamptz NOT NULL,
    host      text NOT NULL,
    program   text NOT NULL,                           -- 'postfix/smtpd', 'dovecot', 'amavis', 'iredapd'
    pid       int,
    queue_id  text,                                    -- vytažené Postfix Queue-ID, pokud je
    severity  smallint NOT NULL DEFAULT 6,             -- syslog: 3 error, 4 warning, 5 notice, 6 info
    message   text NOT NULL,
    PRIMARY KEY (ts, id)
) PARTITION BY RANGE (ts);
CREATE INDEX log_line_ts_brin   ON log_line USING brin (ts);
CREATE INDEX log_line_qid_idx   ON log_line (queue_id) WHERE queue_id IS NOT NULL;
CREATE INDEX log_line_prog_idx  ON log_line (program, ts);
CREATE INDEX log_line_msg_trgm  ON log_line USING gin (message gin_trgm_ops);

-- Jedna zpráva = jedna instance ve frontě Postfixu (jedno Queue-ID).
-- Průchod přes Amavis vytvoří DRUHOU instanci (nové Queue-ID), propojenou
-- přes parent_id => celá cesta zprávy se dá složit.
CREATE TABLE mail_message (
    id             bigint GENERATED ALWAYS AS IDENTITY,
    first_seen     timestamptz NOT NULL,
    last_seen      timestamptz NOT NULL,
    host           text NOT NULL,
    queue_id       text NOT NULL,
    parent_id      bigint,                             -- mail_message.id instance před Amavisem
    message_id     text,                               -- hlavička Message-ID
    sender         text,                               -- lower(), '' = bounce (<>)
    sasl_username  text,                               -- odesláno přihlášeným uživatelem
    client_host    text,
    client_ip      inet,
    size           bigint,
    nrcpt          int,
    direction      text NOT NULL DEFAULT 'unknown'
                   CHECK (direction IN ('in', 'out', 'internal', 'local', 'unknown')),
    status         text NOT NULL DEFAULT 'open'
                   CHECK (status IN ('open', 'sent', 'deferred', 'bounced', 'expired',
                                     'deleted', 'held', 'discarded', 'partial')),
    amavis_result  text,                               -- CLEAN, SPAM, SPAMMY, INFECTED, BANNED, BAD-HEADER
    amavis_mail_id text,                               -- vazba na amavisd.msgs.mail_id (karanténa)
    spam_score     numeric(7,3),
    subject        text,                               -- jen pokud se loguje (header_checks WARN) – viz GDPR
    PRIMARY KEY (first_seen, id)
) PARTITION BY RANGE (first_seen);
CREATE INDEX mail_message_qid_idx    ON mail_message (queue_id);
CREATE INDEX mail_message_msgid_idx  ON mail_message (message_id);
CREATE INDEX mail_message_sender_idx ON mail_message (sender text_pattern_ops, first_seen);
CREATE INDEX mail_message_sasl_idx   ON mail_message (sasl_username, first_seen) WHERE sasl_username IS NOT NULL;
CREATE INDEX mail_message_ip_idx     ON mail_message (client_ip, first_seen);
CREATE INDEX mail_message_parent_idx ON mail_message (parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX mail_message_status_idx ON mail_message (status, first_seen) WHERE status <> 'sent';

-- Pokus o doručení konkrétnímu příjemci (smtp/lmtp/local/virtual/error).
-- Jeden příjemce může mít víc řádků (deferred, deferred, sent).
CREATE TABLE mail_delivery (
    id             bigint GENERATED ALWAYS AS IDENTITY,
    ts             timestamptz NOT NULL,
    message_ref    bigint NOT NULL,                    -- mail_message.id
    recipient      text NOT NULL,                      -- lower()
    orig_recipient text,
    transport      text,                               -- smtp, lmtp, relay, smtp-amavis, error …
    relay          text,                               -- 'mx.example.com[1.2.3.4]:25'
    delay          numeric(10,2),
    delays         text,                               -- 'a/b/c/d'
    dsn            text,                               -- '2.0.0', '4.7.1', '5.1.1'
    status         text NOT NULL CHECK (status IN ('sent', 'deferred', 'bounced', 'expired', 'undeliverable')),
    response       text,
    PRIMARY KEY (ts, id)
) PARTITION BY RANGE (ts);
CREATE INDEX mail_delivery_msg_idx  ON mail_delivery (message_ref);
CREATE INDEX mail_delivery_rcpt_idx ON mail_delivery (recipient text_pattern_ops, ts);
CREATE INDEX mail_delivery_stat_idx ON mail_delivery (status, ts) WHERE status <> 'sent';
CREATE INDEX mail_delivery_dom_idx  ON mail_delivery ((split_part(recipient, '@', 2)), ts);

-- Odmítnutí před přijetím do fronty (NOQUEUE: reject, postscreen, iredapd).
CREATE TABLE mail_reject (
    id          bigint GENERATED ALWAYS AS IDENTITY,
    ts          timestamptz NOT NULL,
    host        text NOT NULL,
    stage       text NOT NULL,                         -- postscreen, smtpd, iredapd
    client_host text,
    client_ip   inet,
    helo        text,
    sender      text,
    recipient   text,
    code        text,                                  -- '554 5.7.1'
    category    text NOT NULL DEFAULT 'other',         -- rbl, unknown_user, greylist, spf, helo, relay,
                                                       -- throttle, blacklist, tls, pregreet, other
    reason      text,
    PRIMARY KEY (ts, id)
) PARTITION BY RANGE (ts);
CREATE INDEX mail_reject_ip_idx  ON mail_reject (client_ip, ts);
CREATE INDEX mail_reject_cat_idx ON mail_reject (category, ts);

-- Přihlášení (IMAP, POP3, SMTP SASL, ManageSieve) – úspěšná i neúspěšná.
CREATE TABLE auth_event (
    id        bigint GENERATED ALWAYS AS IDENTITY,
    ts        timestamptz NOT NULL,
    service   text NOT NULL,                           -- imap, pop3, smtp, sieve
    username  text,
    ip        inet,
    success   boolean NOT NULL,
    reason    text,
    PRIMARY KEY (ts, id)
) PARTITION BY RANGE (ts);
CREATE INDEX auth_event_user_idx ON auth_event (username, ts);
CREATE INDEX auth_event_ip_idx   ON auth_event (ip, ts) WHERE NOT success;

-- Rozpracované zprávy pro korelaci napříč restartem collectoru
-- (malá tabulka, běžně stovky řádků; po 'removed' se maže).
CREATE TABLE mail_open (
    host        text NOT NULL,
    queue_id    text NOT NULL,
    message_ref bigint NOT NULL,
    first_seen  timestamptz NOT NULL,
    PRIMARY KEY (host, queue_id)
);

-- ---------------------------------------------------------------------
-- 3. Statistiky a vzorky
-- ---------------------------------------------------------------------

-- Hodinové agregáty plněné INKREMENTÁLNĚ collectorem (UPSERT value = value + n).
-- Žádný REFRESH MATERIALIZED VIEW nad miliony řádků; drží se natrvalo,
-- i když se surová data po retenci smažou.
--   metric: msg_in, msg_out, msg_internal, rcpt_sent, rcpt_deferred, rcpt_bounced,
--           reject, spam, virus, banned, auth_ok, auth_fail, bytes_in, bytes_out
--   dim:    '' (celkem) | doména | kategorie odmítnutí | služba …
CREATE TABLE stats_hourly (
    bucket  timestamptz NOT NULL,                      -- date_trunc('hour', ts)
    metric  text NOT NULL,
    dim     text NOT NULL DEFAULT '',
    value   bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, metric, dim)
);
CREATE INDEX stats_hourly_metric_idx ON stats_hourly (metric, bucket);

-- Vzorek fronty každou minutu (z `postqueue -j`) – graf fronty v čase.
CREATE TABLE queue_sample (
    ts            timestamptz PRIMARY KEY,
    incoming      int NOT NULL DEFAULT 0,
    active        int NOT NULL DEFAULT 0,
    deferred      int NOT NULL DEFAULT 0,
    hold          int NOT NULL DEFAULT 0,
    corrupt       int NOT NULL DEFAULT 0,
    total_bytes   bigint NOT NULL DEFAULT 0,
    oldest_age_s  int,
    top_reasons   jsonb NOT NULL DEFAULT '[]',         -- [{reason, count}] top 10
    top_domains   jsonb NOT NULL DEFAULT '[]'          -- [{domain, count}] top 10
);

-- Stav služeb a systému (systemctl is-active, disk, certifikát, RBL).
CREATE TABLE health_check (
    name        text PRIMARY KEY,                      -- 'svc.postfix', 'disk./var/vmail', 'rbl.zen', 'cert.smtp'
    status      text NOT NULL CHECK (status IN ('ok', 'warning', 'critical', 'unknown')),
    value       text,
    message     text,
    changed_at  timestamptz NOT NULL DEFAULT now(),
    checked_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- 4. Schránky (synchronizace z vmail.used_quota, vmail.last_login, AD)
-- ---------------------------------------------------------------------

CREATE TABLE mailbox_stats (
    username        text PRIMARY KEY,                  -- e-mailová adresa
    domain          text NOT NULL,
    name            text,
    is_active       boolean NOT NULL DEFAULT true,     -- stav v iRedMailu
    bytes_used      bigint NOT NULL DEFAULT 0,
    messages_count  int    NOT NULL DEFAULT 0,
    quota_bytes     bigint NOT NULL DEFAULT 0,         -- 0 = neomezeno
    last_login_imap timestamptz,
    last_login_pop3 timestamptz,
    last_login_smtp timestamptz,                       -- z auth_event (SASL)
    last_delivery   timestamptz,                       -- poslední doručení do schránky (LDA/LMTP)
    ad_dn           text,
    ad_status       text NOT NULL DEFAULT 'unknown'
                    CHECK (ad_status IN ('enabled', 'disabled', 'expired', 'locked', 'missing', 'unknown')),
    ad_checked_at   timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mailbox_stats_domain_idx ON mailbox_stats (domain);

-- Denní historie velikosti (graf růstu schránek / domén).
CREATE TABLE mailbox_size_daily (
    day        date   NOT NULL,
    username   text   NOT NULL,
    bytes_used bigint NOT NULL,
    messages   int    NOT NULL,
    PRIMARY KEY (day, username)
);

-- Opuštěné schránky – prahy se předávají parametrem (nastavení v portálu).
CREATE FUNCTION abandoned_mailboxes(p_days int DEFAULT 90, p_min_bytes bigint DEFAULT 104857600)
RETURNS TABLE (
    username       text,
    domain         text,
    size_mb        numeric,
    messages_count int,
    last_login     timestamptz,
    days_inactive  int,
    ad_status      text,
    reason         text
) LANGUAGE sql STABLE AS $$
    SELECT m.username,
           m.domain,
           round(m.bytes_used / 1048576.0, 1),
           m.messages_count,
           l.last_login,
           CASE WHEN l.last_login IS NULL THEN NULL
                ELSE (current_date - l.last_login::date) END,
           m.ad_status,
           concat_ws(', ',
               CASE WHEN m.ad_status IN ('disabled', 'expired', 'missing') THEN 'AD: ' || m.ad_status END,
               CASE WHEN l.last_login IS NULL THEN 'nikdy přihlášen'
                    WHEN l.last_login < now() - make_interval(days => p_days)
                    THEN 'nepřihlášen ' || (current_date - l.last_login::date) || ' dní' END,
               CASE WHEN NOT m.is_active THEN 'v iRedMailu zakázána' END)
      FROM mailbox_stats m
      CROSS JOIN LATERAL (
          SELECT nullif(greatest(coalesce(m.last_login_imap, '-infinity'),
                                 coalesce(m.last_login_pop3, '-infinity'),
                                 coalesce(m.last_login_smtp, '-infinity')), '-infinity') AS last_login
      ) l
     WHERE m.bytes_used >= p_min_bytes
       AND (   m.ad_status IN ('disabled', 'expired', 'missing')
            OR NOT m.is_active
            OR l.last_login IS NULL
            OR l.last_login < now() - make_interval(days => p_days))
     ORDER BY m.bytes_used DESC
$$;

-- ---------------------------------------------------------------------
-- 5. Úkoly pro agenta (akce s právy roota)
-- ---------------------------------------------------------------------

CREATE TABLE agent_task (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action        text NOT NULL CHECK (action IN (
                      'queue.delete', 'queue.hold', 'queue.release', 'queue.requeue',
                      'queue.flush', 'queue.show',
                      'quarantine.release',
                      'mailbox.quota_recalc', 'mailbox.kick',
                      'service.status')),
    args          jsonb NOT NULL DEFAULT '{}',        -- {"queue_ids": ["4Xb…", …]} – agent validuje ZNOVU
    status        text NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'running', 'done', 'failed', 'rejected')),
    requested_by  text NOT NULL,
    requested_ip  inet,
    result        jsonb,
    created_at    timestamptz NOT NULL DEFAULT now(),
    started_at    timestamptz,
    finished_at   timestamptz
);
CREATE INDEX agent_task_pending_idx ON agent_task (created_at) WHERE status = 'pending';

-- Probudí agenta okamžitě (LISTEN agent_task); polling po 5 s jako záloha.
CREATE FUNCTION agent_task_notify() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('agent_task', NEW.id::text);
    RETURN NEW;
END $$;
CREATE TRIGGER agent_task_notify AFTER INSERT ON agent_task
    FOR EACH ROW EXECUTE FUNCTION agent_task_notify();

-- ---------------------------------------------------------------------
-- 6. Upozornění (webhook, e-mail)
-- ---------------------------------------------------------------------

CREATE TABLE alert_state (
    key            text PRIMARY KEY,                   -- 'queue.deferred', 'svc.amavis', 'rbl.zen', 'abuse:user@dom'
    status         text NOT NULL CHECK (status IN ('ok', 'warning', 'critical')),
    message        text NOT NULL,
    since          timestamptz NOT NULL DEFAULT now(),
    notified_at    timestamptz,
    acknowledged_by text,
    acknowledged_at timestamptz
);

-- ---------------------------------------------------------------------
-- 7. Partitions: vytvoření dopředu, retence
-- ---------------------------------------------------------------------

-- Vytvoří měsíční partitions od aktuálního měsíce na p_ahead měsíců dopředu.
-- Volá collector při startu a denně timer.
CREATE FUNCTION ensure_partitions(p_ahead int DEFAULT 2) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    t     text;
    m     date;
    name  text;
BEGIN
    FOREACH t IN ARRAY ARRAY['log_line', 'mail_message', 'mail_delivery', 'mail_reject', 'auth_event'] LOOP
        FOR i IN 0..p_ahead LOOP
            m := (date_trunc('month', current_date) + make_interval(months => i))::date;
            name := format('%s_%s', t, to_char(m, 'YYYYMM'));
            IF to_regclass(name) IS NULL THEN
                EXECUTE format('CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                               name, t, m, (m + interval '1 month')::date);
            END IF;
        END LOOP;
    END LOOP;
END $$;

-- Smaže partitions starší než p_months měsíců (celý měsíc najednou).
CREATE FUNCTION drop_old_partitions(p_table text, p_months int) RETURNS int LANGUAGE plpgsql AS $$
DECLARE
    r       record;
    cutoff  text := to_char(date_trunc('month', current_date) - make_interval(months => p_months), 'YYYYMM');
    n       int := 0;
BEGIN
    FOR r IN SELECT c.relname
               FROM pg_inherits i
               JOIN pg_class c ON c.oid = i.inhrelid
               JOIN pg_class p ON p.oid = i.inhparent
              WHERE p.relname = p_table
                AND right(c.relname, 6) ~ '^\d{6}$'
                AND right(c.relname, 6) < cutoff LOOP
        EXECUTE format('DROP TABLE %I', r.relname);
        n := n + 1;
    END LOOP;
    RETURN n;
END $$;

SELECT ensure_partitions(2);

-- ---------------------------------------------------------------------
-- 8. Práva
-- ---------------------------------------------------------------------
-- Role vytváří instalace (docs/INSTALACE.md). Migrace běží jako vlastník
-- (mailpanel_owner); GRANTy se nastaví jen rolím, které existují.
-- Logové tabulky jsou pro collector jen INSERT (+ SELECT): co jednou zapíše,
-- už nezmění ani nesmaže. Retenci (DROP partition) dělá jen vlastník.

ALTER FUNCTION ensure_partitions(int) SECURITY DEFINER;
REVOKE ALL ON FUNCTION ensure_partitions(int) FROM PUBLIC;
REVOKE ALL ON FUNCTION drop_old_partitions(text, int) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mailpanel_web') THEN
        GRANT USAGE ON SCHEMA public TO mailpanel_web;
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO mailpanel_web;
        GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO mailpanel_web;
        GRANT INSERT, UPDATE ON users TO mailpanel_web;
        GRANT INSERT, DELETE ON login_attempts TO mailpanel_web;
        GRANT INSERT, UPDATE, DELETE ON login_unlock, settings TO mailpanel_web;
        GRANT INSERT ON audit_log TO mailpanel_web;
        GRANT INSERT (action, args, requested_by, requested_ip) ON agent_task TO mailpanel_web;
        GRANT UPDATE (acknowledged_by, acknowledged_at) ON alert_state TO mailpanel_web;
        GRANT EXECUTE ON FUNCTION audit_log_verify() TO mailpanel_web;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mailpanel_collector') THEN
        GRANT USAGE ON SCHEMA public TO mailpanel_collector;
        GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO mailpanel_collector;
        GRANT SELECT, INSERT ON log_line, mail_reject, auth_event, audit_log TO mailpanel_collector;
        GRANT SELECT, INSERT, UPDATE ON mail_message, mail_delivery TO mailpanel_collector;
        GRANT SELECT, INSERT, UPDATE, DELETE ON collector_state, mail_open, stats_hourly, queue_sample,
              health_check, mailbox_stats, mailbox_size_daily, alert_state TO mailpanel_collector;
        GRANT SELECT ON settings, users TO mailpanel_collector;
        GRANT EXECUTE ON FUNCTION ensure_partitions(int) TO mailpanel_collector;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mailpanel_agent') THEN
        GRANT USAGE ON SCHEMA public TO mailpanel_agent;
        GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO mailpanel_agent;
        GRANT SELECT ON agent_task, settings TO mailpanel_agent;
        GRANT UPDATE (status, result, started_at, finished_at) ON agent_task TO mailpanel_agent;
        GRANT SELECT, INSERT ON audit_log TO mailpanel_agent;
    END IF;
END $$;
