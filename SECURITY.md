# Bezpečnost

## Hlášení zranitelností

Zranitelnosti prosím **nehlaste veřejným issue**. Použijte soukromé hlášení na GitHubu:
záložka **Security → Report a vulnerability** v tomto repozitáři.

Uveďte popis, dotčenou verzi (commit), kroky k reprodukci a dopad. Odpovíme do 7 dnů.

## Podporované verze

Opravy se vydávají pro poslední verzi ve větvi `main`.

## Bezpečnostní zásady projektu

- žádné runtime závislosti stažené za běhu; knihovny třetích stran jsou ve `public/assets/vendor/`
  s uvedenou verzí a licencí,
- SQL jen parametrizované, výstup do HTML jen přes `View::e()`, CSP bez inline skriptů,
- každá akce měnící stav vyžaduje POST s CSRF tokenem a oprávnění role,
- citlivé hodnoty v DB šifrované, klíč jen v konfiguraci mimo git,
- auditní záznam je jen pro zápis a chráněný hash chainem.

Podrobněji: [docs/NIS2.md](docs/NIS2.md).
