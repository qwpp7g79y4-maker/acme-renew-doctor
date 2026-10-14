# Kwaliteitsrapport

Deze pagina laat zien hoe acme-renew-doctor is gecontroleerd vóór de eerste openbare release, en wat er is opgelost. Ze beschrijft de controles die we deden. Het is geen garantie dat de software vrij is van fouten of veilig is.

## v0.1.0

| | |
|---|---|
| Versie | 0.1.0 ([release](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/releases/tag/v0.1.0), [crates.io](https://crates.io/crates/acme-renew-doctor/0.1.0)) |
| Gecontroleerde commit | [`4b64288`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/4b64288) |
| Datum | 2026-10-14 |
| Tests | 317 geautomatiseerde tests, gedraaid in debug- en releasemodus |

### Wat we controleerden

**Codereview.** De code is gelezen aan de hand van negen vaste vragen:
1. Geeft het het juiste antwoord?
2. Wat gebeurt er bij foute of ontbrekende invoer?
3. Wat gebeurt er als het halverwege misgaat, bijvoorbeeld als de uitvoer niet geschreven kan worden?
4. Welke aannames doet het, en staan die beschreven?
5. Is het veilig als dingen tegelijk gebeuren?
6. Kan onbetrouwbare invoer in de uitvoer lekken of schade doen, bijvoorbeeld via verborgen tekens?
7. Blijft het snel en klein bij grote invoer?
8. Is elke bewering gedekt door een test?
9. Is de code goed te lezen en aan te passen?

**Invoer van elk platform.** UTF-8 met en zonder byte order mark, UTF-16 en UTF-32, Windows-regeleinden (CRLF), Windows-paden, en bestandspaden die geen geldige UTF-8 zijn.

**Tests op elk platform.** Elke wijziging draait de volledige testsuite op Linux, Windows, macOS op Apple Silicon en macOS op Intel, plus de oudste ondersteunde Rust-versie (1.85).

**Release.** De release wordt pas gebouwd nadat de tests opnieuw slagen op de getagde commit. Elk archief krijgt een SHA-256-checksum.

**Afhankelijkheden.** De enige runtime-afhankelijkheid is clap. `cargo audit` draait bij elke wijziging in CI.

### Hoe we controleerden

- Onafhankelijke codereview, door reviewers die de code niet schreven.
- Een externe geautomatiseerde codereview. Alle bevestigde bevindingen zijn in deze versie opgelost, elk met een regressietest.
- Geautomatiseerde tests in CI: [run 38541717053](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/actions/runs/38541717053).
- Afhankelijkheden gecontroleerd met `cargo audit`.

We noemen de reviewdiensten hier niet. Het gaat om de controles en hun resultaten, en elk resultaat is na te gaan in de code, de tests en de changelog.

### Niet gedekt

- Alleen Certbot wordt ondersteund. Andere ACME-clients worden gemeld als onbekende client.
- De tool leest bestanden die je zelf hebt opgeslagen. Hij controleert geen live server, DNS of ACME-account.
