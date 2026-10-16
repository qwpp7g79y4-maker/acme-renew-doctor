# Kwaliteitsrapport

Deze pagina laat zien hoe acme-renew-doctor is gecontroleerd vóór de eerste openbare release, en wat er is opgelost. Ze beschrijft de controles die we deden. Het is geen garantie dat de software vrij is van fouten of veilig is.

## main na v0.1.0

| | |
|---|---|
| Gecontroleerde commit | [`bfb99d7`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/bfb99d7) |
| Datum | 2026-10-16 |
| Tests | 339 geautomatiseerde tests |

- Een externe review van de code. De bevestigde bevindingen zijn opgelost, elk met een regressietest.
- Een verse onafhankelijke eindreview van commit `1a5c3a6`, tegen dezelfde vaste edge-case-checklist en de negen vragen, elk punt geprobeerd met een concrete kwade invoer. Die eindigde met AF, zonder blokkerende bevindingen. Daarvoor vond een verse eindreview van de vorige commit één blokkerend probleem: `--json` schreef DEL, C1-stuurtekens en bidirectionele stuurtekens rauw. Dat is opgelost in `1a5c3a6`, met regressietests.
- Die eindreview meldde drie niet-blokkerende punten. Die zijn aangepakt in de commit erna: release-archieven bevatten nu dit rapport, de README noemt de ondersteunde systemen (glibc 2.34, macOS 10.12/11.0, Windows 10), CI controleert het hoogste glibc-symbool van de Linux-gnu-binary, en CI draait de tests ook in releasemodus. Die commit veranderde alleen de workflows, de documentatie en een controlescript, niet de code van de tool. Een verse onafhankelijke eindreview van die commit, [`4ded184`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/4ded184), tegen dezelfde checklist eindigde met AF, zonder blokkerende bevindingen en met twee niet-blokkerende punten: een domeinlabel van meer dan 63 tekens wordt geaccepteerd en komt in een voorgesteld `dig`- of `curl`-commando terecht (onschuldig, maar geen geldige DNS-naam), en een changelogregel noemde alleen Linux voor het fifo-gedrag, dat voor alle Unix-systemen geldt. De changelogregel is opgelost; de labellengte is opgelost in de commit hieronder.
- Commit [`bfb99d7`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/bfb99d7) wijst een domeinlabel van meer dan 63 bytes af, het bekende niet-blokkerende punt hierboven. Hij voegt ook property tests toe en vijf cargo-fuzz-targets (`safe_domain`, `certbot_log`, `timer_show`, `cert_enddate`, `report_render`), die elk een invariant controleren, niet alleen dat de code draait zonder te paniceren. Elk target draaide 661 seconden op één CPU-kern op een Linux-x86_64-machine: `safe_domain` 31.498.662 runs, `certbot_log` 5.466.535 runs, `timer_show` 19.829.332 runs, `cert_enddate` 48.356.095 runs, `report_render` 630.726 runs. Die run vond geen crash en geen invariant die faalde. Eén assertie in de fuzz-harness was strenger dan de twee controles die ze vergeleek werkelijk garanderen; die is versoepeld tijdens eerdere smoke runs, en daarvoor is geen code van de tool zelf veranderd. Een verse onafhankelijke eindreview van `bfb99d7`, tegen dezelfde checklist, eindigde met AF, zonder blokkerende bevindingen en met twee niet-blokkerende punten: de referentiepagina's noemden de limiet van 63 tekens per label en de nieuwe ongeldige-hostnaam-melding niet, en de melding bij een domein met `*` was niet gedocumenteerd als bewuste keuze. Beide zijn aangepakt in de commit die erop volgt. CI bouwt de fuzz-targets op Linux nightly zodat ze blijven compileren; CI draait ze niet.

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
- Een verse onafhankelijke eindreview van commit [`8156ad9`](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/commit/8156ad9) (dezelfde code als de gecontroleerde commit hierboven; alleen dit rapport is gewijzigd) tegen een vaste edge-case-checklist, elk punt met een concrete kwade invoer. Die eindigde op DONE, zonder blokkerende bevindingen.

We noemen de reviewdiensten hier niet. Het gaat om de controles en hun resultaten, en elk resultaat is na te gaan in de code, de tests en de changelog.

### Niet gedekt

- Alleen Certbot wordt ondersteund. Andere ACME-clients worden gemeld als onbekende client.
- De tool leest bestanden die je zelf hebt opgeslagen. Hij controleert geen live server, DNS of ACME-account.
