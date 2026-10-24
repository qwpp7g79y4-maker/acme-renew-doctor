# acme-renew-doctor

[English](README.md) · Nederlands

Leg uit waarom een Certbot-vernieuwing faalde, of stilletjes nooit draaide, aan de hand van bestanden die je meegeeft.

[![crates.io](https://img.shields.io/crates/v/acme-renew-doctor.svg)](https://crates.io/crates/acme-renew-doctor) [![downloads](https://img.shields.io/crates/d/acme-renew-doctor.svg)](https://crates.io/crates/acme-renew-doctor) [![CI](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/actions/workflows/ci.yml) [![PEPAI gecontroleerd](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fqwpp7g79y4-maker%2Facme-renew-doctor%2Fmain%2F.github%2Fbadge.json)](QUALITY.nl.md) [![MSRV 1.85](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/blob/main/Cargo.toml) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#licentie)

[Installatie](#installatie) • [Snel aan de slag](#snel-aan-de-slag) • [Hoe het werkt](#hoe-het-werkt) • [Alternatieven](#vergelijking-met-alternatieven) • [Beperkingen](#beperkingen) • [Referentie](docs/reference.nl.md)

acme-renew-doctor is een lokaal, alleen-lezen opdrachtregelprogramma in Rust. Het legt uit waarom een Certbot-TLS-vernieuwing faalde, of stilletjes nooit draaide. Het verzamelt niets. Het leest alleen bestanden die je meegeeft: opgeslagen opdrachtuitvoer, of tekst die je in een bestand plakte. Het voert geen opdracht uit, forceert nooit een vernieuwing en herlaadt nooit een service. Het enige bestand dat het schrijft is `example-log.txt` in de huidige map, en alleen als je `--example` meegeeft.  Een bevinding is een vaste code plus het bewijs daarvoor. Codes die een laag noemen gebruiken scheduler, validation of deployment. Het heeft geen account nodig en maakt geen netwerkverbinding.

**Waarschuwing:** het rapport citeert de bestanden die je meegeeft woordelijk terug; het redigeert niet. Verwijder tokens, wachtwoorden en API-sleutels uit een log of andere opgeslagen opdrachtuitvoer voordat je die meegeeft, zeker voordat je het rapport doorstuurt. Zie [Privacy](#privacy).

De uitvoer van de tool is Engels; de voorbeelden hieronder tonen die precies zoals de binary hem schrijft.

## Waarom

Let's Encrypt stopte op 4 juni 2025 met e-mails over verlopende certificaten (https://letsencrypt.org/2025/06/26/expiration-notification-service-has-ended.html). Sindsdien valt een vernieuwing die mislukt, of een timer die stil stopt, makkelijk pas op als het certificaat verloopt. De oorzaak zit in een van drie lagen: de planner, de ACME-validatie of de uitrol. acme-renew-doctor leest het bewijs dat je hebt opgeslagen en noemt die laag, met de regel die het aantoont.

## Installatie

### Vanaf crates.io

Met Rust 1.85 of nieuwer installeer je vanaf [crates.io](https://crates.io/crates/acme-renew-doctor):

```sh
cargo install --locked acme-renew-doctor
acme-renew-doctor --help
```

### Binary-archief

De [release v0.1.0](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/releases/tag/v0.1.0) heeft archieven voor Linux x86_64 (`x86_64-unknown-linux-gnu` en `x86_64-unknown-linux-musl`), macOS (`x86_64-apple-darwin` en `aarch64-apple-darwin`) en Windows (`x86_64-pc-windows-msvc`, een `.zip`), elk met een `.sha256`-checksumbestand. Een archief bevat de binary, de documentatie en de voorbeeldbestanden. Het heeft geen `Cargo.toml`, dus `cargo install --path .` werkt niet in het archief. Download het archief en de checksum, controleer de sha256-checksum, pak het uit, en zet de binary op je `PATH`. Voor Linux x86_64:

```sh
name=acme-renew-doctor-v0.1.0-x86_64-unknown-linux-gnu
base=https://github.com/qwpp7g79y4-maker/acme-renew-doctor/releases/download/v0.1.0
curl -q -fsSL -O "$base/$name.tar.gz" -O "$base/$name.tar.gz.sha256"
sha256sum -c "$name.tar.gz.sha256"
tar -xzf "$name.tar.gz"
install -m 755 "$name/acme-renew-doctor" "$HOME/.local/bin/"
```

`$HOME/.local/bin` moet op je `PATH` staan. Controleer de checksum op macOS met `shasum -a 256 -c` in plaats van `sha256sum -c`.

### Vanuit de bron

Je hebt Rust 1.85 of nieuwer nodig. In een clone van deze repository:

```sh
cargo install --locked --path .
acme-renew-doctor --help
```

`cargo install --path .` heeft de `Cargo.toml` van de broncode nodig. Of bouw met `cargo build --release`; de binary staat dan in `target/release/acme-renew-doctor`.

### Ondersteunde systemen

- Linux x86_64 (`x86_64-unknown-linux-gnu`): glibc 2.34 of nieuwer. CI controleert bij elke wijziging en voor elke release het hoogste glibc-symbool dat de binary nodig heeft. Gebruik voor een oudere distributie of Alpine het statisch gelinkte archief `x86_64-unknown-linux-musl`; dat heeft geen glibc nodig.
- macOS: 10.12 of nieuwer op Intel, 11.0 of nieuwer op Apple Silicon.
- Windows: Windows 10 of nieuwer, x86_64.

## Snel aan de slag

Dit is de echte uitvoer van de binary op de synthetische fixtures in `tests/fixtures`. Een test draait elk voorbeeld en vergelijkt de uitvoer. Elk `--from-*`-bestand maak je zelf. De tool voert de opdrachten die hij afdrukt niet uit.

Geen kloon van deze repository? `acme-renew-doctor --example` schrijft een synthetische Certbot-log naar `example-log.txt` in de huidige map (en weigert een ongerelateerd bestand met die naam te overschrijven) en stopt met exit 0. Om dezelfde `LAYER2_HTTP01_TIMEOUT` te zien zonder kloon, draai `acme-renew-doctor example.com --from-log example-log.txt`. Laat `--from-timer-status` weg; die fixture zit alleen in een kloon.

Zonder bestanden vraagt het rapport erom en eindigt het met exit 2:

```console
$ acme-renew-doctor example.com
acme-renew-doctor 0.1.0 (read-only, nothing was changed)
target: example.com · client: auto
inputs: log=(none) · timer status=(none) · cert disk=(none) · cert live=(none)

? INSUFFICIENT_EVIDENCE  confidence=low  layer=-
  evidence:
  • [timer] no timer status
  • [log] no log given
  • [disk] no disk notAfter
  • [handshake] no live notAfter

Next (SAFE copy-paste checks, read-only; Doctor runs nothing and will NOT renew or reload for you):
  → systemctl show certbot.timer certbot.service -p Id,LoadState,ActiveState,SubState,UnitFileState,Result,ConditionResult,LastTriggerUSec,NextElapseUSecRealtime
    why: save this output yourself and pass the file with --from-timer-status
  → sudo tail -n 400 /var/log/letsencrypt/letsencrypt.log
    why: save a copy yourself and pass it with --from-log
  → sudo openssl x509 -noout -dates -in /etc/letsencrypt/live/example.com/fullchain.pem
    why: save this output yourself and pass the file with --from-cert-disk
  → echo | timeout 10 openssl s_client -connect example.com:443 -servername example.com | openssl x509 -noout -dates
    why: save this output yourself and pass the file with --from-cert-live
  ⚠ Do not force a renewal: Let's Encrypt rate limits apply. Fix the named layer first.
    (dangerous suggestions suppressed by default)

note: live collection is not built yet; pass --from-log, --from-timer-status, --from-cert-disk and/or --from-cert-live.

exit 2: insufficient evidence
```

Een opgeslagen Certbot-log en een opgeslagen timerstatus, allebei synthetisch:

```console
$ acme-renew-doctor example.com --from-log tests/fixtures/certbot/http01-timeout-repeated.log --from-timer-status tests/fixtures/timer/certbot-timer-disabled.txt
acme-renew-doctor 0.1.0 (read-only, nothing was changed)
target: example.com · client: auto
inputs: log=tests/fixtures/certbot/http01-timeout-repeated.log · timer status=tests/fixtures/timer/certbot-timer-disabled.txt · cert disk=(none) · cert live=(none)

✗ LAYER1_TIMER_DISABLED  confidence=high  layer=scheduler
  evidence:
  • [timer] UnitFileState=disabled
  • [timer] ActiveState=inactive

✗ LAYER2_HTTP01_TIMEOUT  confidence=high  layer=validation
  evidence:
  • [log] line 68: 203.0.113.10: Fetching http://example.com/.well-known/acme-challenge/timeouttoken0000000000000000001: Timeout during connect (likely firewall problem)
  • [log] 2 attempts in this log (ACME response and Certbot summary of one attempt count as one), first on line 20

Next (SAFE copy-paste checks, read-only; Doctor runs nothing and will NOT renew or reload for you):
  → systemctl list-timers --all certbot.timer
    why: shows whether the timer is scheduled and when it last ran
  → systemctl is-enabled certbot.timer
    why: shows whether the timer is enabled
  → systemctl status certbot.timer --no-pager
    why: shows whether the timer is active
  → curl -q -sI --max-time 10 http://example.com/.well-known/acme-challenge/acme-renew-doctor-check
    why: any HTTP answer, even 404, means port 80 answers here; a timeout points to firewall or routing
  → dig +short A example.com
    why: compare the A record with the public IPv4 address of this server
  → dig +short AAAA example.com
    why: compare with the public IP of this server; a stale AAAA record is a common cause
  → ss -ltn
    why: look for a listener on port 80
  → sudo tail -n 200 /var/log/letsencrypt/letsencrypt.log
    why: shows recent lines from the Certbot log
  # also test from outside your network: the CA does not see what localhost sees
  ⚠ Do not force a renewal: Let's Encrypt rate limits apply. Fix the named layer first.
    (dangerous suggestions suppressed by default)

exit 1: problem found
```

`2 attempts` is het aantal: een ACME-antwoord en een Certbot-samenvatting van één poging tellen als één. De regel wordt alleen afgedrukt als dat aantal groter is dan 1, dus het woord is `attempts`.

Certificaatdatums die gelijk zijn en nog niet aan de beurt, met de klok vastgezet voor het voorbeeld. `ACME_RENEW_DOCTOR_NOW` is een geheel getal van Unix-seconden. Het wordt nooit afgedrukt. `1,5` en `1.5` worden geweigerd. De UTC-datum moet in 1970-01-01 tot en met 9999-12-31 vallen.

```console
$ ACME_RENEW_DOCTOR_NOW=1791273600 acme-renew-doctor example.com --from-timer-status tests/fixtures/timer/certbot-timer-enabled.txt --from-cert-disk tests/fixtures/certs/dates-current.txt --from-cert-live tests/fixtures/certs/dates-current.txt
acme-renew-doctor 0.1.0 (read-only, nothing was changed)
target: example.com · client: auto
inputs: log=(none) · timer status=tests/fixtures/timer/certbot-timer-enabled.txt · cert disk=tests/fixtures/certs/dates-current.txt · cert live=tests/fixtures/certs/dates-current.txt

✓ OK_NOT_DUE  confidence=high  layer=-
  evidence:
  • [disk] notAfter=Dec 27 03:12:44 2026 GMT
  • [handshake] notAfter=Dec 27 03:12:44 2026 GMT
  • [timer] Id=certbot.timer
  • [timer] LoadState=loaded
  • [timer] ActiveState=active
  • [timer] UnitFileState=enabled

Next (SAFE copy-paste checks, read-only; Doctor runs nothing and will NOT renew or reload for you):
  → systemctl list-timers --all certbot.timer
    why: shows whether the timer is scheduled and when it last ran
  ⚠ Do not force a renewal: Let's Encrypt rate limits apply. Fix the named layer first.
    (dangerous suggestions suppressed by default)

exit 0: ok, not due
```

`1791273600` is 2026-10-06 08:00:00 UTC. `--json` schrijft één JSON-object in plaats van deze tekst. Alle opties, exitcodes en foutmeldingen staan in de [referentie](docs/reference.nl.md) en in `acme-renew-doctor --help`.

## Hoe het werkt

Elke code is terug te voeren op deze regels. De volledige herkenningstekst, de bestandsformaten en de foutmeldingen staan in de [referentie](docs/reference.nl.md#hoe-een-code-gekozen-wordt).

- **Eén validatiecode.** De ACME-fout met het nieuwste tijdstempel wint (`YYYY-MM-DD HH:MM:SS,mmm:`, Certbot `log.py` r.47). Een regel zonder tijdstempel hoort bij de laatste regel met tijdstempel erboven. Bij gelijk tijdstempel, of zonder tijdstempels, blijft de onderste regel als de diepte gelijk is. Een genest subprobleem wint van zijn ouder bij hetzelfde tijdstempel. Het voorvoegsel `During secondary validation: ` wordt vóór de herkenning weggehaald. De bewijsregel houdt de originele tekst. JSON-`type` en `detail` komen uit hetzelfde object, in beide volgordes. Tekst na de `}` van dat object hoort er niet bij. Dezelfde `type` of `detail` twee keer met dezelfde waarde telt als één. Witruimte, ook een newline, mag tussen de sleutel, de dubbele punt en de waarde staan. Twee verschillende waarden van elke JSON-soort in één object zijn geen laagcode; het rapport zegt `ACME JSON is ambiguous (the same object has type or detail more than once with different values)`. Een ander object, of een Certbot-samenvatting, kan nog wel een validatiecode zijn. Een lege waarde bij Domain, Identifier, Type of Detail is geen samenvatting.
- **Timer.** Opgeslagen uitvoer van `systemctl show` wordt alleen gelezen voor `certbot.timer`, `certbot.service` en `snap.certbot.renew.timer`. Elke andere unit wordt genegeerd. Dezelfde unit twee keer met dezelfde toestand telt als één. Dezelfde unit twee keer met verschillende toestanden is `INSUFFICIENT_EVIDENCE` (`timer status is ambiguous (the same unit appears more than once with different states)`). `Id=`-regels die geen van die drie units noemen zijn `INSUFFICIENT_EVIDENCE` (`timer status not recognised (no certbot.timer, certbot.service or snap.certbot.renew.timer)`). `LAYER1_TIMER_DISABLED` als LoadState `masked` is, of als de timer `loaded` is en UnitFileState `disabled` of `masked` is. `LAYER1_TIMER_NOT_FIRING` als hij loaded is en niet disabled of masked, en hij niet `active` is of zijn Result niet leeg is en niet `success`. Dezelfde sleutel twee keer in één blok met een andere waarde is hetzelfde dubbelzinnige resultaat; dezelfde waarde twee keer telt als één. Een ontbrekende ActiveState of UnitFileState is geen `LAYER1_TIMER_NOT_FIRING` met hoge zekerheid. Een gefaalde `certbot.service` houdt zijn bewijsregel op de eerste laagdiagnose, niet op een leesfout. Zonder laagdiagnose en zonder leesfout blijft de regel op de onvoldoende-bewijs-bevinding.
- **Certificaten.** Datums komen uit opgeslagen uitvoer van `openssl x509 -noout -dates`. Een jaar buiten 1970 tot en met 9999 wordt niet herkend, en twee `notAfter`-regels die niet hetzelfde tijdstip zijn worden niet herkend. `LAYER3_NO_RELOAD` als de notAfter op schijf later is dan de live notAfter. `OK_NOT_DUE` als schijf en live notAfter gelijk zijn, er genoeg kalenderdagen over zijn, de notBefore van het certificaat op schijf (als die bekend is) niet na `now` ligt, er geen ACME-fout is, de service-unit niet `failed` is, dit niet het niet-ondersteunde snap-timergeval is, een snap-timer die de enige timer is en niet loaded en active is geen `OK_NOT_DUE`, en een timer als die er is loaded, enabled en active is. "Genoeg dagen" is een derde van de looptijd van het certificaat op schijf zelf (notAfter minus notBefore, uit dezelfde opgeslagen `-dates`-uitvoer), met een maximum van 30 dagen, of de vaste 30 dagen als notBefore ontbreekt of niet vóór notAfter ligt. Het maximum is nodig omdat geen publiek vertrouwd certificaat langer loopt dan Certbot's standaard van 90 dagen, dus een langere looptijd mag de drempel niet soepeler maken; het schalen naar de looptijd is nodig omdat Let's Encrypt ook certificaten van 6 dagen uitgeeft, waarbij een vaste 30 dagen langer is dan de hele levensduur van het certificaat en `OK_NOT_DUE` nooit haalbaar zou zijn. Op 2026-10-17 geraadpleegd, staat op https://letsencrypt.org/docs/faq/ "Our default certificates are valid for 90 days." en "Subscribers can opt in to short-lived certificates which are valid for six days."
- **Client.** Met `--client auto` is een log alleen Certbot als een regel die tijdstempelvorm heeft, een level, en een loggernaam die met `certbot` of `acme` begint. Anders is de code `CLIENT_UNKNOWN` (exit 3). `--client acme.sh` wordt niet gelezen.
- **Checks.** Het menselijke rapport toont alleen-lezen copy-paste-checks. Doctor voert ze niet uit. Een check moet door de allowlist en de woorden-denylist. Een korte denylist-vlag wordt exact vergeleken, dus `-i` wordt geweigerd en `-I` is een andere vlag. Een woord of een lange vlag wordt vergeleken zonder op ASCII-hoofdletters te letten. Wat niet doorkomt wordt weggelaten, en het commando wordt niet getoond. Het bewijs zegt dan `1 suggested check` of `2 suggested checks`, zodat het woord bij het getal past. Een bevinding met de notitie dat `certbot.service` faalde stelt ook `journalctl -u certbot.service -n 50 --no-pager` voor, één keer, ook als die bevinding een laagcode is.
- **Exit.** 0 ok, nog niet aan de beurt. 1 er is een laag gevonden. 2 onvoldoende bewijs. 3 gebruik, inclusief `CLIENT_UNKNOWN`. `CLIENT_UNKNOWN` wordt vóór elke laagcode bekeken. Als het tekstrapport, `--json`, `--help` of `--version` niet geschreven kan worden omdat de standaarduitvoer dicht of vol is, panict de tool niet: hij schrijft `acme-renew-doctor: could not write output: ...` naar de standaardfout en eindigt met 3. Een gebruiksmelding die niet geschreven kan worden doet hetzelfde. `--help` en `--version` eindigen alleen met 0 als die tekst geschreven is. Als de standaardfout dicht of vol is, panict de melding voor een ongeldige `ACME_RENEW_DOCTOR_NOW` niet, en het proces eindigt nog steeds met 3.

`DOMAIN` staat op het rapport en filtert de log niet. `[DOMAIN]` en `--all` kunnen niet samen. `--client` is standaard `auto`.

## Vergelijking met alternatieven

Andere aanpakken en waarom deze tool ze niet kiest. Voor de producten hieronder is geen leverancierspagina nagelezen, dus geen van deze vergelijkingen is een citaat van een leverancierspagina; wat niet geverifieerd is, staat erbij.

**Een Python-script.** Eén Rust-binary is makkelijker te installeren.

**Zelf vernieuwen of herladen.** Te riskant. De rate limits van Let's Encrypt gelden. De standaarduitvoer stelt nooit `--force-renewal` voor, en ook geen reload die de tool zou uitvoeren.

**certease.** Beschreven als tool voor fleet-installatie. Niet geverifieerd: er is geen pagina nagelezen. Het is een ander product: deze tool stelt een diagnose van één machine op basis van bestanden die je meegeeft.

**Een cloud-monitor voor verloopdatums, bijvoorbeeld Red Sift.** Zulke diensten bestaan en bewaken verloopdatums van buitenaf, maar geven geen lokale oorzaak. Niet geverifieerd: er is geen pagina nagelezen.

**Caddy, Traefik en cert-manager.** Niet in 0.1.0. Ze hebben hun eigen ACME-implementaties. Misschien later.

**acme-renew-doctor** is MIT OR Apache-2.0, één binary, geen account, geen netwerk. Het leest bestanden die je meegeeft en noemt een laag met de bewijsregel.

## Beperkingen

- Live verzamelen is niet gebouwd. Zonder `--from-*`-bestand is het rapport `INSUFFICIENT_EVIDENCE` (exit 2) en zegt het dat je die bestanden moet meegeven.
- De tool redigeert niet. In het tekstrapport wordt tekst uit een invoerbestand als citaat op één regel getoond: C0- en C1-stuurtekens (ESC, CR, LF, TAB, DEL en U+0080 tot en met U+009F) en U+2028 en U+2029, plus bidirectionele stuurtekens (U+202A tot en met U+202E, U+2066 tot en met U+2069, U+200E, U+200F en U+061C), worden als zichtbare escapes geschreven, zoals `\n` en `\u{1b}`. Een logcitaat houdt het voorvoegsel `[log] line N:`. Woorden in dat citaat, inclusief `--force-renewal`, zijn de woorden uit het bestand, geen voorgestelde check en geen advies. `--json` houdt zijn eigen escaping.
- acme.sh-logs worden niet gelezen. `--client acme.sh` is `INSUFFICIENT_EVIDENCE`. Installatiepaden van acme.sh verschillen per systeem.
- Certificaatdatums komen alleen uit opgeslagen uitvoer van `openssl x509 -dates`, niet uit PEM en niet uit een live handshake. `OK_NOT_DUE` schaalt zijn drempel naar de looptijd van het certificaat op schijf (notBefore tot notAfter), met een maximum van 30 dagen, en valt terug op de vaste 30 dagen als notBefore ontbreekt.
- `DOMAIN` staat op het rapport en filtert de log niet.
- Geplakte terminaluitvoer van Certbot (geen letsencrypt.log) is `CLIENT_UNKNOWN` met `--client auto`. Met `--client certbot` wordt de samenvatting gelezen. De oude Boulder-tekst `Error creating new order :: ...` in terminaluitvoer, en een samenvatting zonder inspringing, worden niet herkend.
- Een check vanaf localhost is niet hetzelfde als wat de CA van buiten ziet.
- Logs en timers vragen vaak root. Zonder root werkt alleen de `--from-*`-bestandsmodus, of het resultaat is exit 2.
- De checks en voorbeelden gaan uit van `certbot.timer`. Een snap-installatie (`snap.certbot.renew.timer`) of cron wordt niet herkend.
- Certbot roteert `letsencrypt.log` bij elke run (`certbot/_internal/log.py` v5.0.0 r.165-173, `RotatingFileHandler` met `doRollover`). Eerdere runs staan in `letsencrypt.log.N`, en `--from-log` leest één bestand.
- De voorgestelde checks gaan uit van Certbot op systemd (`certbot.timer`, `/etc/letsencrypt`, `/var/log/letsencrypt`). Voor snap- of cron-installaties en voor acme.sh zijn ze nog niet aangepast. Sommige checks vragen sudo, alleen om te lezen.
- De verbindingsfouten `Network unreachable`, `Connection reset by peer`, `Timeout after connect` en `Timeout during <op>` (Boulder `va/va.go` r.426-442) krijgen geen eigen code. Ze zijn `INSUFFICIENT_EVIDENCE` met de bewijsregel `recognised connection error without a dedicated rule`.
- Aan elkaar geplakte logs: de ACME-fout met het nieuwste tijdstempel wint. Refused op `2026-09-28 04:05:11` boven timeout op `2026-09-28 03:12:44` is `LAYER2_HTTP01_REFUSED`. Bij gelijk tijdstempel, of een samenvatting zonder tijdstempels (`--client certbot`), blijft de onderste regel als de diepte gelijk is. Een genest subprobleem wint van zijn ouder bij hetzelfde tijdstempel.
- `--from-log` leest ongeldige UTF-8 door U+FFFD op de plaats van elke ongeldige reeks te zetten, en het rapport zegt hoeveel ongeldige bytes vervangen zijn, zonder ze te citeren. Eén ongeldige byte (bijvoorbeeld `0xFF` of Latin-1 `0xE9`) in de timeout-log geeft nog steeds `LAYER2_HTTP01_TIMEOUT` (exit 1). Een vervangingsteken geeft nooit `OK_NOT_DUE`. UTF-16 en UTF-32, little-endian of big-endian, met of zonder BOM, worden geweigerd (exit 2); de melding noemt de codering en zegt dat het bestand als UTF-8 opgeslagen moet worden. Een UTF-8-BOM geeft nog steeds `LAYER2_HTTP01_TIMEOUT`. Eén NUL-byte, of een paar ongeldige bytes die niet dat brede-coderingspatroon zijn, wordt niet als UTF-16 gezien. `--from-timer-status`, `--from-cert-disk` en `--from-cert-live` gebruiken dezelfde UTF-16- en UTF-32-controle als een log, met of zonder BOM, en stoppen met exit 2 en dezelfde melding. Een UTF-8-BOM vooraan wordt overgeslagen en het bestand blijft werken. Elke andere bytereeks die geen geldige UTF-8 is, wordt geweigerd (exit 2) met `cannot read PATH: the file is not valid UTF-8`.
- Elk van `--from-log`, `--from-timer-status`, `--from-cert-disk` en `--from-cert-live` leest alleen een gewoon bestand, en het bestand wordt eerst geopend, met één uitzondering: `--from-log -` leest in plaats daarvan standaardinvoer, volledig gebufferd (tot dezelfde limiet van 268435456 bytes) voordat dezelfde controles lopen, zodat `journalctl -u certbot.service | acme-renew-doctor example.com --from-log -` werkt. Het type en de grootte komen anders van dat geopende bestand. Op Linux, macOS en de BSD's blokkeert het openen niet als het pad een fifo is. Een fifo, een apparaat zoals `/dev/zero`, of een pipe zoals `/dev/stdin` is exit 2 met `cannot read PATH: not a regular file, save the output to a file first`; alleen het letterlijke pad `-` leest standaardinvoer, en alleen bij `--from-log`. Een map is exit 2 met `cannot read PATH: is a directory`. Een leeg pad is exit 2 met `cannot read: the path is empty`. `--from-log` weigert een bestand groter dan 268435456 bytes (256 MiB). Het timerbestand en beide certificaatbestanden weigeren een bestand groter dan 1048576 bytes (1 MiB). Een log boven die limiet zegt `cannot read PATH: the file is N bytes, over the 268435456 byte limit`. Een timer- of certificaatbestand boven zijn limiet zegt `cannot read PATH: the file is N bytes, over the 1048576 byte limit`. Als het bestand groeit terwijl het gelezen wordt, zegt een log `cannot read PATH: the file is over the 268435456 byte limit`, en een timer- of certificaatbestand zegt `cannot read PATH: the file is over the 1048576 byte limit`. Op de `inputs:`-regel van het tekstrapport wordt een pad getoond zoals het is, zodat `C:\Users\certbot` leesbaar blijft, tenzij het een stuurteken of bidirectioneel teken bevat of met `"` begint. Dan wordt het tussen dubbele aanhalingstekens getoond met de escapes `\\`, `\"`, `\n`, `\r`, `\t` en `\u{..}`, zodat een echte newline `"a\nb.log"` is en de twee tekens backslash en n `a\nb.log` blijven. In bewijsregels en in JSON worden stuurtekens en backslashes ge-escaped. Een pad dat geen UTF-8 is, wordt getoond met U+FFFD op de plaats van de slechte bytes, en de JSON blijft geldig.
- Een certificaatdatum met een niet-Engelse maandnaam (bijvoorbeeld `Mei`) wordt niet herkend (exit 2). Maak `openssl`-uitvoer met een Engelse of C-locale. Dit rust op broncode, niet op een echte `nl_NL`-run.
- Het model noemt ook `DANGEROUS_FORCE_BLOCKED`, `LAYER1_PERMISSION`, `LAYER2_DNS01_CREDENTIALS`, `LAYER2_HTTP01_404_WEBROOT`, `LAYER2_HTTP01_REDIRECT` en `LAYER3_COPIED_PATH`. De ingebouwde regels kiezen die laagcodes niet. `DANGEROUS_FORCE_BLOCKED` wordt alleen toegevoegd als een voorgestelde check de allowlist niet haalt. De checks die de tool zelf voorstelt halen die lijst wel.

## Privacy

acme-renew-doctor werkt volledig offline: geen netwerk, geen API-key, geen telemetrie. De enige runtime-dependency is clap. Het redigeert niet: bewijstekst is de bestandstekst, met stuurtekens als zichtbare escapes in het tekstrapport. Alle fixtures zijn synthetisch of geanonimiseerde kopieën van openbare berichten. Zie [tests/fixtures/README.md](tests/fixtures/README.md).

## Steunen

acme-renew-doctor is gratis te gebruiken. Bespaart het je tijd, dan kun je het werk steunen via [Ko-fi](https://ko-fi.com/pepai).

## Licentie

Naar keuze onder een van deze licenties:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

Copyright 2026 PEPAI.

## Contact

PEPAI, pep_ai@icloud.com

Meld bugs en ideeën via [Issues](https://github.com/qwpp7g79y4-maker/acme-renew-doctor/issues); meld beveiligingsproblemen privé zoals beschreven in [SECURITY.md](SECURITY.md).
