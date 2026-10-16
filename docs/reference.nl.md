# acme-renew-doctor referentie

[English](reference.md) · Nederlands

Deze pagina heeft alle details. Voor een overzicht, zie de [README](../README.nl.md).

De uitvoer van de tool is Engels. Foutmeldingen en voorbeelden staan hier zoals de binary ze schrijft.

## Opties

Draai `acme-renew-doctor --help` voor de ingebouwde hulp. `--version` print `acme-renew-doctor 0.1.0` en eindigt met 0. `--help` en `--version` eindigen met 0 als die tekst geschreven is. Als de standaarduitvoer dicht of vol is, eindigen ze met 3 en zegt de standaardfout `acme-renew-doctor: could not write output: ...`. Andere clap-fouten eindigen met 3. Zie [Exitcodes en gebruiksfouten](#exitcodes-en-gebruiksfouten).

| Optie | Wat het doet |
| --- | --- |
| `[DOMAIN]` | Staat op het rapport. De log wordt niet op domein gefilterd. Kan niet samen met `--all`. |
| `--all` | Stel alle certificaten vast. Live verzamelen is niet gebouwd; geef `--from-*`-bestanden mee. Kan niet samen met `[DOMAIN]`. |
| `--json` | Eén JSON-object met `schema_version` 1, in plaats van tekst. |
| `--from-log` | Certbot-log om te analyseren, bijvoorbeeld een kopie van `/var/log/letsencrypt/letsencrypt.log`. |
| `--from-timer-status` | Opgeslagen uitvoer van `systemctl show certbot.timer` om te analyseren. |
| `--from-cert-disk` | Opgeslagen uitvoer van `openssl x509 -noout -dates` voor het certificaat op schijf. |
| `--from-cert-live` | Opgeslagen uitvoer van `openssl x509 -noout -dates` voor het certificaat dat de server stuurt. |
| `--client` | `certbot`, `acme.sh` of `auto`. Standaard `auto`. In 0.1.0 worden alleen Certbot-logs gelezen. |
| `--help` | Toon hulp en eindig met 0 als die tekst geschreven is. Als de standaarduitvoer dicht of vol is, eindig met 3. |
| `--version` | Toon de versie en eindig met 0 als die tekst geschreven is. Als de standaarduitvoer dicht of vol is, eindig met 3. |

`ACME_RENEW_DOCTOR_NOW` is geen vlag. Het is een omgevingsvariabele voor tests: een geheel getal van Unix-seconden, gebruikt door de 30-dagencheck, nooit afgedrukt. `1,5` en `1.5` zijn geen gehele getallen, dus ze blijven ongeldig. De UTC-datum van die seconde moet in 1970-01-01 tot en met 9999-12-31 vallen. `0` is 1970-01-01 00:00:00 UTC. `-1` en `253402300800` vallen buiten dat bereik. De waarde in de fout wordt ge-escaped zoals bestandstekst, zodat een stuurteken niet rauw wordt afgedrukt. Een systeemklok vóór 1970-01-01 UTC wordt niet seconde 0; de fout is `system clock is outside 1970-01-01 through 9999-12-31 UTC`.

De tool maakt zelf geen decimalen op. Bewijstekst is de bestandstekst, dus een Certbot-tijdstempel houdt de komma uit de log (`2026-09-28 03:12:44,512`). In het tekstrapport worden C0- en C1-stuurtekens (ESC, CR, LF, TAB, DEL en U+0080 tot en met U+009F) en U+2028 en U+2029, plus bidirectionele stuurtekens (U+202A tot en met U+202E, U+2066 tot en met U+2069, U+200E, U+200F en U+061C), in die tekst als zichtbare escapes geschreven, zoals `\n` en `\u{1b}`, zodat één bewijsregel één regel blijft. Een logcitaat houdt het voorvoegsel `[log] line N:`. Woorden in dat citaat, inclusief `--force-renewal`, zijn de woorden uit het bestand, geen voorgestelde check en geen advies. `--json` houdt zijn eigen escaping, en U+2028 blijft daar het teken.

## Exitcodes

| Exit | Wanneer |
| --- | --- |
| 0 | Er is een bevinding `OK_NOT_DUE`, en elke bevinding behalve `DANGEROUS_FORCE_BLOCKED` is `OK_NOT_DUE`. `--help` en `--version` eindigen ook met 0 als die tekst geschreven is. De tekst eindigt op `exit 0: ok, not due`. |
| 1 | Een bevinding heeft een laag (scheduler, validation of deployment). De tekst eindigt op `exit 1: problem found`. |
| 2 | Elk ander rapport, inclusief `INSUFFICIENT_EVIDENCE`. De tekst eindigt op `exit 2: insufficient evidence`. |
| 3 | Een bevinding is `CLIENT_UNKNOWN`, of clap wees de argumenten af, of `ACME_RENEW_DOCTOR_NOW` is geen geheel getal van Unix-seconden, of zijn UTC-datum valt buiten 1970-01-01 tot en met 9999-12-31. Een `CLIENT_UNKNOWN`-rapport eindigt op `exit 3: usage error`. Clap en de klokvariabele schrijven naar stderr en laten stdout leeg. Als het tekstrapport of JSON niet geschreven kan worden omdat de standaarduitvoer dicht of vol is, panict de tool niet: hij schrijft `acme-renew-doctor: could not write output: ...` naar de standaardfout en eindigt met 3. Een gebruiksmelding die niet geschreven kan worden doet hetzelfde. Als de standaardfout dicht of vol is, panict de melding voor een ongeldige `ACME_RENEW_DOCTOR_NOW` niet, en het proces eindigt nog steeds met 3. |

`CLIENT_UNKNOWN` wordt vóór elke laagcode bekeken, dus dat rapport eindigt met 3 ook als een andere bevinding een laag heeft.

## Exitcodes en gebruiksfouten

Elke rij hieronder is tegen de binary gedraaid, en een test houdt dat zo. Stdout is leeg. Het bericht is de volledige stderr. De binary zet er een newline bij. `\n` in de laatste kolom is een newline in het bericht. Een `NAAM=waarde` vooraan is een omgevingsvariabele, geen argument.

| Case | Command | Exit | Message |
| --- | --- | --- | --- |
| Unknown client. | `--client foo` | 3 | `error: invalid value 'foo' for '--client <CLIENT>'\n  [possible values: certbot, acme.sh, auto]\n\nFor more information, try '--help'.\n` |
| Domain together with `--all`. | `example.com --all` | 3 | `error: the argument '[DOMAIN]' cannot be used with '--all'\n\nUsage: acme-renew-doctor <DOMAIN>\n\nFor more information, try '--help'.\n` |
| `--from-log` without a file. | `--from-log` | 3 | `error: a value is required for '--from-log <FILE>' but none was supplied\n\nFor more information, try '--help'.\n` |
| Unknown flag. | `--bogus` | 3 | `error: unexpected argument '--bogus' found\n\n  tip: to pass '--bogus' as a value, use '-- --bogus'\n\nUsage: acme-renew-doctor [OPTIONS] [DOMAIN]\n\nFor more information, try '--help'.\n` |
| Clock with a comma. | `ACME_RENEW_DOCTOR_NOW=1,5 example.com` | 3 | `acme-renew-doctor: ACME_RENEW_DOCTOR_NOW must be a whole number of Unix seconds, got 1,5\n` |
| Clock with a dot fraction. | `ACME_RENEW_DOCTOR_NOW=1.5 example.com` | 3 | `acme-renew-doctor: ACME_RENEW_DOCTOR_NOW must be a whole number of Unix seconds, got 1.5\n` |
| Clock that is not a number. | `ACME_RENEW_DOCTOR_NOW=not-a-timestamp example.com` | 3 | `acme-renew-doctor: ACME_RENEW_DOCTOR_NOW must be a whole number of Unix seconds, got not-a-timestamp\n` |
| Clock before 1970. | `ACME_RENEW_DOCTOR_NOW=-1 example.com` | 3 | `acme-renew-doctor: ACME_RENEW_DOCTOR_NOW must be a Unix second from 1970-01-01 through 9999-12-31 UTC, got -1\n` |
| Clock after 9999. | `ACME_RENEW_DOCTOR_NOW=253402300800 example.com` | 3 | `acme-renew-doctor: ACME_RENEW_DOCTOR_NOW must be a Unix second from 1970-01-01 through 9999-12-31 UTC, got 253402300800\n` |

## Rapportmeldingen

Deze berichten zijn bewijsregels in het rapport op stdout. Stderr is leeg. De test controleert dat stdout de regel bevat en dat de proces-exit klopt. Een ontbrekend bestand gebruikt `cannot read PATH: NotFound`. Geen leesrecht gebruikt `cannot read PATH: PermissionDenied`. Een map gebruikt `cannot read PATH: is a directory`. Een fifo, apparaat of pipe gebruikt `cannot read PATH: not a regular file, save the output to a file first`. Een leeg pad gebruikt `cannot read: the path is empty`. Een log groter dan 268435456 bytes (256 MiB) gebruikt `cannot read PATH: the file is N bytes, over the 268435456 byte limit`. Een timer- of certificaatbestand groter dan 1048576 bytes (1 MiB) gebruikt `cannot read PATH: the file is N bytes, over the 1048576 byte limit`. Een bestand van precies die grootte wordt nog gelezen. Als het bestand groeit terwijl het gelezen wordt, gebruikt een log `cannot read PATH: the file is over the 268435456 byte limit`, en een timer- of certificaatbestand gebruikt `cannot read PATH: the file is over the 1048576 byte limit`.

| Case | Command | Exit | Message |
| --- | --- | --- | --- |
| Log path does not exist. | `--from-log tests/fixtures/certbot/does-not-exist.log` | 2 | `cannot read tests/fixtures/certbot/does-not-exist.log: NotFound` |
| Log path is a directory. | `--from-log tests/fixtures/certbot` | 2 | `cannot read tests/fixtures/certbot: is a directory` |
| Timer file has no `Id=` line. | `--from-timer-status tests/fixtures/certs/not-a-cert.txt` | 2 | `timer status not recognised (no Id= line in systemctl show output)` |
| Certificate file has no `notAfter=`. | `--from-cert-disk tests/fixtures/certs/not-a-cert.txt` | 2 | `certificate dates not recognised (no notAfter= line in openssl x509 -dates output)` |
| `--client acme.sh`. | `--client acme.sh --from-log tests/fixtures/acme-sh/verify-error-dns01.log` | 2 | `acme.sh logs are not parsed yet (v0.1 parses Certbot logs only)` |
| `--client auto` on a non-Certbot log. | `--from-log tests/fixtures/acme-sh/verify-error-dns01.log` | 3 | `no Certbot log lines found in tests/fixtures/acme-sh/verify-error-dns01.log (expected lines like '2026-09-28 03:12:44,512:DEBUG:certbot._internal.main:...')` |

`--from-cert-live` gebruikt dezelfde niet-herkend-zin als `--from-cert-disk`. Andere bewijsregels die het rapport kan printen: `no timer status`, `no log given`, `no disk notAfter`, `no live notAfter`, `log read, no ACME errors found`, `ACME errors in log not recognised by the current rules`, `recognised connection error without a dedicated rule`, `no .timer block in the timer status (only <id>)`, `timer status not recognised (no certbot.timer, certbot.service or snap.certbot.renew.timer)`, `timer status is ambiguous (the same unit appears more than once with different states)`, `ACME JSON is ambiguous (the same object has type or detail more than once with different values)`, `snap.certbot.renew.timer is active: snap install, not supported yet`, `snap.certbot.renew.timer is active and certbot.timer is masked: snap install, not supported yet`, en `<id> failed (Result=<result>); the renewal ran and failed, check the Certbot log`.

`--from-timer-status`, `--from-cert-disk` en `--from-cert-live` gebruiken dezelfde brede-coderingscontrole als `--from-log`. Een UTF-8-BOM vooraan wordt overgeslagen en het bestand wordt nog steeds gelezen. Elke andere bytereeks die geen geldige UTF-8 is, is exit 2 met `cannot read PATH: the file is not valid UTF-8`. Op de `inputs:`-regel van het tekstrapport wordt een pad ruw afgedrukt als het geen teken bevat dat als stuurteken of bidirectioneel teken ge-escaped zou worden, en als het niet met `"` begint. Backslashes blijven staan, dus `C:\Users\certbot\log.txt` verandert niet. Spaties en andere Unicode blijven leesbaar. Anders staat het pad tussen dubbele aanhalingstekens: `\` wordt `\\`, `"` wordt `\"`, een newline wordt `\n`, een carriage return wordt `\r`, een tab wordt `\t`, en elk ander stuurteken of bidirectioneel teken wordt `\u{..}`. Een echte newline verschijnt als `"a\nb.log"`. De twee tekens `\` en `n` blijven `a\nb.log`. Een ruw pad begint nooit met `"`, dus het kan niet op een geciteerd pad lijken. JSON-uitvoer blijft ongewijzigd en gebruikt nog steeds JSON-escaping. Een pad-byte die geen UTF-8 is, wordt getoond als U+FFFD, en de JSON blijft geldig. Een invoer/uitvoerfout waarvan het soort noch `NotFound` noch `PermissionDenied` is, is `cannot read PATH: other kind`. `--from-log` leest ongeldige UTF-8 met U+FFFD op de plaats van elke ongeldige reeks en voegt `note: replaced N invalid UTF-8 byte` toe als N 1 is, of `note: replaced N invalid UTF-8 bytes` anders. De notitie noemt het aantal en citeert de bytes niet. Een log in `UTF-16LE`, `UTF-16BE`, `UTF-32LE` of `UTF-32BE` is exit 2 met `cannot read PATH: the file is ENCODING; save it as UTF-8`. Een BOM kiest de codering. Zonder BOM moeten de eerste 64 bytes een zuiver NUL-patroon van minstens 32 bytes tonen: `UTF-32LE` is `c 00 00 00`, `UTF-16LE` is `c 00`, `UTF-32BE` is `00 00 00 c`, `UTF-16BE` is `00 c`, en `c` is nooit `00`. Een UTF-8-BOM (`EF BB BF`) wordt overgeslagen. Eén NUL-byte, of een paar ongeldige bytes die dat patroon niet vormen, is geen brede codering. Een U+FFFD in de log blokkeert `OK_NOT_DUE`.

Als de anti-force-poort voorgestelde checks laat vallen, is het bewijs `1 suggested check blocked by the anti-force gate` of `2 suggested checks blocked by the anti-force gate`. Het woord past bij het getal. De checks die de tool zelf voorstelt halen de poort, dus een normaal rapport toont deze regel niet.

De attempts-regel wordt alleen afgedrukt als het aantal groter is dan 1: `2 attempts in this log (ACME response and Certbot summary of one attempt count as one), first on line 20`. Eén poging voegt die regel niet toe.

## Codes

| Code | Laag | Betekenis |
| --- | --- | --- |
| `OK_NOT_DUE` | - | Schijf en live notAfter zijn gelijk en er blijven meer dan 30 kalenderdagen over, er is geen ACME-fout, de service-unit is niet `failed`, dit is niet het niet-ondersteunde snap-timergeval, en een timer als die er is, is loaded, enabled en active. |
| `LAYER1_TIMER_DISABLED` | scheduler | LoadState van de timer is `masked`, of hij is `loaded` met UnitFileState `disabled` of `masked`. |
| `LAYER1_TIMER_NOT_FIRING` | scheduler | De timer is `loaded` en niet disabled of masked, en hij is niet `active` of zijn Result is niet leeg en niet `success`. |
| `LAYER2_HTTP01_TIMEOUT` | validation | De gekozen ACME-fout heeft type `connection`, en het detail bevat `/.well-known/acme-challenge/` en `Timeout during connect`. |
| `LAYER2_HTTP01_REFUSED` | validation | De gekozen ACME-fout heeft type `connection`, en het detail bevat `/.well-known/acme-challenge/` en `Connection refused`. |
| `LAYER2_RATE_LIMIT` | validation | De gekozen ACME-fout heeft type `rateLimited`. Een `retry after`-tijd in het detail wordt eruit gehaald, tot aan de dubbele punt die niet in een klok zit (`08:14:02`). |
| `LAYER2_DNS01_TXT` | validation | Type `unauthorized` en het detail begint met `No TXT record found at _acme-challenge.` of met `Incorrect TXT record ` en bevat ` found at _acme-challenge.`, of type `dns` en het detail bevat ` looking up TXT for _acme-challenge.`. |
| `LAYER3_NO_RELOAD` | deployment | De notAfter op schijf is later dan de live notAfter. |
| `CLIENT_UNKNOWN` | - | `--client auto` en het bestand heeft geen Certbot-logregel. |
| `INSUFFICIENT_EVIDENCE` | - | Niet genoeg bewijs voor een laagcode of voor `OK_NOT_DUE`. |

Niet gekozen door de ingebouwde regels: `LAYER1_PERMISSION`, `LAYER2_DNS01_CREDENTIALS`, `LAYER2_HTTP01_404_WEBROOT`, `LAYER2_HTTP01_REDIRECT`, `LAYER3_COPIED_PATH`. `DANGEROUS_FORCE_BLOCKED` is alleen de poort, hierboven beschreven.

## Hoe een code gekozen wordt

- Hooguit één validatiecode, van de ACME-fout met het nieuwste tijdstempel. `parse` zet die fout achteraan. Bij gelijk tijdstempel, of zonder tijdstempels, blijft de onderste regel als de diepte gelijk is. Een genest subprobleem wint van zijn ouder bij hetzelfde tijdstempel. Een regel zonder tijdstempel krijgt het tijdstempel van de laatste regel met tijdstempel erboven.
- Het stempel is `YYYY-MM-DD HH:MM:SS,mmm` vóór de dubbele punt van Certbot `FILE_FMT` (`log.py` r.47): `%(asctime)s:%(levelname)s:%(name)s:%(message)s`. Een loggernaam die met `certbot` of `acme` begint merkt het bestand als Certbot als `--client` `auto` is.
- Het voorvoegsel `During secondary validation: ` (Boulder `va/va.go` r.718) wordt één keer weggehaald vóór de herkenning. De bewijsregel houdt de originele tekst.
- Een ACME-JSON-body en een Certbot-samenvatting van één poging tellen als één. De attempts-regel gebruikt het grootste van de twee aantallen, en alleen als dat getal groter is dan 1.
- `Timeout during connect` is `LAYER2_HTTP01_TIMEOUT` (Boulder `va/va.go` r.424). `Timeout during <op>` voor een ander enkel woord `op`, `Network unreachable`, `Connection reset by peer` en `Timeout after connect (your server may be slow or overloaded)` (r.426-442) zijn `INSUFFICIENT_EVIDENCE` met `recognised connection error without a dedicated rule`.
- Een gefaalde `certbot.service` krijgt geen eigen code. Die bewijsregel blijft op de eerste laagdiagnose, niet op een leesfout, en hij blokkeert `OK_NOT_DUE`. Zonder laagdiagnose en zonder leesfout blijft de regel op de onvoldoende-bewijs-bevinding. Alleen `certbot.timer`, `certbot.service` en `snap.certbot.renew.timer` worden gelezen, en een service-blok wordt nooit als timer gelezen.
- `snap.certbot.renew.timer`, als hij loaded en active is, wordt geen timercode en geen `OK_NOT_DUE`. Het bewijs zegt dat de snap-installatie nog niet ondersteund wordt. Als `certbot.timer` `masked` of `disabled` is, staat dat woord erbij. Als die snap-timer de enige timer is en hij niet loaded en active is, is het resultaat geen `OK_NOT_DUE` en noemt het bewijs `snap.certbot.renew.timer`. Een ontbrekende ActiveState of UnitFileState is geen `LAYER1_TIMER_NOT_FIRING` met hoge zekerheid.
- ActiveState `activating` of `deactivating` zou `LAYER1_TIMER_NOT_FIRING` geven, maar een timer heeft die toestand niet in systemd v249 `src/basic/unit-def.c` r.252-258 (`timer_state_table`).
- `OK_NOT_DUE` gebruikt 30 kalenderdagen vóór notAfter. Het gebruikt notBefore niet. De Let's Encrypt-FAQ zegt "Our default certificates are valid for 90 days." Dertig dagen benadert 2/3 daarvan. Dezelfde pagina zegt "Subscribers can opt in to short-lived certificates which are valid for six days." https://letsencrypt.org/docs/faq/
- Een U+FFFD in een gelezen log blokkeert `OK_NOT_DUE`. Ongeldige UTF-8 is de gewone bron: elke ongeldige reeks wordt één U+FFFD, en het rapport telt de ongeldige bytes.

## Bestandsformaten

**Certbot-log.** Regels in de vorm `2026-09-28 03:12:44,512:DEBUG:certbot._internal.main:message`. Een vervolgregel heeft geen nieuw tijdstempel. De samenvattingsvelden die de parser leest zijn `  Domain:` of `  Identifier:`, dan `  Type:`, dan `  Detail:`, elk met twee spaties ervoor. Een lege waarde in een van die velden is geen samenvatting. Een samenvatting die op kolom 0 begint wordt niet gelezen. JSON-foutbodies gebruiken `type` `urn:ietf:params:acme:error:...` en `detail` uit hetzelfde object, in beide volgordes. Tekst na de `}` van dat object hoort er niet bij, en een genest object houdt zijn eigen velden. Witruimte, ook een newline, mag tussen een sleutel, de dubbele punt en de waarde staan. Dezelfde `type` of `detail` twee keer met dezelfde waarde telt als één. Twee verschillende waarden van elke JSON-soort in één object worden niet als laagcode gebruikt. Een genest subprobleem wint van zijn ouder bij hetzelfde tijdstempel. Het rapport zegt `ACME JSON is ambiguous (the same object has type or detail more than once with different values)`. Een ander object, of een Certbot-samenvatting, kan nog wel een validatiecode zijn. Een object zonder `urn:ietf:params:acme:error:`-type blijft genegeerd, ook als een sleutel herhaald wordt. De herkenningstekst komt uit Boulder-commit `1578a1d051b8` (`va/va.go`, `va/dns.go`, `ratelimits/limiter.go`). Repo's: https://github.com/certbot/certbot en https://github.com/letsencrypt/boulder. `--from-log` accepteert een UTF-8-BOM vooraan. Ongeldige UTF-8 wordt vervangen, zoals bij de rapportmeldingen staat. UTF-16 en UTF-32 worden geweigerd. Het pad moet een gewoon bestand van hooguit 268435456 bytes (256 MiB) zijn.

**Timerbestand.** Uitvoer van `systemctl show`, één regel `Key=value`. Blokken van meerdere units worden gescheiden door een lege regel. Alleen `Id=certbot.timer` (de timer), `Id=certbot.service` (de service) en `Id=snap.certbot.renew.timer` (de snap-timer) worden gelezen. Elke andere unit wordt genegeerd, ook als `Id=` op `.timer` of `.service` eindigt. Dezelfde unit twee keer met dezelfde LoadState, ActiveState, SubState, UnitFileState, Result en ConditionResult telt als één. Dezelfde sleutel twee keer in één blok met een andere waarde is hetzelfde dubbelzinnige resultaat; dezelfde waarde twee keer telt als één. Dezelfde unit twee keer met een andere toestand is `timer status is ambiguous (the same unit appears more than once with different states)`. Een bestand zonder `Id=`-regel, inclusief tekst van `systemctl status`, is `timer status not recognised (no Id= line in systemctl show output)`. Een bestand met `Id=`-regels maar geen van die drie units is `timer status not recognised (no certbot.timer, certbot.service or snap.certbot.renew.timer)`. Veldnamen volgen `org.freedesktop.systemd1(5)` en `systemctl(1)` op systemd 249. `LoadState=not-found` is geen `LAYER1_TIMER_DISABLED`. Het pad moet een gewoon bestand van hooguit 1048576 bytes (1 MiB) zijn. Een UTF-8-BOM vooraan wordt overgeslagen. UTF-16 en UTF-32 worden geweigerd met dezelfde melding als een log. Andere ongeldige UTF-8 is `the file is not valid UTF-8`.

**Certificaatdatums.** `openssl x509 -noout -dates` of `-enddate` (OpenSSL 3.0.2, man `openssl-x509`). De regel is `notAfter=Mon DD HH:MM:SS YYYY GMT`. Een dag onder 10 heeft twee spaties tussen de maand en de dag, zoals in `notAfter=Jun  4 11:04:38 2035 GMT`. De maand moet een Engelse afkorting zijn. `Mei` wordt niet herkend. Het jaar loopt van 1970 tot en met 9999. Een jaar buiten dat bereik wordt niet herkend. Twee `notAfter`-regels die niet hetzelfde tijdstip zijn worden niet herkend. De tool leest geen PEM. Het pad moet een gewoon bestand van hooguit 1048576 bytes (1 MiB) zijn. Een UTF-8-BOM vooraan wordt overgeslagen. UTF-16 en UTF-32 worden geweigerd met dezelfde melding als een log. Andere ongeldige UTF-8 is `the file is not valid UTF-8`.

**acme.sh.** Wordt niet gelezen. Het synthetische voorbeeld is het openbare bericht van 14 april 2020, met de TXT-waarden vervangen door letters van dezelfde lengte. https://community.letsencrypt.org/t/verify-error-during-secondary-validation-no-txt-record-found-at-acme-challenge/119427

Je maakt de bestanden zelf. De verzamelopdrachten die bij `INSUFFICIENT_EVIDENCE` worden afgedrukt zijn:

- `--from-log`: `sudo tail -n 400 /var/log/letsencrypt/letsencrypt.log`
- `--from-timer-status`: `systemctl show certbot.timer certbot.service -p Id,LoadState,ActiveState,SubState,UnitFileState,Result,ConditionResult,LastTriggerUSec,NextElapseUSecRealtime`
- `--from-cert-disk`: `sudo openssl x509 -noout -dates -in /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem`
- `--from-cert-live`: `echo | timeout 10 openssl s_client -connect YOUR_DOMAIN:443 -servername YOUR_DOMAIN | openssl x509 -noout -dates`

`YOUR_DOMAIN` is wat de catalogus print als je geen domein meegeeft, of een domein dat `safe_domain` afwijst. Anders print hij het domein dat je meegaf. Een domein is veilig als het hooguit 253 tekens is, minstens twee labels heeft, een punt bevat, geen `*` bevat, en elk label ASCII-letters, cijfers of `-` is, niet leeg, en niet met `-` begint of eindigt.

## Voorgestelde checks

De catalogus ligt vast. Elke opdracht moet door een allowlist (het programma en zijn vlaggen) en een denylist van woorden. Een korte denylist-vlag wordt exact vergeleken (`-i` wordt geweigerd, `-I` niet). Een woord of een lange vlag wordt vergeleken zonder op ASCII-hoofdletters te letten. Als het bewijs van een bevinding zegt dat `certbot.service` faalde, stelt de catalogus ook `journalctl -u certbot.service -n 50 --no-pager` voor, één keer, voor de code van die bevinding en niet alleen voor `INSUFFICIENT_EVIDENCE`. Een check die faalt wordt weggelaten. Zijn opdracht wordt niet getoond. Samengevoegde korte opties worden gecontroleerd (`ss` `K`/`D`, `journalctl` `f`, `curl` `X`/`o`/`O`/`T`/`d`/`F`/`K`/`D`/`c`/`J`/`w`, `tail` `f`/`F`). Elke `curl`-opdracht moet `-q` als eerste argument gebruiken. Een pipe wordt gesplitst op `|`, ook zonder spaties eromheen. Schrijvende curl-opties zoals `--trace`, `--trace-ascii`, `--stderr`, `--etag-save`, `--hsts`, `--alt-svc`, `--libcurl`, `--create-dirs` en `--output-dir` worden geweigerd. `timeout` mag alleen als `timeout N` met N van 1 tot 120, vóór `openssl s_client`.

Het menselijke rapport leidt ze in met `Next (SAFE copy-paste checks, read-only; Doctor runs nothing and will NOT renew or reload for you):` en eindigt dat blok met `Do not force a renewal: Let's Encrypt rate limits apply.` Bij een timeout voegt het toe `also test from outside your network: the CA does not see what localhost sees`. Bij een rate limit voegt het toe `wait until the retry-after time; repeated attempts only extend the problem`.

## JSON-uitvoer

`--json` schrijft één object, zonder serde. Sleutels, op volgorde: `schema_version` (1), `tool` (`name`, `version`), `input` (`domain`, `all`, `client`, `from_log`, `from_timer_status`, `from_cert_disk`, `from_cert_live`), `findings` (elk `code`, `layer`, `confidence`, `evidence` van `source` en `text`), `next_checks` (elk `for`, `command`, `why`, `safety` = `read-only`), dan `exit_code`. `notes` staat vóór `exit_code` als het domein onveilig is in een shell-opdracht, of als `--from-log` ongeldige UTF-8-bytes heeft vervangen. De tekst bij een onveilig domein is `note: the domain contains characters that are unsafe in a shell command; replace YOUR_DOMAIN yourself.` De vervangingstekst is `note: replaced N invalid UTF-8 byte` of `note: replaced N invalid UTF-8 bytes`, en die komt eerst. Het domein in JSON is `YOUR_DOMAIN` als het domein onveilig is. Aanhalingstekens, backslashes, newlines en tabs worden ge-escaped. Andere C0-stuurtekens, DEL, C1-stuurtekens (U+0080 tot en met U+009F) en de bidirectionele stuurtekens hierboven worden als `\uXXXX` geschreven, zodat ze de cursor niet kunnen verplaatsen of een regel niet kunnen omdraaien als de JSON in een terminal staat. Een JSON-parser geeft het oorspronkelijke teken terug. U+2028 en U+2029 blijven het teken. Er is geen `notes`-sleutel als het domein veilig is en er geen ongeldige UTF-8-byte vervangen is.

Als er geen `--from-*`-bestand is meegegeven, eindigt het menselijke rapport ook met `note: live collection is not built yet; pass --from-log, --from-timer-status, --from-cert-disk and/or --from-cert-live.`

## Bronnen

Let's Encrypt stopte op 4 juni 2025 met e-mails over verlopende certificaten: https://letsencrypt.org/2025/06/26/expiration-notification-service-has-ended.html

Looptijd van het certificaat, hierboven geciteerd: https://letsencrypt.org/docs/faq/

De rate-limit-detailtekst in de synthetische rate-limit-fixture wijst naar https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers

Certbot en Boulder, commit `1578a1d051b8`: https://github.com/certbot/certbot en https://github.com/letsencrypt/boulder

Openbare berichten die als geanonimiseerde fixtures dienen. De bytes in `tests/fixtures/real/` en `tests/fixtures/acme-sh/` zijn de knip, met namen, adressen en tokens vervangen. Matchregels en hun inspringing zijn die van het bericht gebleven. Wat elk bestand doet staat in [tests/fixtures/README.md](../tests/fixtures/README.md).

- 12 november 2025, certbot 5.1.0, apache, regels 10-67 van de ruwe post: https://community.letsencrypt.org/t/certbot-renewal-fails-with-time-out-during-connect-likely-firewall-problem-warning/242890 en https://community.letsencrypt.org/raw/242890. Uitkomst: `LAYER2_HTTP01_TIMEOUT`, exit 1.
- Maart 2025, certbot 2.11.0, regels 225-274: https://community.letsencrypt.org/t/rate-limit-issue/235219. Uitkomst: `LAYER2_RATE_LIMIT`, exit 1, bewijs `retry after 2025-03-16 02:54:35 UTC`.
- Oktober 2020, certbot 0.31.0, regels 360-446: https://community.letsencrypt.org/t/failed-authorization-procedure-no-txt-record-found-at-acme-challenge/136973. Uitkomst: `LAYER2_DNS01_TXT`, exit 1.
- Januari 2024, certbot 2.1.0, regels 28-46, terminaluitvoer: https://community.letsencrypt.org/t/dns-01-no-txt-record-found-at-acme-challenge-domain-tld/211563. Met `--client certbot`: `LAYER2_DNS01_TXT`, exit 1. Met `--client auto`: `CLIENT_UNKNOWN`, exit 3.
- Regels 13-16, terminaluitvoer: https://community.letsencrypt.org/t/timeout-during-connect-likely-firewall-problem/244674. `--client auto`: `CLIENT_UNKNOWN`, exit 3. `--client certbot`: `LAYER2_HTTP01_TIMEOUT`, exit 1.
- Augustus 2025, regels 32-34, `Domain:` heeft in het bericht geen inspringing: https://community.letsencrypt.org/t/update-letsencrypt-certificate-fails/240423. `--client certbot`: `INSUFFICIENT_EVIDENCE`, exit 2, `log read, no ACME errors found`.
- 2023, Certbot op Windows, regels 12-39, oude Boulder-tekst `Error creating new order :: too many certificates (5) ... retry after 2023-10-04T10:49:08Z`: https://community.letsencrypt.org/t/i-made-too-many-certificated-by-accident-how-to-fix-it/206050. `--client certbot` herkent die tekst niet: `log read, no ACME errors found`.
- November 2023, certbot 1.21.0, regels 113-126, een samenvatting van een helper, geen volledige log: https://community.letsencrypt.org/t/too-many-failed-authorizations/208147. `--client certbot`: `log read, no ACME errors found`.
- Mei 2023, regels 382-391, `systemctl status` met `Loaded: masked`, en regels 553-570, `snap.certbot.renew.timer`: https://community.letsencrypt.org/t/another-instance-of-certbot-is-already-running/197422/20. Geen `Id=`-regel, dus `timer status not recognised`, exit 2.
- Super User, het codeblok zoals het er stond, `Active: inactive (dead) since .....; 1 months 7 days ago` (de puntjes staan zo in het bericht): https://superuser.com/questions/1354732. Geen `Id=`-regel, exit 2.
- 14 april 2020, acme.sh-log, eerste bericht, codeblok "Here is the complete log": https://community.letsencrypt.org/t/verify-error-during-secondary-validation-no-txt-record-found-at-acme-challenge/119427. Hetzelfde voorvoegsel staat in https://community.letsencrypt.org/t/timeout-during-connect-likely-firewall-problem/244674. De logregel wijst naar https://github.com/acmesh-official/acme.sh/wiki/How-to-debug-acme.sh.

De beschrijvingen van certease en Red Sift in de README zijn niet geverifieerd: er is geen pagina voor nagelezen.
