# Timer fixtures

Output of `systemctl show <timer> -p Id,LoadState,ActiveState,SubState,UnitFileState,LastTriggerUSec,NextElapseUSecRealtime,Result` (systemd 249). One `Key=value` per line. The order is systemd's, not the order of `-p`. An empty value is `Key=`.

Source of the fields: man `org.freedesktop.systemd1(5)` and `systemctl(1)` "show". The Debian/Ubuntu timer of Certbot is called `certbot.timer`. A unit that does not exist gives `LoadState=not-found`; that is not `LAYER1_TIMER_DISABLED`.

Every file in this directory is synthetic.

Real example of an enabled timer (`apt-daily.timer`, Pop!_OS, 6 October 2026):

```
NextElapseUSecRealtime=Tue 2026-10-06 21:12:24 CEST
LastTriggerUSec=Tue 2026-10-06 09:10:06 CEST
Result=success
Id=apt-daily.timer
LoadState=loaded
ActiveState=active
SubState=waiting
UnitFileState=enabled
```

Real example of a disabled timer (`xfs_scrub_all.timer`, the same system):

```
NextElapseUSecRealtime=
LastTriggerUSec=
Result=success
Id=xfs_scrub_all.timer
LoadState=loaded
ActiveState=inactive
SubState=dead
UnitFileState=disabled
```

## certbot-timer-enabled.txt

Synthetic. The same shape as the `apt-daily.timer` example, with `Id=certbot.timer`.

Illustrative: `NextElapseUSecRealtime` and `LastTriggerUSec` (the shape comes from the real example, the values are not a reading of a real `certbot.timer`), and the `Id` value.

## certbot-timer-disabled.txt

Synthetic. The same shape as the `xfs_scrub_all.timer` example, with `Id=certbot.timer`. Empty `NextElapseUSecRealtime` and `LastTriggerUSec` follow that example.

Illustrative: the `Id` value.

## Real output of 6 October 2026 18:56 CEST

Pop!_OS, systemd 249 (249.11-0ubuntu3.20pop0). Read only, with:

`systemctl show <unit> -p Id,LoadState,ActiveState,SubState,UnitFileState,Result,ConditionResult,LastTriggerUSec,NextElapseUSecRealtime`

Two units in one call give blocks separated by one blank line. Properties that do not belong to a unit type are omitted.

Sources: man `org.freedesktop.systemd1(5)` (package systemd 249). Section Unit objects: ActiveState is `active`, `reloading`, `inactive`, `failed`, `activating` or `deactivating`; `failed` means inactive and the previous run was not successful. Section Timer unit objects: Result includes `success` and `resources`. Section Service unit objects: Result gives the reason of a failed service. Section Unit: ConditionResult is the outcome of the last condition check.

systemd v249, `src/core/timer.c` lines 915-919 (`timer_result_table`): `success`, `resources`, `start-limit-hit`. Line 337: the timer goes to `TIMER_FAILED` if result is not `success`. Line 32: `TIMER_FAILED` becomes `UNIT_FAILED` (`ActiveState=failed`). `src/basic/unit-def.c` lines 252-258 (`timer_state_table`, SubState): `dead`, `waiting`, `running`, `elapsed`, `failed`.

### (a) apport-autoreport.timer

Enabled but not active; the timer condition is not met.

```
NextElapseUSecRealtime=
LastTriggerUSec=
Result=success
Id=apport-autoreport.timer
LoadState=loaded
ActiveState=inactive
SubState=dead
UnitFileState=enabled
ConditionResult=no
```

### (b) apt-daily.timer and force-ryzen-performance.service

```
NextElapseUSecRealtime=Tue 2026-10-06 21:12:24 CEST
LastTriggerUSec=Tue 2026-10-06 09:10:06 CEST
Result=success
Id=apt-daily.timer
LoadState=loaded
ActiveState=active
SubState=waiting
UnitFileState=enabled
ConditionResult=yes

Result=exit-code
Id=force-ryzen-performance.service
LoadState=loaded
ActiveState=failed
SubState=failed
UnitFileState=enabled
ConditionResult=yes
```

`force-ryzen-performance.service` is a unit of this system. In the fixture below that Id is replaced on purpose by `certbot.service`.

### (c) xfs_scrub_all.timer

The same output as (a), with `UnitFileState=disabled` and `Id=xfs_scrub_all.timer`.

```
NextElapseUSecRealtime=
LastTriggerUSec=
Result=success
Id=xfs_scrub_all.timer
LoadState=loaded
ActiveState=inactive
SubState=dead
UnitFileState=disabled
ConditionResult=no
```

## certbot-timer-enabled-inactive.txt

Synthetic. Output (a), character for character, except `Id=apport-autoreport.timer` is replaced by `Id=certbot.timer`.

## certbot-timer-failed.txt

Synthetic. Constructed. No real failed timer was available. The shape is that of `systemctl show`. The values come from the sources above: `ActiveState=failed` and `SubState=failed` (timer.c line 32 and unit-def.c lines 252-258), `Result=resources` (`timer_result_table`, and a result other than `success` sets the timer to failed, timer.c line 337), `UnitFileState=enabled`, `ConditionResult=yes`. `LastTriggerUSec=Mon 2026-10-05 03:12:44 CEST` follows the time shape from (b); that time is illustrative. `NextElapseUSecRealtime` is empty, as in (a) and (c).

## certbot-timer-ok-service-failed.txt

Synthetic. Output (b), character for character, with two replacements: `Id=apt-daily.timer` becomes `Id=certbot.timer`, and `Id=force-ryzen-performance.service` becomes `Id=certbot.service`. The Id of that real service is replaced on purpose.

## certbot-service-only-failed.txt

Synthetic. Only the second block from `certbot-timer-ok-service-failed.txt`, character for character: the `certbot.service` block (`Result=exit-code`, `ActiveState=failed`). That block comes from output (b) above, the block of `force-ryzen-performance.service`, whose Id was already replaced by `certbot.service` in `certbot-timer-ok-service-failed.txt`. The timer block is not in it.
