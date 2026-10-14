#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerStatus {
    pub id: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub unit_file_state: String,
    pub result: String,
    pub condition_result: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemctlShow {
    pub timer: Option<TimerStatus>,
    pub service: Option<TimerStatus>,
    /// `snap.certbot.renew.timer`, separate from certbot.timer.
    pub snap_timer: Option<TimerStatus>,
}

struct Block {
    has_id: bool,
    /// A key in this block was repeated with a different value.
    conflict: bool,
    /// An `Id=` value was one of the three Certbot units.
    supported_id: bool,
    seen_id: bool,
    seen_load: bool,
    seen_active: bool,
    seen_sub: bool,
    seen_unit_file: bool,
    seen_result: bool,
    seen_condition: bool,
    status: TimerStatus,
}

const CERTBOT_TIMER_ID: &str = "certbot.timer";
const CERTBOT_SERVICE_ID: &str = "certbot.service";
const SNAP_TIMER_ID: &str = "snap.certbot.renew.timer";

pub const NO_ID_LINE: &str = "timer status not recognised (no Id= line in systemctl show output)";
pub const NO_SUPPORTED_UNIT: &str =
    "timer status not recognised (no certbot.timer, certbot.service or snap.certbot.renew.timer)";
pub const AMBIGUOUS_UNITS: &str =
    "timer status is ambiguous (the same unit appears more than once with different states)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShowParse {
    Units(Box<SystemctlShow>),
    NoId,
    NoSupportedUnit,
    Ambiguous,
}

pub fn parse_systemctl_show(text: &str) -> Option<SystemctlShow> {
    match classify_show(text) {
        ShowParse::Units(show) => Some(*show),
        _ => None,
    }
}

pub fn classify_show(text: &str) -> ShowParse {
    let blocks = parse_blocks(text);
    if !blocks.iter().any(|block| block.has_id) {
        return ShowParse::NoId;
    }
    // A supported unit whose own block repeats a key with two values is ambiguous,
    // even when the last `Id=` is no longer that unit.
    if blocks
        .iter()
        .any(|block| block.conflict && block.supported_id)
    {
        return ShowParse::Ambiguous;
    }
    let timer = match one_unit(&blocks, CERTBOT_TIMER_ID) {
        UnitPick::Ambiguous => return ShowParse::Ambiguous,
        UnitPick::One(block) => Some(block.status.clone()),
        UnitPick::None => None,
    };
    let service = match one_unit(&blocks, CERTBOT_SERVICE_ID) {
        UnitPick::Ambiguous => return ShowParse::Ambiguous,
        UnitPick::One(block) => Some(block.status.clone()),
        UnitPick::None => None,
    };
    let snap_timer = match one_unit(&blocks, SNAP_TIMER_ID) {
        UnitPick::Ambiguous => return ShowParse::Ambiguous,
        UnitPick::One(block) => Some(block.status.clone()),
        UnitPick::None => None,
    };
    if timer.is_none() && service.is_none() && snap_timer.is_none() {
        return ShowParse::NoSupportedUnit;
    }
    ShowParse::Units(Box::new(SystemctlShow {
        timer,
        service,
        snap_timer,
    }))
}

enum UnitPick<'a> {
    None,
    One(&'a Block),
    Ambiguous,
}

fn one_unit<'a>(blocks: &'a [Block], id: &str) -> UnitPick<'a> {
    let mut chosen: Option<&Block> = None;
    for block in blocks
        .iter()
        .filter(|block| block.has_id && block.status.id == id)
    {
        if block.conflict {
            return UnitPick::Ambiguous;
        }
        match chosen {
            None => chosen = Some(block),
            Some(previous) if same_unit_state(&previous.status, &block.status) => {}
            Some(_) => return UnitPick::Ambiguous,
        }
    }
    match chosen {
        Some(block) => UnitPick::One(block),
        None => UnitPick::None,
    }
}

fn same_unit_state(left: &TimerStatus, right: &TimerStatus) -> bool {
    left.load_state == right.load_state
        && left.active_state == right.active_state
        && left.sub_state == right.sub_state
        && left.unit_file_state == right.unit_file_state
        && left.result == right.result
        && left.condition_result == right.condition_result
}

fn parse_blocks(text: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut current = empty_block();
    let mut any = false;
    for line in text.lines() {
        if line.is_empty() {
            if any {
                blocks.push(current);
                current = empty_block();
                any = false;
            }
            continue;
        }
        any = true;
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "Id" => {
                current.has_id = true;
                if value == CERTBOT_TIMER_ID
                    || value == CERTBOT_SERVICE_ID
                    || value == SNAP_TIMER_ID
                {
                    current.supported_id = true;
                }
                assign(
                    &mut current.seen_id,
                    &mut current.status.id,
                    &mut current.conflict,
                    value,
                );
            }
            "LoadState" => assign(
                &mut current.seen_load,
                &mut current.status.load_state,
                &mut current.conflict,
                value,
            ),
            "ActiveState" => assign(
                &mut current.seen_active,
                &mut current.status.active_state,
                &mut current.conflict,
                value,
            ),
            "SubState" => assign(
                &mut current.seen_sub,
                &mut current.status.sub_state,
                &mut current.conflict,
                value,
            ),
            "UnitFileState" => assign(
                &mut current.seen_unit_file,
                &mut current.status.unit_file_state,
                &mut current.conflict,
                value,
            ),
            "Result" => assign(
                &mut current.seen_result,
                &mut current.status.result,
                &mut current.conflict,
                value,
            ),
            "ConditionResult" => assign(
                &mut current.seen_condition,
                &mut current.status.condition_result,
                &mut current.conflict,
                value,
            ),
            _ => {}
        }
    }
    if any {
        blocks.push(current);
    }
    blocks
}

/// The first value is stored. The same value again is fine. A different value
/// marks the block ambiguous and leaves the first value in place.
fn assign(seen: &mut bool, slot: &mut String, conflict: &mut bool, value: &str) {
    if *seen && *slot != value {
        *conflict = true;
    }
    if !*seen {
        *slot = value.to_string();
    }
    *seen = true;
}

fn empty_block() -> Block {
    Block {
        has_id: false,
        conflict: false,
        supported_id: false,
        seen_id: false,
        seen_load: false,
        seen_active: false,
        seen_sub: false,
        seen_unit_file: false,
        seen_result: false,
        seen_condition: false,
        status: TimerStatus {
            id: String::new(),
            load_state: String::new(),
            active_state: String::new(),
            sub_state: String::new(),
            unit_file_state: String::new(),
            result: String::new(),
            condition_result: String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPORT: &str = "\
NextElapseUSecRealtime=
LastTriggerUSec=
Result=success
Id=apport-autoreport.timer
LoadState=loaded
ActiveState=inactive
SubState=dead
UnitFileState=enabled
ConditionResult=no
";

    const TWO_UNITS: &str = "\
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
";

    const XFS: &str = "\
NextElapseUSecRealtime=
LastTriggerUSec=
Result=success
Id=xfs_scrub_all.timer
LoadState=loaded
ActiveState=inactive
SubState=dead
UnitFileState=disabled
ConditionResult=no
";

    fn crlf(text: &str) -> String {
        text.replace('\n', "\r\n")
    }

    fn timer_of(show: &SystemctlShow) -> &TimerStatus {
        show.timer.as_ref().expect("timer")
    }

    #[test]
    fn apport_shape_parses_when_the_id_is_certbot_timer() {
        let text = APPORT.replace("Id=apport-autoreport.timer", "Id=certbot.timer");
        let show = parse_systemctl_show(&text).expect("certbot");
        let timer = timer_of(&show);
        assert_eq!(timer.id, "certbot.timer");
        assert_eq!(timer.load_state, "loaded");
        assert_eq!(timer.active_state, "inactive");
        assert_eq!(timer.sub_state, "dead");
        assert_eq!(timer.unit_file_state, "enabled");
        assert_eq!(timer.result, "success");
        assert_eq!(timer.condition_result, "no");
        assert!(show.service.is_none());
        assert_eq!(parse_systemctl_show(&crlf(&text)), Some(show));
    }

    #[test]
    fn two_units_split_timer_and_service() {
        let text = TWO_UNITS
            .replace("Id=apt-daily.timer", "Id=certbot.timer")
            .replace("Id=force-ryzen-performance.service", "Id=certbot.service");
        let show = parse_systemctl_show(&text).expect("two units");
        let timer = timer_of(&show);
        assert_eq!(timer.id, "certbot.timer");
        assert_eq!(timer.active_state, "active");
        assert_eq!(timer.sub_state, "waiting");
        assert_eq!(timer.unit_file_state, "enabled");
        assert_eq!(timer.result, "success");
        assert_eq!(timer.condition_result, "yes");
        let service = show.service.clone().expect("service block");
        assert_eq!(service.id, "certbot.service");
        assert_eq!(service.load_state, "loaded");
        assert_eq!(service.active_state, "failed");
        assert_eq!(service.sub_state, "failed");
        assert_eq!(service.unit_file_state, "enabled");
        assert_eq!(service.result, "exit-code");
        assert_eq!(service.condition_result, "yes");
        assert_eq!(parse_systemctl_show(&crlf(&text)), Some(show));
    }

    #[test]
    fn xfs_shape_parses_when_the_id_is_certbot_timer() {
        let text = XFS.replace("Id=xfs_scrub_all.timer", "Id=certbot.timer");
        let show = parse_systemctl_show(&text).expect("certbot");
        let timer = timer_of(&show);
        assert_eq!(timer.id, "certbot.timer");
        assert_eq!(timer.load_state, "loaded");
        assert_eq!(timer.active_state, "inactive");
        assert_eq!(timer.sub_state, "dead");
        assert_eq!(timer.unit_file_state, "disabled");
        assert_eq!(timer.result, "success");
        assert_eq!(timer.condition_result, "no");
        assert!(show.service.is_none());
        assert_eq!(parse_systemctl_show(&crlf(&text)), Some(show));
    }

    #[test]
    fn service_only_block_is_not_a_timer() {
        let text = "\
Result=exit-code
Id=certbot.service
LoadState=loaded
ActiveState=failed
SubState=failed
UnitFileState=enabled
ConditionResult=yes
";
        let show = parse_systemctl_show(text).expect("service only");
        assert!(show.timer.is_none());
        let service = show.service.clone().expect("service block");
        assert_eq!(service.id, "certbot.service");
        assert_eq!(service.active_state, "failed");
        assert_eq!(service.result, "exit-code");
        assert_eq!(parse_systemctl_show(&crlf(text)), Some(show));
    }

    #[test]
    fn bare_certbot_id_is_not_a_supported_unit() {
        let text = "\
Id=certbot
LoadState=loaded
ActiveState=active
SubState=waiting
UnitFileState=enabled
Result=success
";
        assert!(parse_systemctl_show(text).is_none());
    }

    #[test]
    fn identical_certbot_timer_blocks_are_one_timer() {
        let text = "\
Id=certbot.timer
LoadState=loaded
ActiveState=inactive
UnitFileState=disabled

Id=certbot.timer
LoadState=loaded
ActiveState=inactive
UnitFileState=disabled
";
        let show = parse_systemctl_show(text).expect("one timer");
        let timer = timer_of(&show);
        assert_eq!(timer.id, "certbot.timer");
        assert_eq!(timer.unit_file_state, "disabled");
        assert_eq!(timer.active_state, "inactive");
    }

    #[test]
    fn no_id_is_none() {
        assert!(parse_systemctl_show("LoadState=loaded\nActiveState=active\n").is_none());
        assert!(parse_systemctl_show("").is_none());
    }

    #[test]
    fn snap_timer_is_not_the_certbot_timer() {
        let both = "\
Id=certbot.timer
LoadState=masked
ActiveState=inactive
UnitFileState=masked

Id=snap.certbot.renew.timer
LoadState=loaded
ActiveState=active
UnitFileState=enabled
";
        let show = parse_systemctl_show(both).expect("both");
        assert_eq!(show.timer.as_ref().expect("certbot").id, "certbot.timer");
        assert_eq!(show.timer.as_ref().expect("certbot").load_state, "masked");
        assert_eq!(
            show.snap_timer.as_ref().expect("snap").id,
            "snap.certbot.renew.timer"
        );
        assert_eq!(
            show.snap_timer.as_ref().expect("snap").active_state,
            "active"
        );
        assert!(show.service.is_none());

        let only = "\
Id=snap.certbot.renew.timer
LoadState=loaded
ActiveState=active
UnitFileState=enabled
";
        let show = parse_systemctl_show(only).expect("snap only");
        assert!(show.timer.is_none());
        assert!(show.service.is_none());
        assert_eq!(
            show.snap_timer.as_ref().expect("snap").id,
            "snap.certbot.renew.timer"
        );
    }

    #[test]
    fn disabled_certbot_timer_after_an_unrelated_timer_stays_the_timer() {
        let text = "\
Id=apt-daily.timer
LoadState=loaded
ActiveState=active
UnitFileState=enabled

Id=certbot.timer
LoadState=loaded
ActiveState=inactive
UnitFileState=disabled
";
        let show = parse_systemctl_show(text).expect("certbot timer");
        let timer = timer_of(&show);
        assert_eq!(timer.id, "certbot.timer");
        assert_eq!(timer.unit_file_state, "disabled");
        assert_eq!(timer.active_state, "inactive");
        assert!(show.service.is_none());
    }

    #[test]
    fn disabled_certbot_timer_before_an_unrelated_timer_stays_the_timer() {
        let text = "\
Id=certbot.timer
LoadState=loaded
ActiveState=inactive
UnitFileState=disabled

Id=apt-daily.timer
LoadState=loaded
ActiveState=active
UnitFileState=enabled
";
        let show = parse_systemctl_show(text).expect("certbot timer");
        let timer = timer_of(&show);
        assert_eq!(timer.id, "certbot.timer");
        assert_eq!(timer.unit_file_state, "disabled");
    }

    #[test]
    fn unrelated_units_are_not_certbot_units() {
        for text in [APPORT, TWO_UNITS, XFS] {
            assert!(
                parse_systemctl_show(text).is_none(),
                "unrelated units were selected: {text}"
            );
        }
    }

    #[test]
    fn two_certbot_timers_with_different_states_are_not_one_timer() {
        let text = "\
Id=certbot.timer
LoadState=loaded
ActiveState=active
UnitFileState=enabled

Id=certbot.timer
LoadState=loaded
ActiveState=inactive
UnitFileState=disabled
";
        assert!(
            parse_systemctl_show(text).is_none(),
            "contradictory certbot.timer blocks were merged"
        );
    }

    #[test]
    fn unrelated_service_does_not_hide_certbot_service() {
        let text = "\
Id=force-ryzen-performance.service
LoadState=loaded
ActiveState=active
UnitFileState=enabled

Id=certbot.service
LoadState=loaded
ActiveState=failed
SubState=failed
UnitFileState=enabled
Result=exit-code
";
        let show = parse_systemctl_show(text).expect("certbot service");
        assert!(show.timer.is_none());
        let service = show.service.clone().expect("certbot.service");
        assert_eq!(service.id, "certbot.service");
        assert_eq!(service.active_state, "failed");
        assert_eq!(service.result, "exit-code");
    }
}
