#![no_main]

use libfuzzer_sys::fuzz_target;

use acme_renew_doctor::timer::{self, ShowParse};

const CERTBOT_TIMER_ID: &str = "certbot.timer";
const CERTBOT_SERVICE_ID: &str = "certbot.service";
const SNAP_TIMER_ID: &str = "snap.certbot.renew.timer";

// `timer::classify_show` on arbitrary bytes. When it recognises units, each
// slot must hold the unit its name promises, and at least one slot must be
// filled (otherwise it should have classified as `NoSupportedUnit`).
fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let text = String::from_utf8_lossy(data);
    if let ShowParse::Units(show) = timer::classify_show(&text) {
        if let Some(status) = &show.timer {
            assert_eq!(status.id, CERTBOT_TIMER_ID);
        }
        if let Some(status) = &show.service {
            assert_eq!(status.id, CERTBOT_SERVICE_ID);
        }
        if let Some(status) = &show.snap_timer {
            assert_eq!(status.id, SNAP_TIMER_ID);
        }
        assert!(show.timer.is_some() || show.service.is_some() || show.snap_timer.is_some());
    }
});
