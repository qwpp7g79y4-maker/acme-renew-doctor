use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use crate::model::{Code, Confidence, Evidence, EvidenceSource, Finding};

pub const ACME_ERROR_PREFIX: &str = "urn:ietf:params:acme:error:";

/// One JSON object repeated `type` or `detail` with two different values.
pub const AMBIGUOUS_ACME_JSON: &str = "ACME JSON is ambiguous (the same object has type or detail more than once with different values)";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AcmeProblem {
    pub problem_type: String,
    pub detail: String,
    pub identifier: Option<String>,
    /// Line of the finding that wins: latest timestamp, otherwise the bottom line.
    pub line: usize,
    /// Line of the oldest finding: earliest timestamp, ties by the lowest line.
    /// With no timestamps, the top line.
    pub first_line: usize,
    /// JSON nesting depth. `0` for a Certbot summary. A deeper object is a
    /// nested subproblem and outranks its parent when the timestamp is the same,
    /// so the order of `type` and `subproblems` does not change the diagnosis.
    pub depth: u32,
    /// `YYYY-MM-DD HH:MM:SS,mmm` of the winning finding. A line without a timestamp
    /// takes the timestamp of the last log line above it.
    pub logged_at: Option<String>,
    /// How many hits; each JSON body and each summary counts.
    pub occurrences: usize,
    /// ACME responses (JSON) with this error.
    pub json_hits: usize,
    /// Certbot summaries with this error.
    pub summary_hits: usize,
}

impl AcmeProblem {
    pub fn short_type(&self) -> &str {
        self.problem_type
            .strip_prefix(ACME_ERROR_PREFIX)
            .unwrap_or(&self.problem_type)
    }

    /// An ACME response and a Certbot summary of one attempt count as one.
    pub fn attempts(&self) -> usize {
        self.json_hits.max(self.summary_hits)
    }
}

pub fn has_certbot_lines(text: &str) -> bool {
    text.lines().any(is_certbot_line)
}

/// Problems from a Certbot log, plus whether one ACME object contradicted itself.
pub struct LogParse {
    pub problems: Vec<AcmeProblem>,
    pub ambiguous_json: bool,
}

pub fn parse(text: &str) -> Vec<AcmeProblem> {
    parse_log(text).problems
}

pub fn parse_log(text: &str) -> LogParse {
    let scan = scan_json(text);
    let mut hits = scan.hits;
    let mut hit_at = 0usize;
    let mut set = ProblemSet::default();
    let mut stamp: Option<String> = None;
    let mut line_no = 0usize;
    let mut rest = text;
    while !rest.is_empty() {
        let (line, next) = split_line(rest);
        rest = next;
        line_no += 1;
        if let Some(found) = log_stamp(line) {
            stamp = Some(found.to_string());
        }
        if let Some((type_line, detail_line)) = two_following_lines(rest) {
            if let Some(mut problem) = summary_of(line, type_line, detail_line, line_no) {
                problem.logged_at.clone_from(&stamp);
                set.add(problem);
                for _ in 0..2 {
                    if rest.is_empty() {
                        break;
                    }
                    let (_, after) = split_line(rest);
                    rest = after;
                    line_no += 1;
                }
                skip_hits_through(&hits, &mut hit_at, line_no);
                continue;
            }
        }
        while hit_at < hits.len() && hits[hit_at].line == line_no {
            let mut problem = std::mem::take(&mut hits[hit_at]);
            hit_at += 1;
            problem.logged_at.clone_from(&stamp);
            set.add(problem);
        }
        while hit_at < hits.len() && hits[hit_at].line < line_no {
            hit_at += 1;
        }
    }
    set.problems.sort_by(diagnosis_order);
    LogParse {
        problems: set.problems,
        ambiguous_json: scan.ambiguous,
    }
}

/// A log that was read. Invalid UTF-8 sequences are U+FFFD; `replaced_invalid_utf8_bytes` counts the bytes those sequences replaced.
#[derive(Debug)]
pub struct DecodedLog {
    pub text: String,
    pub replaced_invalid_utf8_bytes: usize,
}

/// Above the 100 MiB heavy read. A larger regular file is refused before it is read.
pub const LOG_MAX_BYTES: u64 = 256 * 1024 * 1024;
/// Saved timer status and certificate dates are short text.
pub const SHORT_TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// Bytes at the start of a file inspected for a NUL pattern when there is no BOM.
const WIDE_PREFIX_LEN: usize = 64;
/// Shorter than this, a run of NULs is a few zeros, not UTF-16 or UTF-32.
const WIDE_PATTERN_MIN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WideEncoding {
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

impl WideEncoding {
    fn label(self) -> &'static str {
        match self {
            WideEncoding::Utf16Le => "UTF-16LE",
            WideEncoding::Utf16Be => "UTF-16BE",
            WideEncoding::Utf32Le => "UTF-32LE",
            WideEncoding::Utf32Be => "UTF-32BE",
        }
    }
}

/// `-` means standard input, buffered fully (up to `LOG_MAX_BYTES`) and then
/// decoded exactly like a file, so the same size and encoding checks apply.
pub fn read_log(path: &Path) -> Result<DecodedLog, Finding> {
    let is_stdin = path == Path::new("-");
    let bytes = if is_stdin {
        read_capped(
            std::io::stdin().lock(),
            LOG_MAX_BYTES,
            EvidenceSource::Log,
            "standard input",
        )?
    } else {
        read_regular_bytes(path, LOG_MAX_BYTES, EvidenceSource::Log)?
    };
    let what = if is_stdin {
        "standard input".to_string()
    } else {
        path.display().to_string()
    };
    decode_log_bytes(&what, &bytes)
}

/// Read at most `max_bytes` from `reader`, with the same over-the-limit
/// message `read_regular_bytes` uses for a file.
fn read_capped(
    mut reader: impl Read,
    max_bytes: u64,
    source: EvidenceSource,
    what: &str,
) -> Result<Vec<u8>, Finding> {
    let mut bytes = Vec::new();
    if let Err(err) = reader
        .by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
    {
        return Err(finding_for_io_kind(source, what, &err));
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(read_finding(
            source,
            format!("cannot read {what}: over the {max_bytes} byte limit"),
        ));
    }
    Ok(bytes)
}

fn finding_for_io_kind(source: EvidenceSource, what: &str, err: &std::io::Error) -> Finding {
    let kind = match err.kind() {
        std::io::ErrorKind::PermissionDenied => "PermissionDenied",
        std::io::ErrorKind::NotFound => "NotFound",
        _ => "other kind",
    };
    read_finding(source, format!("cannot read {what}: {kind}"))
}

/// Read a regular file, at most `max_bytes`.
///
/// The file is opened first, then `fstat` on that handle decides the type and
/// the size. On Unix the open uses `O_NONBLOCK` (`0o4000` on Linux and Android,
/// `0x0004` on macOS, iOS, FreeBSD, NetBSD, OpenBSD and DragonFly), so a fifo
/// swapped in under the path cannot block. A huge sparse file is still refused
/// from the size on the handle, before the bytes are kept.
///
/// If that open fails, `std::fs::metadata` (it follows symlinks) classifies the
/// path. A directory is `is a directory`. Anything else that exists and is not
/// a regular file is `not a regular file, save the output to a file first`.
/// A missing path, a regular file that could not be opened, or a failed
/// `metadata` keeps the io error kind from the open.
pub fn read_regular_bytes(
    path: &Path,
    max_bytes: u64,
    source: EvidenceSource,
) -> Result<Vec<u8>, Finding> {
    if path.as_os_str().is_empty() {
        return Err(read_finding(
            source,
            "cannot read: the path is empty".to_string(),
        ));
    }
    let file = match open_read(path) {
        Ok(file) => file,
        Err(err) => return Err(finding_for_failed_open(path, source, &err)),
    };
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(err) => return Err(finding_for_io(path, source, &err)),
    };
    if meta.is_dir() {
        return Err(read_finding(
            source,
            format!("cannot read {}: is a directory", path.display()),
        ));
    }
    if !meta.is_file() {
        return Err(read_finding(
            source,
            format!(
                "cannot read {}: not a regular file, save the output to a file first",
                path.display()
            ),
        ));
    }
    let len = meta.len();
    if len > max_bytes {
        return Err(read_finding(
            source,
            format!(
                "cannot read {}: the file is {len} bytes, over the {max_bytes} byte limit",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    if let Err(err) = file
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
    {
        return Err(finding_for_io(path, source, &err));
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(read_finding(
            source,
            format!(
                "cannot read {}: the file is over the {max_bytes} byte limit",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

/// Open for reading.
///
/// On Unix, `O_NONBLOCK` is added so a fifo cannot block. Linux and Android
/// use `0o4000`. macOS, iOS, FreeBSD, NetBSD, OpenBSD and DragonFly use
/// `0x0004`.
fn open_read(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const O_NONBLOCK: i32 = 0o4000;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    const O_NONBLOCK: i32 = 0x0004;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::File::open(path)
    }
}

/// Classify a path whose open failed.
///
/// `metadata` follows symlinks, so a link to a directory is still a directory.
/// The open error is kept when the path is missing, is a regular file, or
/// cannot be inspected.
fn finding_for_failed_open(path: &Path, source: EvidenceSource, err: &std::io::Error) -> Finding {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => read_finding(
            source,
            format!("cannot read {}: is a directory", path.display()),
        ),
        Ok(meta) if !meta.is_file() => read_finding(
            source,
            format!(
                "cannot read {}: not a regular file, save the output to a file first",
                path.display()
            ),
        ),
        _ => finding_for_io(path, source, err),
    }
}

fn read_finding(source: EvidenceSource, text: String) -> Finding {
    Finding::new(
        Code::InsufficientEvidence,
        Confidence::High,
        vec![Evidence { source, text }],
    )
}

fn finding_for_io(path: &Path, source: EvidenceSource, err: &std::io::Error) -> Finding {
    finding_for_io_kind(source, &path.display().to_string(), err)
}

fn decode_log_bytes(what: &str, bytes: &[u8]) -> Result<DecodedLog, Finding> {
    if let Some(encoding) = wide_text_encoding(bytes) {
        return Err(wide_encoding_finding(what, encoding, EvidenceSource::Log));
    }
    let bytes = without_utf8_bom(bytes);
    let (text, replaced_invalid_utf8_bytes) = utf8_with_replacement(bytes);
    Ok(DecodedLog {
        text,
        replaced_invalid_utf8_bytes,
    })
}

/// Timer status and certificate dates: same wide-encoding check as a log, then strict UTF-8.
pub fn read_strict_text(
    path: &Path,
    max_bytes: u64,
    source: EvidenceSource,
) -> Result<String, Finding> {
    let bytes = read_regular_bytes(path, max_bytes, source)?;
    if let Some(encoding) = wide_text_encoding(&bytes) {
        return Err(wide_encoding_finding(
            &path.display().to_string(),
            encoding,
            source,
        ));
    }
    let bytes = without_utf8_bom(&bytes);
    match std::str::from_utf8(bytes) {
        Ok(text) => Ok(text.to_string()),
        Err(_) => Err(read_finding(
            source,
            format!(
                "cannot read {}: the file is not valid UTF-8",
                path.display()
            ),
        )),
    }
}

fn without_utf8_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
}

/// UTF-16 or UTF-32 at the start of `bytes`.
///
/// A BOM wins. Without a BOM, the first 64 bytes must be a pure ASCII-range
/// NUL pattern for at least 32 bytes. UTF-32 is tested first: its ASCII form
/// also has a zero in every other byte, so it would otherwise look like UTF-16.
/// One NUL, or a few invalid bytes, does not match.
// `as_chunks` is unstable on Rust 1.85. Stable Clippy still asks for it.
#[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
fn wide_text_encoding(bytes: &[u8]) -> Option<WideEncoding> {
    if bytes.starts_with(&[0x00, 0x00, 0xFE, 0xFF]) {
        return Some(WideEncoding::Utf32Be);
    }
    if bytes.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) {
        return Some(WideEncoding::Utf32Le);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return Some(WideEncoding::Utf16Be);
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return Some(WideEncoding::Utf16Le);
    }
    let window = bytes.len().min(WIDE_PREFIX_LEN);
    if window < WIDE_PATTERN_MIN {
        return None;
    }
    let sample = &bytes[..window - (window % 4)];
    if sample
        .chunks_exact(4)
        .all(|group| group[0] != 0 && group[1] == 0 && group[2] == 0 && group[3] == 0)
    {
        return Some(WideEncoding::Utf32Le);
    }
    if sample
        .chunks_exact(4)
        .all(|group| group[0] == 0 && group[1] == 0 && group[2] == 0 && group[3] != 0)
    {
        return Some(WideEncoding::Utf32Be);
    }
    if sample
        .chunks_exact(2)
        .all(|group| group[0] != 0 && group[1] == 0)
    {
        return Some(WideEncoding::Utf16Le);
    }
    if sample
        .chunks_exact(2)
        .all(|group| group[0] == 0 && group[1] != 0)
    {
        return Some(WideEncoding::Utf16Be);
    }
    None
}

fn wide_encoding_finding(what: &str, encoding: WideEncoding, source: EvidenceSource) -> Finding {
    read_finding(
        source,
        format!(
            "cannot read {what}: the file is {}; save it as UTF-8",
            encoding.label()
        ),
    )
}

/// One U+FFFD per invalid sequence. The count is the number of invalid bytes, not the number of replacement characters.
fn utf8_with_replacement(bytes: &[u8]) -> (String, usize) {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return (text.to_string(), 0);
    }
    let mut text = String::with_capacity(bytes.len());
    let mut replaced = 0usize;
    for chunk in bytes.utf8_chunks() {
        text.push_str(chunk.valid());
        let invalid = chunk.invalid();
        if !invalid.is_empty() {
            replaced += invalid.len();
            text.push('\u{FFFD}');
        }
    }
    (text, replaced)
}

pub fn finding_for_read_error(path: &Path, err: &std::io::Error) -> Finding {
    finding_for_io(path, EvidenceSource::Log, err)
}

#[derive(Default)]
struct ProblemSet {
    problems: Vec<AcmeProblem>,
    index: HashMap<(String, String), usize>,
    earliest_at: Vec<Option<String>>,
    earliest_line: Vec<usize>,
}

impl ProblemSet {
    fn add(&mut self, new: AcmeProblem) {
        let key = (new.short_type().to_string(), new.detail.clone());
        if let Some(&idx) = self.index.get(&key) {
            let earlier = is_earlier(
                &new.logged_at,
                new.line,
                &self.earliest_at[idx],
                self.earliest_line[idx],
            );
            let existing = &mut self.problems[idx];
            if existing.identifier.is_none() {
                existing.identifier.clone_from(&new.identifier);
            }
            if earlier {
                existing.first_line = new.line;
            }
            if by_recency(&new, existing).is_gt() {
                existing.line = new.line;
                existing.logged_at.clone_from(&new.logged_at);
            }
            if new.depth > existing.depth {
                existing.depth = new.depth;
            }
            existing.json_hits += new.json_hits;
            existing.summary_hits += new.summary_hits;
            existing.occurrences += new.occurrences;
            if earlier {
                self.earliest_at[idx].clone_from(&new.logged_at);
                self.earliest_line[idx] = new.line;
            }
        } else {
            let idx = self.problems.len();
            self.earliest_at.push(new.logged_at.clone());
            self.earliest_line.push(new.line);
            self.index.insert(key, idx);
            self.problems.push(new);
        }
    }
}

/// Earliest timestamp wins. Equal timestamps (or no timestamps) keep the lowest line.
fn is_earlier(
    new_at: &Option<String>,
    new_line: usize,
    old_at: &Option<String>,
    old_line: usize,
) -> bool {
    match new_at.cmp(old_at) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => new_line < old_line,
    }
}

fn summary_of(
    line: &str,
    type_line: &str,
    detail_line: &str,
    line_no: usize,
) -> Option<AcmeProblem> {
    let identifier = summary_identifier(line)?;
    let type_token = summary_type(type_line)?;
    let detail = summary_detail(detail_line)?;
    Some(AcmeProblem {
        problem_type: full_problem_type(&type_token),
        detail,
        identifier: Some(identifier),
        line: line_no,
        first_line: line_no,
        depth: 0,
        occurrences: 1,
        json_hits: 0,
        summary_hits: 1,
        logged_at: None,
    })
}

fn two_following_lines(rest: &str) -> Option<(&str, &str)> {
    let (first, after_first) = next_line(rest)?;
    let (second, _) = next_line(after_first)?;
    Some((first, second))
}

fn next_line(rest: &str) -> Option<(&str, &str)> {
    if rest.is_empty() {
        None
    } else {
        Some(split_line(rest))
    }
}

fn split_line(text: &str) -> (&str, &str) {
    match text.split_once('\n') {
        Some((line, rest)) => (strip_cr(line), rest),
        None => (strip_cr(text), ""),
    }
}

fn strip_cr(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

fn skip_hits_through(hits: &[AcmeProblem], hit_at: &mut usize, line_no: usize) {
    while *hit_at < hits.len() && hits[*hit_at].line <= line_no {
        *hit_at += 1;
    }
}

/// The latest timestamp wins. With no timestamp, or with equal timestamps, the bottom line wins.
/// Depth is not part of this order: it only picks the diagnosis among different errors.
fn by_recency(left: &AcmeProblem, right: &AcmeProblem) -> Ordering {
    left.logged_at
        .cmp(&right.logged_at)
        .then(left.line.cmp(&right.line))
}

/// Latest timestamp, then a nested subproblem, then the bottom line.
/// Depth comes before the line so a parent `type` placed after `subproblems`
/// does not hide the nested error.
fn diagnosis_order(left: &AcmeProblem, right: &AcmeProblem) -> Ordering {
    left.logged_at
        .cmp(&right.logged_at)
        .then(left.depth.cmp(&right.depth))
        .then(left.line.cmp(&right.line))
}

/// `YYYY-MM-DD HH:MM:SS,mmm` before the colon of FILE_FMT (Certbot log.py r.47).
fn log_stamp(line: &str) -> Option<&str> {
    is_log_line(line).then(|| &line[..23])
}

fn summary_identifier(line: &str) -> Option<String> {
    let value = line
        .strip_prefix("  Domain:")
        .or_else(|| line.strip_prefix("  Identifier:"))?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn summary_type(line: &str) -> Option<String> {
    let value = line.strip_prefix("  Type:")?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn summary_detail(line: &str) -> Option<String> {
    let value = line.strip_prefix("  Detail:")?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn full_problem_type(type_token: &str) -> String {
    if type_token.starts_with("urn:") {
        type_token.to_string()
    } else {
        format!("{ACME_ERROR_PREFIX}{type_token}")
    }
}

/// Nesting deeper than this is not stored. Keys inside it are not ACME fields.
const MAX_JSON_DEPTH: usize = 64;

/// `type` and `detail` belong to one JSON object. Field order does not matter.
/// A field in a nested object, or after this object's `}`, is not this object's field.
/// The same key twice with the same value counts as one. Two different values,
/// of any JSON kind, are ambiguous.
struct OpenObject {
    problem_type: Option<String>,
    type_line: usize,
    type_order: u64,
    detail: Option<String>,
    seen_type: Option<FieldValue>,
    seen_detail: Option<FieldValue>,
    type_conflict: bool,
    detail_conflict: bool,
    depth: u32,
}

/// A decoded string, or the byte span of a non-string JSON value.
///
/// A `Nested` object/array value's end is *not* found here: finding it
/// requires a scan of the whole value, and doing that eagerly for every
/// `"type"`/`"detail"` key is what used to make a log with N levels of
/// `{"detail": {"detail": ...}}` cost O(N * size) instead of O(size) (one
/// full extra scan, plus a clone, per level). The span is resolved lazily,
/// in `other_value_text`, only when a second occurrence of the same key in
/// the same object needs to be compared against it.
#[derive(Clone)]
enum FieldValue {
    String(String),
    Nested(usize),
    Token(usize, usize),
}

/// The text of a non-string field value, found lazily. `Nested`'s end is
/// only scanned for here, on comparison — not once per enclosing level.
fn other_value_text<'a>(text: &'a str, value: &FieldValue) -> Option<&'a str> {
    match *value {
        FieldValue::Nested(start) => {
            let end = json_value_end(text, start)?;
            text.get(start..end)
        }
        FieldValue::Token(start, end) => text.get(start..end),
        FieldValue::String(_) => None,
    }
}

/// The same key twice with the same value counts as one; this is how that
/// value equality is decided, including the lazy `Nested` lookup above.
fn field_values_equal(text: &str, left: &FieldValue, right: &FieldValue) -> bool {
    match (left, right) {
        (FieldValue::String(left), FieldValue::String(right)) => left == right,
        (FieldValue::String(_), _) | (_, FieldValue::String(_)) => false,
        _ => match (other_value_text(text, left), other_value_text(text, right)) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        },
    }
}

struct PendingHit {
    order: u64,
    problem: AcmeProblem,
}

struct JsonScan {
    hits: Vec<AcmeProblem>,
    ambiguous: bool,
}

/// One pass over the log. Hits are sparse. The object stack stops at
/// `MAX_JSON_DEPTH`, so a file of braces does not allocate one vector per line.
fn scan_json(text: &str) -> JsonScan {
    let mut stack: Vec<OpenObject> = Vec::new();
    let mut extra_depth = 0usize;
    let mut hits: Vec<PendingHit> = Vec::new();
    let mut ambiguous = false;
    let mut order = 0u64;
    let mut line = 1usize;
    let mut index = 0usize;
    while index < text.len() {
        let Some(ch) = text[index..].chars().next() else {
            break;
        };
        if ch == '"' {
            if let Some((key, key_end)) = parse_json_string(text, index) {
                let key_line = line;
                let after_key_line = line + count_newlines(text, index, key_end);
                let mut look_line = after_key_line;
                let colon_at = skip_ws_nl(text, key_end, &mut look_line);
                if text.as_bytes().get(colon_at) == Some(&b':') {
                    let mut value_line = look_line;
                    let value_at = skip_ws_nl(text, colon_at + 1, &mut value_line);
                    if extra_depth == 0 && (key == "type" || key == "detail") {
                        if let Some(top) = stack.last_mut() {
                            apply_field(top, &key, text, value_at, key_line, &mut order);
                        }
                    }
                    if text.as_bytes().get(value_at) == Some(&b'"') {
                        if let Some((_, value_end)) = parse_json_string(text, value_at) {
                            line = value_line + count_newlines(text, value_at, value_end);
                            index = value_end;
                            continue;
                        }
                        // A broken string is not consumed. Scanning resumes after the key.
                        line = after_key_line;
                        index = key_end;
                        continue;
                    }
                    // An array or object is scanned again from its first byte.
                    line = value_line;
                    index = value_at;
                    continue;
                }
                line = after_key_line;
                index = key_end;
                continue;
            }
            index += 1;
            continue;
        }
        match ch {
            '{' => {
                if extra_depth > 0 || stack.len() >= MAX_JSON_DEPTH {
                    extra_depth += 1;
                } else {
                    let depth = stack.len() as u32 + 1;
                    stack.push(empty_object(depth));
                }
                index += 1;
            }
            '}' => {
                if extra_depth > 0 {
                    extra_depth -= 1;
                } else if let Some(obj) = stack.pop() {
                    finish_json_object(obj, &mut hits, &mut ambiguous);
                }
                index += 1;
            }
            '\n' => {
                line += 1;
                index += 1;
            }
            _ => index += ch.len_utf8(),
        }
    }
    for obj in stack {
        finish_json_object(obj, &mut hits, &mut ambiguous);
    }
    hits.sort_by(|left, right| {
        left.problem
            .line
            .cmp(&right.problem.line)
            .then(left.order.cmp(&right.order))
    });
    JsonScan {
        hits: hits.into_iter().map(|hit| hit.problem).collect(),
        ambiguous,
    }
}

fn empty_object(depth: u32) -> OpenObject {
    OpenObject {
        problem_type: None,
        type_line: 0,
        type_order: 0,
        detail: None,
        seen_type: None,
        seen_detail: None,
        type_conflict: false,
        detail_conflict: false,
        depth,
    }
}

fn apply_field(
    obj: &mut OpenObject,
    key: &str,
    text: &str,
    value_at: usize,
    key_line: usize,
    order: &mut u64,
) {
    let parsed = field_value(text, value_at);
    if key == "type" {
        note_type(text, obj, parsed, key_line, order);
    } else if key == "detail" {
        note_detail(text, obj, parsed);
    }
}

fn note_type(
    text: &str,
    obj: &mut OpenObject,
    parsed: Option<FieldValue>,
    key_line: usize,
    order: &mut u64,
) {
    match parsed {
        Some(FieldValue::String(value)) => {
            if obj.problem_type.is_none() && value.starts_with(ACME_ERROR_PREFIX) {
                *order += 1;
                obj.problem_type = Some(value.clone());
                obj.type_line = key_line;
                obj.type_order = *order;
            }
            remember(
                text,
                &mut obj.seen_type,
                &mut obj.type_conflict,
                FieldValue::String(value),
            );
        }
        Some(other) => remember(text, &mut obj.seen_type, &mut obj.type_conflict, other),
        None => {
            if obj.seen_type.is_some() {
                obj.type_conflict = true;
            }
        }
    }
}

fn note_detail(text: &str, obj: &mut OpenObject, parsed: Option<FieldValue>) {
    match parsed {
        Some(FieldValue::String(value)) => {
            if obj.seen_detail.is_none() {
                obj.detail = Some(value.clone());
            }
            remember(
                text,
                &mut obj.seen_detail,
                &mut obj.detail_conflict,
                FieldValue::String(value),
            );
        }
        Some(other) => remember(text, &mut obj.seen_detail, &mut obj.detail_conflict, other),
        None => {
            if obj.seen_detail.is_some() {
                obj.detail_conflict = true;
            }
        }
    }
}

/// The first value is kept. A later different value marks the field as a conflict.
fn remember(text: &str, slot: &mut Option<FieldValue>, conflict: &mut bool, value: FieldValue) {
    match slot {
        Some(existing) if !field_values_equal(text, existing, &value) => *conflict = true,
        Some(_) => {}
        None => *slot = Some(value),
    }
}

fn field_value(text: &str, start: usize) -> Option<FieldValue> {
    match text.as_bytes().get(start) {
        Some(b'"') => {
            let (value, _) = parse_json_string(text, start)?;
            Some(FieldValue::String(value))
        }
        // An object/array value's end is not scanned for here: `scan_json`'s
        // main loop is about to walk it anyway. Finding it eagerly, once per
        // nesting level, is what used to multiply cost by nesting depth.
        Some(b'{') | Some(b'[') => Some(FieldValue::Nested(start)),
        // Short tokens (numbers, `true`/`false`/`null`, unreadable text)
        // cost nothing to bound eagerly, and keep `None` for an empty/broken
        // value exact for cases that can still have a later occurrence to
        // compare against.
        _ => {
            let end = json_value_end(text, start)?;
            Some(FieldValue::Token(start, end))
        }
    }
}

/// End index of one JSON value. Strings are skipped. `None` when the value is unreadable.
fn json_value_end(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if start >= bytes.len() {
        return None;
    }
    match bytes[start] {
        b'"' => parse_json_string(text, start).map(|(_, end)| end),
        b'{' | b'[' => {
            let mut depth = 0i32;
            let mut index = start;
            while index < text.len() {
                let ch = text[index..].chars().next()?;
                match ch {
                    '"' => {
                        let (_, end) = parse_json_string(text, index)?;
                        index = end;
                    }
                    '{' | '[' => {
                        depth += 1;
                        index += 1;
                    }
                    '}' | ']' => {
                        depth -= 1;
                        index += 1;
                        if depth == 0 {
                            return Some(index);
                        }
                    }
                    _ => index += ch.len_utf8(),
                }
            }
            None
        }
        _ => {
            let mut index = start;
            while index < text.len() {
                let ch = text[index..].chars().next()?;
                if matches!(ch, ' ' | '\t' | '\r' | '\n' | ',' | '}' | ']') {
                    break;
                }
                index += ch.len_utf8();
            }
            if index == start {
                None
            } else {
                Some(index)
            }
        }
    }
}

fn finish_json_object(obj: OpenObject, hits: &mut Vec<PendingHit>, ambiguous: &mut bool) {
    if obj.problem_type.is_some() && (obj.type_conflict || obj.detail_conflict) {
        *ambiguous = true;
        return;
    }
    if let Some(problem_type) = obj.problem_type {
        hits.push(PendingHit {
            order: obj.type_order,
            problem: AcmeProblem {
                problem_type,
                detail: obj.detail.unwrap_or_default(),
                identifier: None,
                line: obj.type_line,
                first_line: obj.type_line,
                depth: obj.depth,
                logged_at: None,
                occurrences: 1,
                json_hits: 1,
                summary_hits: 0,
            },
        });
    }
}

fn count_newlines(text: &str, from: usize, to: usize) -> usize {
    text.get(from..to)
        .map(|slice| slice.bytes().filter(|byte| *byte == b'\n').count())
        .unwrap_or(0)
}

fn skip_ws_nl(text: &str, mut index: usize, line: &mut usize) -> usize {
    while index < text.len() {
        let Some(ch) = text[index..].chars().next() else {
            break;
        };
        match ch {
            ' ' | '\t' | '\r' => index += ch.len_utf8(),
            '\n' => {
                *line += 1;
                index += 1;
            }
            _ => break,
        }
    }
    index
}

pub(crate) fn parse_json_string(text: &str, quote_at: usize) -> Option<(String, usize)> {
    if !text[quote_at..].starts_with('"') {
        return None;
    }
    let rest_start = quote_at + 1;
    let mut out = String::new();
    let mut chars = text[rest_start..].char_indices();
    while let Some((offset, ch)) = chars.next() {
        match ch {
            '"' => return Some((out, rest_start + offset + 1)),
            '\\' => {
                let escaped = chars.next()?.1;
                match escaped {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    'b' => out.push('\u{0008}'),
                    'f' => out.push('\u{000c}'),
                    'u' => {
                        let Some(code) = read_hex4(&mut chars) else {
                            // A broken escape is one unknown character, not a lost object.
                            out.push('\u{FFFD}');
                            continue;
                        };
                        if (0xD800..=0xDBFF).contains(&code) {
                            // A high surrogate pairs with a following \uDC00-\uDFFF.
                            // Anything else leaves it alone and it becomes U+FFFD.
                            let mut ahead = chars.clone();
                            let low = match (ahead.next(), ahead.next()) {
                                (Some((_, '\\')), Some((_, 'u'))) => read_hex4(&mut ahead)
                                    .filter(|low| (0xDC00..=0xDFFF).contains(low)),
                                _ => None,
                            };
                            match low {
                                Some(low) => {
                                    chars = ahead;
                                    let pair = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                                    out.push(char::from_u32(pair).unwrap_or('\u{FFFD}'));
                                }
                                None => out.push('\u{FFFD}'),
                            }
                        } else {
                            out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                        }
                    }
                    _ => return None,
                }
            }
            _ => out.push(ch),
        }
    }
    None
}

/// Reads up to four hex digits. Stops before any other character, so a broken
/// escape never swallows the closing quote; fewer than four digits is `None`.
fn read_hex4(chars: &mut std::str::CharIndices<'_>) -> Option<u32> {
    let mut code = 0;
    for _ in 0..4 {
        let mut ahead = chars.clone();
        let digit = ahead.next().and_then(|(_, ch)| ch.to_digit(16))?;
        *chars = ahead;
        code = code * 16 + digit;
    }
    Some(code)
}

fn is_certbot_line(line: &str) -> bool {
    if !is_log_line(line) {
        return false;
    }
    let Some(after_level) = strip_level(&line[24..]) else {
        return false;
    };
    let Some((name, _)) = after_level.split_once(':') else {
        return false;
    };
    !name.is_empty()
        && !name.contains(' ')
        && (name.starts_with("certbot") || name.starts_with("acme"))
}

fn strip_level(rest: &str) -> Option<&str> {
    for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] {
        if let Some(after) = rest.strip_prefix(level) {
            return after.strip_prefix(':');
        }
    }
    None
}

fn is_log_line(line: &str) -> bool {
    let bytes = line.as_bytes();
    if bytes.len() < 24 {
        return false;
    }
    let digits =
        |start: usize, len: usize| bytes[start..start + len].iter().all(u8::is_ascii_digit);
    digits(0, 4)
        && bytes[4] == b'-'
        && digits(5, 2)
        && bytes[7] == b'-'
        && digits(8, 2)
        && bytes[10] == b' '
        && digits(11, 2)
        && bytes[13] == b':'
        && digits(14, 2)
        && bytes[16] == b':'
        && digits(17, 2)
        && bytes[19] == b','
        && digits(20, 3)
        && bytes[23] == b':'
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::model::{ClientKind, Report, Snapshot};

    use super::*;

    #[test]
    fn summary_detail_rejects_a_blank_value_like_its_siblings() {
        assert_eq!(summary_detail("  Detail:"), None);
        assert_eq!(summary_detail("  Detail:   "), None);
        assert_eq!(
            summary_detail("  Detail: rate limited"),
            Some("rate limited".to_string())
        );
    }

    struct RemoveTempDir {
        path: PathBuf,
    }

    impl Drop for RemoveTempDir {
        fn drop(&mut self) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o700));
            }
            let _ = std::fs::remove_dir(&self.path);
        }
    }

    /// Linux CI records the real uid in `/proc`. Other Unix targets have no
    /// such file; `false` then means a mode `000` directory must fail `open`.
    #[cfg(unix)]
    fn running_as_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .any(|line| {
                line.strip_prefix("Uid:")
                    .and_then(|rest| rest.split_whitespace().next())
                    .is_some_and(|uid| uid == "0")
            })
    }

    fn report_with(finding: Finding) -> Report {
        Report {
            snapshot: Snapshot {
                domain: None,
                all: false,
                client: ClientKind::Auto,
                from_log: None,
                from_timer_status: None,
                from_cert_disk: None,
                from_cert_live: None,
            },
            findings: vec![finding],
            replaced_invalid_utf8_bytes: 0,
        }
    }

    #[test]
    fn unescapes_quote_and_backslash_in_detail() {
        let text = r#"
{
  "type": "urn:ietf:params:acme:error:connection",
  "detail": "say \"hi\" and C:\\temp"
}
"#;
        let problems = parse(text);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].detail, "say \"hi\" and C:\\temp");
        assert_eq!(problems[0].short_type(), "connection");
    }

    #[test]
    fn unescapes_solidus_newline_tab_and_unicode() {
        let text = r#"
{
  "type": "urn:ietf:params:acme:error:connection",
  "detail": "a\/b\n\t\u0041"
}
"#;
        let problems = parse(text);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].detail, "a/b\n\tA");
    }

    fn detail_with(escape: &str) -> Vec<AcmeProblem> {
        let text = format!(
            "{{\"type\": \"urn:ietf:params:acme:error:connection\", \"detail\": \"a{escape}b\"}}\n"
        );
        parse(&text)
    }

    #[test]
    fn surrogate_pair_escape_is_decoded() {
        let problems = detail_with(r"\uD83D\uDE00");
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].detail, "a\u{1F600}b");
    }

    #[test]
    fn lone_surrogate_escapes_become_replacement_characters() {
        for escape in [r"\uD83D", r"\uDE00", r"\uD83Dx", r"\uD83D\u0041"] {
            let problems = detail_with(escape);
            assert_eq!(problems.len(), 1, "{escape}");
            assert!(
                problems[0].detail.contains('\u{FFFD}'),
                "{escape}: {:?}",
                problems[0].detail
            );
        }
        let problems = detail_with(r"\uD83D\u0041");
        assert_eq!(problems[0].detail, "a\u{FFFD}Ab");
    }

    #[test]
    fn broken_unicode_escapes_become_replacement_characters() {
        // The test text ends in `b"`; `b` is a hex digit, so each escape stops on a
        // non-hex character first.
        for escape in [r"\uZZZZ", r"\u00x", r"\u12G4", r"\u-"] {
            let problems = detail_with(escape);
            assert_eq!(problems.len(), 1, "{escape}");
            assert!(
                problems[0].detail.contains('\u{FFFD}'),
                "{escape}: {:?}",
                problems[0].detail
            );
            assert!(
                problems[0].detail.ends_with('b'),
                "{escape}: {:?}",
                problems[0].detail
            );
        }
    }

    #[test]
    fn broken_unicode_escape_in_type_keeps_the_object() {
        let text = "{\"detail\": \"x\", \"type\": \"urn:ietf:params:acme:error:conn\\u00\"}\n";
        let problems = parse(text);
        assert_eq!(problems.len(), 1);
        assert!(
            problems[0].problem_type.contains('\u{FFFD}'),
            "{:?}",
            problems[0].problem_type
        );
    }

    const TIMEOUT_DETAIL: &str = "http://example.com/.well-known/acme-challenge/test: Timeout during connect (likely firewall problem)";

    fn connection_object(detail_first: bool) -> String {
        let detail = format!("\"detail\": \"{TIMEOUT_DETAIL}\"");
        let kind = "\"type\": \"urn:ietf:params:acme:error:connection\"";
        if detail_first {
            format!("{{{detail}, {kind}}}")
        } else {
            format!("{{{kind}, {detail}}}")
        }
    }

    #[test]
    fn detail_before_type_in_one_compact_object_is_kept() {
        let problems = parse(&connection_object(true));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].short_type(), "connection");
        assert_eq!(problems[0].detail, TIMEOUT_DETAIL);
    }

    #[test]
    fn type_before_detail_in_one_compact_object_is_kept() {
        let problems = parse(&connection_object(false));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].detail, TIMEOUT_DETAIL);
    }

    #[test]
    fn detail_before_type_in_a_multiline_object_is_kept() {
        let text = format!(
            "{{\n  \"detail\": \"{TIMEOUT_DETAIL}\",\n  \"type\": \"urn:ietf:params:acme:error:connection\"\n}}\n"
        );
        let problems = parse(&text);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].detail, TIMEOUT_DETAIL);
        assert_eq!(problems[0].line, 3);
    }

    #[test]
    fn detail_in_a_later_object_is_not_paired_with_an_earlier_type() {
        let text = format!(
            "{{\"type\": \"urn:ietf:params:acme:error:connection\"}}\n{{\"detail\": \"{TIMEOUT_DETAIL}\"}}"
        );
        let problems = parse(&text);
        assert!(
            problems
                .iter()
                .all(|problem| !problem.detail.contains("Timeout during connect")),
            "{problems:?}"
        );
    }

    #[test]
    fn nested_objects_keep_their_own_type_and_detail() {
        let text = format!(
            "{{\"type\": \"urn:ietf:params:acme:error:malformed\", \"detail\": \"outer\", \"sub\": {{\"detail\": \"{TIMEOUT_DETAIL}\", \"type\": \"urn:ietf:params:acme:error:connection\"}}}}"
        );
        let problems = parse(&text);
        let connection = problems
            .iter()
            .find(|problem| problem.short_type() == "connection")
            .expect("nested connection");
        assert_eq!(connection.detail, TIMEOUT_DETAIL);
        let outer = problems
            .iter()
            .find(|problem| problem.short_type() == "malformed")
            .expect("outer object");
        assert_eq!(outer.detail, "outer");
    }

    #[test]
    fn multiline_nested_detail_before_type_stays_in_that_object() {
        let text = format!(
            "{{\n  \"type\": \"urn:ietf:params:acme:error:malformed\",\n  \"detail\": \"outer\",\n  \"sub\": {{\n    \"detail\": \"{TIMEOUT_DETAIL}\",\n    \"type\": \"urn:ietf:params:acme:error:connection\"\n  }}\n}}\n"
        );
        let problems = parse(&text);
        let connection = problems
            .iter()
            .find(|problem| problem.short_type() == "connection")
            .expect("nested connection");
        assert_eq!(connection.detail, TIMEOUT_DETAIL);
        let outer = problems
            .iter()
            .find(|problem| problem.short_type() == "malformed")
            .expect("outer object");
        assert_eq!(outer.detail, "outer");
    }

    #[test]
    fn conflicting_json_type_is_not_parsed() {
        let text = format!(
            "{{\"type\": \"urn:ietf:params:acme:error:connection\", \"detail\": \"{TIMEOUT_DETAIL}\", \"type\": \"urn:ietf:params:acme:error:malformed\"}}"
        );
        let parsed = parse_log(&text);
        assert!(parsed.ambiguous_json);
        assert!(
            parsed.problems.is_empty(),
            "different type values must not become a problem: {:?}",
            parsed.problems
        );
    }

    #[test]
    fn conflicting_json_detail_is_not_parsed() {
        let text = format!(
            "{{\"detail\": \"{TIMEOUT_DETAIL}\", \"detail\": \"other detail\", \"type\": \"urn:ietf:params:acme:error:connection\"}}"
        );
        let parsed = parse_log(&text);
        assert!(parsed.ambiguous_json);
        assert!(
            parsed.problems.is_empty(),
            "different detail values must not become a problem: {:?}",
            parsed.problems
        );
    }

    #[test]
    fn non_acme_type_then_different_acme_type_is_not_parsed() {
        let text = format!(
            "{{\"type\": \"http-01\", \"type\": \"urn:ietf:params:acme:error:connection\", \"detail\": \"{TIMEOUT_DETAIL}\"}}"
        );
        let parsed = parse_log(&text);
        assert!(parsed.ambiguous_json);
        assert!(
            parsed.problems.is_empty(),
            "a later ACME type must not win over a different earlier type: {:?}",
            parsed.problems
        );
    }

    #[test]
    fn conflicting_json_type_does_not_drop_a_later_object() {
        let text = format!(
            "{{\"type\": \"urn:ietf:params:acme:error:connection\", \"detail\": \"{TIMEOUT_DETAIL}\", \"type\": \"urn:ietf:params:acme:error:malformed\"}}\n{{\"type\": \"urn:ietf:params:acme:error:rateLimited\", \"detail\": \"too many\"}}"
        );
        let parsed = parse_log(&text);
        assert!(parsed.ambiguous_json);
        assert_eq!(parsed.problems.len(), 1, "{:?}", parsed.problems);
        assert_eq!(parsed.problems[0].short_type(), "rateLimited");
        assert_eq!(parsed.problems[0].detail, "too many");
    }

    #[test]
    fn nested_detail_conflict_keeps_the_outer_object() {
        let text = format!(
            "{{\"type\": \"urn:ietf:params:acme:error:malformed\", \"detail\": \"outer\", \"sub\": {{\"type\": \"urn:ietf:params:acme:error:connection\", \"detail\": \"{TIMEOUT_DETAIL}\", \"detail\": \"other\"}}}}"
        );
        let parsed = parse_log(&text);
        assert!(parsed.ambiguous_json);
        assert_eq!(parsed.problems.len(), 1, "{:?}", parsed.problems);
        assert_eq!(parsed.problems[0].short_type(), "malformed");
        assert_eq!(parsed.problems[0].detail, "outer");
    }

    #[test]
    fn conflicting_json_does_not_drop_a_clear_summary() {
        let text = format!(
            "{{\"type\": \"urn:ietf:params:acme:error:connection\", \"detail\": \"{TIMEOUT_DETAIL}\", \"detail\": \"other\"}}\n  Domain: example.com\n  Type:   connection\n  Detail: {TIMEOUT_DETAIL}\n"
        );
        let parsed = parse_log(&text);
        assert!(parsed.ambiguous_json);
        assert_eq!(parsed.problems.len(), 1, "{:?}", parsed.problems);
        assert_eq!(parsed.problems[0].json_hits, 0);
        assert_eq!(parsed.problems[0].summary_hits, 1);
        assert_eq!(parsed.problems[0].detail, TIMEOUT_DETAIL);
    }

    #[test]
    fn repeated_json_type_with_the_same_value_is_kept() {
        let text = format!(
            "{{\"type\": \"urn:ietf:params:acme:error:connection\", \"type\": \"urn:ietf:params:acme:error:connection\", \"detail\": \"{TIMEOUT_DETAIL}\"}}"
        );
        let parsed = parse_log(&text);
        assert!(!parsed.ambiguous_json);
        assert_eq!(parsed.problems.len(), 1, "{:?}", parsed.problems);
        assert_eq!(parsed.problems[0].short_type(), "connection");
        assert_eq!(parsed.problems[0].detail, TIMEOUT_DETAIL);
    }

    #[test]
    fn repeated_json_detail_with_the_same_value_is_kept() {
        let text = format!(
            "{{\"detail\": \"{TIMEOUT_DETAIL}\", \"detail\": \"{TIMEOUT_DETAIL}\", \"type\": \"urn:ietf:params:acme:error:connection\"}}"
        );
        let parsed = parse_log(&text);
        assert!(!parsed.ambiguous_json);
        assert_eq!(parsed.problems.len(), 1, "{:?}", parsed.problems);
        assert_eq!(parsed.problems[0].short_type(), "connection");
        assert_eq!(parsed.problems[0].detail, TIMEOUT_DETAIL);
    }

    #[test]
    fn non_acme_duplicate_keys_stay_ignored() {
        let text = r#"{ "type": "http-01", "detail": "one", "detail": "two" }"#;
        let parsed = parse_log(text);
        assert!(!parsed.ambiguous_json);
        assert!(parsed.problems.is_empty());
    }

    #[test]
    fn ignores_http01_and_dns_types() {
        let text = r#"
{ "type": "http-01", "detail": "ignore me" }
{ "type": "dns", "detail": "ignore me too" }
"#;
        assert!(parse(text).is_empty());
    }

    #[test]
    fn domain_and_identifier_forms_set_identifier() {
        let domain = "  Domain: example.com\n  Type:   connection\n  Detail: from domain\n";
        let from_domain = parse(domain);
        assert_eq!(from_domain.len(), 1);
        assert_eq!(from_domain[0].identifier.as_deref(), Some("example.com"));
        assert_eq!(from_domain[0].short_type(), "connection");
        assert_eq!(from_domain[0].detail, "from domain");
        assert_eq!(
            from_domain[0].problem_type,
            "urn:ietf:params:acme:error:connection"
        );

        let identifier =
            "  Identifier: example.com\n  Type:   connection\n  Detail: from identifier\n";
        let from_identifier = parse(identifier);
        assert_eq!(from_identifier.len(), 1);
        assert_eq!(
            from_identifier[0].identifier.as_deref(),
            Some("example.com")
        );
        assert_eq!(from_identifier[0].detail, "from identifier");
    }

    #[test]
    fn json_and_summary_of_the_same_error_are_one_find() {
        let text = "\
{
  \"type\": \"urn:ietf:params:acme:error:connection\",
  \"detail\": \"same detail\"
}
  Domain: example.com
  Type:   connection
  Detail: same detail
";
        let problems = parse(text);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].short_type(), "connection");
        assert_eq!(problems[0].detail, "same detail");
        assert_eq!(problems[0].identifier.as_deref(), Some("example.com"));
        assert_eq!(problems[0].first_line, 2);
        assert_eq!(problems[0].line, 5);
        assert_eq!(problems[0].json_hits, 1);
        assert_eq!(problems[0].summary_hits, 1);
        assert_eq!(problems[0].occurrences, 2);
        assert_eq!(problems[0].attempts(), 1);
    }

    #[test]
    fn empty_text_has_no_finds() {
        assert!(parse("").is_empty());
    }

    #[test]
    fn read_error_is_insufficient_evidence_exit_two() {
        let path = Path::new("tests/fixtures/certbot/letsencrypt.log");
        let denied = finding_for_read_error(
            path,
            &std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        );
        assert_eq!(denied.code, Code::InsufficientEvidence);
        assert_eq!(denied.layer, None);
        assert_eq!(denied.confidence, Confidence::High);
        assert_eq!(denied.evidence.len(), 1);
        assert_eq!(denied.evidence[0].source, EvidenceSource::Log);
        assert_eq!(
            denied.evidence[0].text,
            "cannot read tests/fixtures/certbot/letsencrypt.log: PermissionDenied"
        );
        assert_eq!(report_with(denied).exit_status().code(), 2);

        let missing = finding_for_read_error(
            path,
            &std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        );
        assert_eq!(missing.code, Code::InsufficientEvidence);
        assert_eq!(missing.layer, None);
        assert_eq!(
            missing.evidence[0].text,
            "cannot read tests/fixtures/certbot/letsencrypt.log: NotFound"
        );
        assert_eq!(report_with(missing).exit_status().code(), 2);
    }

    #[test]
    fn read_log_missing_file_is_insufficient_evidence() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/certbot/does-not-exist.log");
        let err = read_log(&path).unwrap_err();
        assert_eq!(err.code, Code::InsufficientEvidence);
        assert_eq!(err.layer, None);
        assert_eq!(err.evidence[0].source, EvidenceSource::Log);
        assert_eq!(
            err.evidence[0].text,
            format!("cannot read {}: NotFound", path.display())
        );
    }

    /// A directory must say `is a directory` even when `open` fails before the
    /// handle check. Windows fails that open with `PermissionDenied`. Unix opens
    /// a searchable directory, so the search bit is cleared first and `open`
    /// fails the same way. Root ignores that bit and still takes the handle check.
    #[test]
    fn directory_open_failure_says_is_a_directory() {
        let path =
            std::env::temp_dir().join(format!("acme-renew-doctor-open-dir-{}", std::process::id()));
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|err| panic!("mkdir {}: {err}", path.display()));
        let _cleanup = RemoveTempDir { path: path.clone() };

        // On Unix a readable directory opens, and fstat would report it. Clear
        // the search bit so this test takes the open-failure path. Windows
        // already refuses to open a directory.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
                .unwrap_or_else(|err| panic!("chmod {}: {err}", path.display()));
        }
        let opened = open_read(&path);
        #[cfg(not(unix))]
        assert!(
            opened.is_err(),
            "opening a directory must fail so metadata classifies it"
        );
        #[cfg(unix)]
        if !running_as_root() {
            assert!(
                opened.is_err(),
                "mode 000 directory must fail open so metadata classifies it"
            );
        }

        let expected = format!("cannot read {}: is a directory", path.display());
        let from_bytes = read_regular_bytes(&path, LOG_MAX_BYTES, EvidenceSource::Log).unwrap_err();
        assert_eq!(from_bytes.code, Code::InsufficientEvidence);
        assert_eq!(from_bytes.layer, None);
        assert_eq!(from_bytes.evidence.len(), 1);
        assert_eq!(from_bytes.evidence[0].source, EvidenceSource::Log);
        assert_eq!(from_bytes.evidence[0].text, expected);

        let from_log = read_log(&path).unwrap_err();
        assert_eq!(from_log.evidence[0].text, expected);
    }

    #[test]
    fn has_certbot_lines_accepts_fixtures_and_rejects_other_logs() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/certbot");
        let mut logs = 0;
        for entry in std::fs::read_dir(&dir).expect("certbot fixtures") {
            let path = entry.expect("entry").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("log") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read fixture");
            assert!(has_certbot_lines(&text), "{}", path.display());
            logs += 1;
        }
        assert_eq!(logs, 7);

        let acme_sh = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/acme-sh/verify-error-dns01.log"),
        )
        .expect("acme.sh fixture");
        assert!(!has_certbot_lines(&acme_sh));
        assert!(!has_certbot_lines(""));
        assert!(!has_certbot_lines("   \n\n  "));
        assert!(!has_certbot_lines(
            "2026-9-28 03:12:44,512:DEBUG:acme.client:Received response:\n"
        ));
        assert!(!has_certbot_lines(
            "2026-09-28 03:12:44,512:DEBUG:urllib3.connectionpool:Starting new HTTP connection\n"
        ));

        let timeout = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/certbot/http01-timeout.log"),
        )
        .expect("timeout fixture");
        let first = timeout.lines().next().expect("first line");
        assert!(has_certbot_lines(&format!("{first}\r\n")));
    }

    #[test]
    fn invalid_utf8_counts_bytes_not_replacement_characters() {
        let (text, count) = utf8_with_replacement(&[b'a', 0xFF, b'b', 0xE9, 0x80, b'c']);
        assert_eq!(count, 3);
        assert_eq!(text.chars().filter(|ch| *ch == '\u{FFFD}').count(), 2);
        assert_eq!(text, "a\u{FFFD}b\u{FFFD}c");
        let (clean, none) = utf8_with_replacement(b"ok\0");
        assert_eq!(none, 0);
        assert_eq!(clean, "ok\0");
    }

    #[test]
    fn wide_encoding_follows_bom_then_a_long_nul_pattern() {
        assert_eq!(
            wide_text_encoding(&[0xFF, 0xFE, 0x61, 0x00]),
            Some(WideEncoding::Utf16Le)
        );
        assert_eq!(
            wide_text_encoding(&[0xFE, 0xFF, 0x00, 0x61]),
            Some(WideEncoding::Utf16Be)
        );
        assert_eq!(
            wide_text_encoding(&[0xFF, 0xFE, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00]),
            Some(WideEncoding::Utf32Le)
        );
        assert_eq!(
            wide_text_encoding(&[0x00, 0x00, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0x61]),
            Some(WideEncoding::Utf32Be)
        );
        assert_eq!(wide_text_encoding(&[0xEF, 0xBB, 0xBF, b'a']), None);

        let mut utf16le = Vec::new();
        for _ in 0..16 {
            utf16le.extend_from_slice(&[b'A', 0x00]);
        }
        assert_eq!(wide_text_encoding(&utf16le), Some(WideEncoding::Utf16Le));
        assert_eq!(wide_text_encoding(&utf16le[..30]), None);

        let mut utf32be = Vec::new();
        for _ in 0..8 {
            utf32be.extend_from_slice(&[0x00, 0x00, 0x00, b'A']);
        }
        assert_eq!(wide_text_encoding(&utf32be), Some(WideEncoding::Utf32Be));

        assert_eq!(wide_text_encoding(&[0u8; 64]), None);
        let mut utf8 = b"2026-09-28 03:12:44,512:DEBUG:certbot".to_vec();
        utf8.insert(0, 0x00);
        utf8.extend_from_slice(&[0xFF, b'x', 0xE9]);
        assert_eq!(wide_text_encoding(&utf8), None);
    }

    #[test]
    fn json_value_end_reads_a_quoted_string_past_an_embedded_comma() {
        // The `_` (bare-token) branch would stop at the first comma; only
        // the dedicated `"` arm knows a comma inside quotes is not a break.
        assert_eq!(json_value_end(r#""a, b" rest"#, 0), Some(6));
    }

    #[test]
    fn json_value_end_reads_a_nested_object_past_an_embedded_brace_breaker() {
        assert_eq!(json_value_end("{\"a\":1} rest", 0), Some(7));
        assert_eq!(json_value_end("[1,[2,3],4] rest", 0), Some(11));
    }

    #[test]
    fn json_value_end_is_none_at_or_past_the_end_of_text() {
        assert_eq!(json_value_end("abc", 3), None);
        assert_eq!(json_value_end("abc", 4), None);
    }

    #[test]
    fn json_value_end_skips_a_brace_hidden_inside_a_nested_string() {
        // Without its own quote-skipping, the brace/bracket depth counter
        // would count the `{` inside the string value as real nesting and
        // never see the object close.
        assert_eq!(json_value_end("{\"a\":\"x{y\"}rest", 0), Some(11));
    }

    #[test]
    fn json_value_end_is_none_for_an_unterminated_object() {
        assert_eq!(json_value_end("{\"a\":1", 0), None);
    }

    #[test]
    fn json_value_end_bare_token_breaking_immediately_is_none() {
        assert_eq!(json_value_end(",x", 0), None);
        assert_eq!(json_value_end("true, more", 0), Some(4));
    }

    #[test]
    fn json_value_end_bare_token_running_to_the_end_of_text_is_its_length() {
        // No breaker character at all: the loop bound itself, not a match
        // arm, is what ends the scan.
        assert_eq!(json_value_end("true", 0), Some(4));
    }

    #[test]
    fn is_log_line_requires_every_field_not_just_one() {
        // All fields but the year are valid; a chain of `&&` mutated to `||`
        // anywhere after the corrupted year would still accept this line.
        assert!(!is_log_line("202X-09-28 03:12:44,512:"));
        // Exactly 24 bytes and otherwise well-formed must be accepted (a
        // `<` to `<=` mutant on the length guard would reject it outright).
        assert!(is_log_line("2026-09-28 03:12:44,512:"));
        assert!(!is_log_line(&"2026-09-28 03:12:44,512:"[..23]));
    }

    #[test]
    fn is_earlier_breaks_ties_by_line_not_by_defaulting_to_either_answer() {
        let a = Some("x".to_string());
        let b = Some("y".to_string());
        assert!(is_earlier(&a, 1, &b, 1));
        assert!(!is_earlier(&b, 1, &a, 1));
        // Equal timestamps: the lower line is earlier, and a tie (same
        // line) is not earlier than itself.
        assert!(is_earlier(&a, 1, &a, 2));
        assert!(!is_earlier(&a, 2, &a, 1));
        assert!(!is_earlier(&a, 2, &a, 2));
    }

    #[test]
    fn problem_set_add_keeps_the_deeper_depth_regardless_of_arrival_order() {
        fn problem(depth: u32, line: usize) -> AcmeProblem {
            AcmeProblem {
                problem_type: "urn:ietf:params:acme:error:connection".to_string(),
                detail: "same".to_string(),
                identifier: None,
                line,
                first_line: line,
                depth,
                logged_at: None,
                occurrences: 1,
                json_hits: 1,
                summary_hits: 0,
            }
        }
        let mut shallow_first = ProblemSet::default();
        shallow_first.add(problem(0, 1));
        shallow_first.add(problem(3, 2));
        assert_eq!(shallow_first.problems[0].depth, 3);

        let mut deep_first = ProblemSet::default();
        deep_first.add(problem(3, 1));
        deep_first.add(problem(0, 2));
        assert_eq!(
            deep_first.problems[0].depth, 3,
            "a later, shallower duplicate must not erase the deeper depth"
        );
    }

    #[test]
    fn skip_hits_through_advances_past_every_hit_at_or_before_the_line() {
        let hits = vec![
            AcmeProblem {
                line: 1,
                ..Default::default()
            },
            AcmeProblem {
                line: 2,
                ..Default::default()
            },
            AcmeProblem {
                line: 5,
                ..Default::default()
            },
        ];
        let mut hit_at = 0;
        skip_hits_through(&hits, &mut hit_at, 3);
        assert_eq!(hit_at, 2);
    }

    #[test]
    fn read_regular_bytes_accepts_a_file_exactly_at_the_byte_limit() {
        let dir = std::env::temp_dir().join(format!(
            "acme-renew-doctor-exact-limit-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("exact.txt");
        std::fs::write(&path, vec![b'x'; 10]).expect("write");
        let ok = read_regular_bytes(&path, 10, EvidenceSource::Log);
        assert!(ok.is_ok(), "{ok:?}");
        assert_eq!(ok.unwrap().len(), 10);
        let over = read_regular_bytes(&path, 9, EvidenceSource::Log).unwrap_err();
        assert!(over.evidence[0].text.contains("over the 9 byte limit"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_capped_accepts_input_within_the_limit() {
        let bytes = read_capped(
            std::io::Cursor::new(b"hello".to_vec()),
            10,
            EvidenceSource::Log,
            "standard input",
        )
        .expect("within the limit");
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn read_capped_rejects_input_over_the_limit() {
        let err = read_capped(
            std::io::Cursor::new(vec![0u8; 11]),
            10,
            EvidenceSource::Log,
            "standard input",
        )
        .unwrap_err();
        assert_eq!(
            err.evidence[0].text,
            "cannot read standard input: over the 10 byte limit"
        );
    }

    #[cfg(unix)]
    #[test]
    fn finding_for_failed_open_names_a_fifo_as_not_a_regular_file() {
        let dir = std::env::temp_dir().join(format!(
            "acme-renew-doctor-fifo-open-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo")
            .success());
        let err = std::io::Error::other("stand-in");
        let finding = finding_for_failed_open(&path, EvidenceSource::Log, &err);
        assert!(
            finding.evidence[0]
                .text
                .contains("not a regular file, save the output to a file first"),
            "{}",
            finding.evidence[0].text
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wide_text_encoding_checks_the_whole_rounded_window_not_a_shorter_one() {
        // 14 clean UTF-16LE pairs (28 bytes), then 8 bytes that break the
        // pattern, then one more byte (37 total, matching the window the
        // 32-byte minimum and `window - (window % 4)` rounding would use).
        // A window computed with `/` instead of `%` would stop short of the
        // break and misread this as UTF-16LE.
        let mut bytes = Vec::new();
        for _ in 0..14 {
            bytes.extend_from_slice(&[0x41, 0x00]);
        }
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        bytes.push(0);
        assert_eq!(bytes.len(), 37);
        assert_eq!(wide_text_encoding(&bytes), None);
    }

    #[test]
    fn backspace_and_form_feed_escapes_are_decoded() {
        assert_eq!(
            parse_json_string(r#""a\bc""#, 0),
            Some(("a\u{0008}c".to_string(), 6))
        );
        assert_eq!(
            parse_json_string(r#""a\fc""#, 0),
            Some(("a\u{000c}c".to_string(), 6))
        );
    }

    #[test]
    fn count_newlines_counts_only_within_the_given_range() {
        assert_eq!(count_newlines("a\nb\nc", 0, 5), 2);
        assert_eq!(count_newlines("a\nb\nc", 2, 5), 1);
        assert_eq!(count_newlines("a\nb\nc", 0, 0), 0);
    }

    #[test]
    fn skip_ws_nl_counts_newlines_and_stops_at_the_first_non_space() {
        let mut line = 1usize;
        let index = skip_ws_nl("\n\n  x", 0, &mut line);
        assert_eq!(line, 3);
        assert_eq!(index, 4);
        let mut line_at_end = 1usize;
        let index_at_end = skip_ws_nl("   ", 0, &mut line_at_end);
        assert_eq!(index_at_end, 3);
        assert_eq!(line_at_end, 1);
    }

    #[test]
    fn utf8_bom_is_skipped_and_one_bad_byte_is_counted() {
        let decoded = decode_log_bytes("log", b"\xEF\xBB\xBFhello").expect("utf-8 bom");
        assert_eq!(decoded.text, "hello");
        assert_eq!(decoded.replaced_invalid_utf8_bytes, 0);

        let decoded = decode_log_bytes("log", b"ab\xFFcd").expect("one bad byte");
        assert_eq!(decoded.replaced_invalid_utf8_bytes, 1);
        assert!(decoded.text.contains('\u{FFFD}'));

        let err = decode_log_bytes("log", &[0xFF, 0xFE, b'A', 0x00]).unwrap_err();
        assert!(err.evidence[0].text.contains("UTF-16LE"));
        assert!(err.evidence[0].text.contains("save it as UTF-8"));
        assert!(!err.evidence[0].text.contains("other kind"));
    }
}
