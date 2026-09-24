//! The one canonicalizer: from what a server reports about a request to its target.
//!
//! The token and the server must describe a request identically, or a check compares
//! two different things. So there is exactly one canonicalizer, [`canonicalize`], and
//! both observing and checking go through it.
//!
//! **The standard.** RFC 9110 §4.2.3 says when two URIs are equivalent: the scheme and
//! host compare case-insensitively, an absent port equals the scheme's default, and
//! everything else compares exactly. RFC 3986 §6 agrees (§6.2.2.1 for case, §6.2.3 for
//! the default port), and RFC 9421 uses the same subset for `@scheme`, `@authority`,
//! `@path` and `@method`. So the standards *permit* folding the scheme's and the host's
//! case.
//!
//! **The policy.** Within the canonicalizer, the main way an exact-match allowlist
//! fails open is a merge: two requests a real server keeps apart getting one target.
//! Real routers do keep host case apart even though RFC 9110 permits folding it: Go's
//! `net/http` `ServeMux` matches a pattern's host byte for byte, so `example.com/admin`
//! and `EXAMPLE.COM/admin` can be routed to different handlers. So the canonicalizer
//! folds nothing. A scheme, host or IPv6 literal that is not already lowercase is
//! denied, like every other input that is not already canonical. The one thing it fills
//! in is the scheme's default port, and only when no port is given. A false denial is
//! the accepted cost.
//!
//! **The rule set is pinned by the caveat kind.** A stored caveat is valid only if it
//! reads back through these rules to the same bytes (see `format.rs`), so the `http`
//! caveat kind in a `v1` token means "an HTTP target under this rule set". That makes
//! the two directions of change different:
//!
//! - **Tightening a rule is safe.** A caveat sealed under the old rules that the new
//!   rules deny no longer reads back, so the whole token denies (`MalformedToken`). A
//!   tightening can cause false denials, never a new allow.
//! - **Widening a rule is not.** Accepting or folding something that is denied today
//!   would silently widen what every existing token allows, with no change to its bytes.
//!   So a widening needs a new caveat kind, never an edit to a rule here.
//!
//! **Every canonicalization rule lives in this file, and nowhere else.** The rest of
//! the crate sees only [`canonicalize`], [`write_authority`] and the byte limits: the
//! token format checks a stored caveat by running it back through `canonicalize`, and
//! observe, learn, seal and check never look at a rule. So this rule set can be
//! replaced wholesale by rewriting this one file and the conformance vectors, under a new
//! caveat kind if it widens anything.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::target::{HttpTarget, RequestFacts, Target};
use crate::Denial;

/// The longest method accepted, in bytes. The longest registered HTTP method
/// (`UPDATEREDIRECTREF`) is 17 bytes.
pub const MAX_METHOD_BYTES: usize = 32;

/// The longest scheme accepted, in bytes. Only `http` and `https` are supported; the
/// limit exists so even a wrong scheme is bounded before it is read.
pub const MAX_SCHEME_BYTES: usize = 16;

/// The longest authority accepted, in bytes: the longest host, a colon and a
/// five-digit port. A longer authority is denied (`RequestTooLong`) before it is read.
pub const MAX_AUTHORITY_BYTES: usize = MAX_HOST_BYTES + 6;

/// The longest host, in bytes: the longest DNS name in text form (RFC 1035 §2.3.4).
/// A longer host inside an authority that fits [`MAX_AUTHORITY_BYTES`] is only found
/// once the authority is split, so it is denied as `MalformedHost`, not
/// `RequestTooLong`. Also what keeps a sealed caveat's authority inside
/// [`MAX_AUTHORITY_BYTES`], so every caveat `seal` writes can be read back.
const MAX_HOST_BYTES: usize = 253;

/// The longest path accepted, in bytes, counting the query too, since the field holds
/// both as the server received them.
pub const MAX_PATH_BYTES: usize = 4096;

/// The schemes the canonicalizer supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    /// RFC 9110 §4.2.1 and §4.2.2.
    fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

/// Turns what a server reports about a request into the request's target, or denies.
///
/// This is the only canonicalizer. `gate::observe` and `gate::check` both call it, so a
/// request observed while learning and the same request checked later always get the
/// same target.
///
/// Every field is checked against its byte limit before any field is read. The fields
/// are then read in order (method, scheme, authority, path), and the first bad one
/// names the denial. No rule reads a fact from outside the request; the only rule that
/// reads a second field is the port rule, which reads the scheme to fill in a missing
/// port and to deny that default written out.
pub fn canonicalize(request: &RequestFacts) -> Result<Target, Denial> {
    if request.method.len() > MAX_METHOD_BYTES
        || request.scheme.len() > MAX_SCHEME_BYTES
        || request.authority.len() > MAX_AUTHORITY_BYTES
        || request.path.len() > MAX_PATH_BYTES
    {
        return Err(Denial::RequestTooLong);
    }

    let method = canonical_method(request.method)?;
    let scheme = canonical_scheme(request.scheme)?;
    let (host, port) = split_authority(request.authority)?;
    let host = canonical_host(host)?;
    let port = match port {
        Some(port) => canonical_port(port, scheme)?,
        None => scheme.default_port(),
    };
    let path = canonical_path(drop_query(request.path)?)?;

    Ok(Target::Http(HttpTarget::new(
        method, scheme, host, port, path,
    )))
}

/// Writes an authority back the one way [`canonicalize`] accepts it: the host, plus
/// `:port` unless the port is the scheme's default (an explicit default port is
/// denied, so writing it would not read back).
pub(crate) fn write_authority(scheme: Scheme, host: &str, port: u16) -> String {
    let mut authority = String::from(host);
    if port != scheme.default_port() {
        authority.push(':');
        authority.push_str(&port.to_string());
    }
    authority
}

/// Method: exact bytes, never case-folded (RFC 9110 §9.1: methods are case-sensitive).
/// It must be an RFC 9110 token (§5.6.2).
fn canonical_method(method: &[u8]) -> Result<String, Denial> {
    if method.is_empty() || !method.iter().all(|&byte| is_tchar(byte)) {
        return Err(Denial::MalformedMethod);
    }
    Ok(ascii_to_string(method))
}

/// RFC 9110 §5.6.2 `tchar`. Note that it excludes `;` and space, the token format's
/// two separators.
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Scheme: exactly `http` or `https`. RFC 3986 §3.1 makes the scheme case-insensitive
/// with lowercase as its canonical form, but folding `HTTPS` into `https` would be a
/// merge, so any other spelling is denied rather than lowercased.
fn canonical_scheme(scheme: &[u8]) -> Result<Scheme, Denial> {
    match scheme {
        b"http" => Ok(Scheme::Http),
        b"https" => Ok(Scheme::Https),
        _ => Err(Denial::UnsupportedScheme),
    }
}

/// Splits an authority into its host and its optional port.
///
/// User info (`user@`) is never part of a target and is denied outright (RFC 9110
/// §4.2.4 forbids it in http and https URIs). An IPv6 literal is the host up to and
/// including its closing `]`.
fn split_authority(authority: &[u8]) -> Result<(&[u8], Option<&[u8]>), Denial> {
    if authority.contains(&b'@') {
        return Err(Denial::MalformedHost);
    }
    let (host, rest) = if authority.first() == Some(&b'[') {
        let close = authority
            .iter()
            .position(|&byte| byte == b']')
            .ok_or(Denial::MalformedHost)?;
        // The host keeps its `]`; the rest starts right after it.
        let host = authority.get(..=close).ok_or(Denial::MalformedHost)?;
        let rest = authority
            .get(close..)
            .and_then(|from_close| from_close.get(1..))
            .ok_or(Denial::MalformedHost)?;
        (host, rest)
    } else {
        let host_end = authority
            .iter()
            .position(|&byte| byte == b':')
            .unwrap_or(authority.len());
        authority
            .split_at_checked(host_end)
            .ok_or(Denial::MalformedHost)?
    };
    match rest.split_first() {
        None => Ok((host, None)),
        Some((b':', port)) => Ok((host, Some(port))),
        Some(_) => Err(Denial::MalformedHost),
    }
}

/// Host: kept exactly, never case-folded. RFC 3986 §3.2.2 makes a host
/// case-insensitive, but a router may not fold it (Go's `net/http` `ServeMux` matches
/// it byte for byte), so a host that is not already lowercase is denied, not lowercased.
///
/// - A name may use lowercase ASCII letters, digits, `-`, `_` and `.`, and every
///   dot-separated label must be non-empty, which rules out an empty host and a
///   trailing dot (a name with and without a trailing dot can resolve differently).
///   Uppercase is denied. Non-ASCII is denied: an international name must arrive as
///   punycode.
/// - A name whose last label is a number (the WHATWG URL Standard's "ends in a number":
///   all digits, or `0x` and hex digits) is read as an IPv4 address by browsers and
///   many resolvers, in decimal, octal or hex, with 1 to 4 parts. So it must be exactly
///   a dotted quad (four decimal parts, 0 to 255, no leading zeros), the one spelling
///   everyone reads the same way. `127.1`, `0x7f.0.0.1`, `2130706433` and `256.0.0.1`
///   are denied.
/// - An IPv6 literal must be in brackets and already in RFC 5952 text form, lowercase
///   hex included: `[::1]` and `[2001:db8::1]`, never `[0::1]`, `[0:0:0:0:0:0:0:1]` or
///   `[2001:DB8::1]`. Forms with an embedded IPv4 part and zone ids are denied.
/// - At most 253 bytes (`MAX_HOST_BYTES`).
fn canonical_host(host: &[u8]) -> Result<String, Denial> {
    if host.len() > MAX_HOST_BYTES {
        return Err(Denial::MalformedHost);
    }
    let valid = match host
        .strip_prefix(b"[")
        .and_then(|rest| rest.strip_suffix(b"]"))
    {
        Some(ipv6) => is_canonical_ipv6(ipv6),
        None => is_host_name(host) && (!ends_in_number(host) || is_dotted_quad(host)),
    };
    if !valid {
        return Err(Denial::MalformedHost);
    }
    Ok(ascii_to_string(host))
}

/// Lowercase ASCII letters, digits, `-`, `_` and `.`, with no empty label.
fn is_host_name(host: &[u8]) -> bool {
    host.iter().all(|&byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
    }) && host
        .split(|&byte| byte == b'.')
        .all(|label| !label.is_empty())
}

/// The WHATWG URL Standard's "ends in a number" for a host with no empty label: the
/// last label is all ASCII digits, or `0x`/`0X` followed by hex digits (none at all
/// counts too: WHATWG reads `0x` as zero). Case-insensitive, as WHATWG defines it,
/// although an uppercase host is denied before this is asked.
fn ends_in_number(host: &[u8]) -> bool {
    let last = host.rsplit(|&byte| byte == b'.').next().unwrap_or_default();
    match last {
        [b'0', b'x' | b'X', hex @ ..] => hex.iter().all(u8::is_ascii_hexdigit),
        _ => !last.is_empty() && last.iter().all(u8::is_ascii_digit),
    }
}

/// Exactly four decimal parts, each 0 to 255 with no leading zero: the one IPv4
/// spelling every parser reads the same way.
fn is_dotted_quad(host: &[u8]) -> bool {
    let is_octet = |part: &[u8]| {
        matches!(part.len(), 1..=3)
            && part.iter().all(u8::is_ascii_digit)
            && (part.len() == 1 || part.first() != Some(&b'0'))
            && decimal_value(part).is_some_and(|value| value <= 255)
    };
    let mut parts = host.split(|&byte| byte == b'.');
    parts.clone().count() == 4 && parts.all(is_octet)
}

/// Whether the text inside the brackets is an IPv6 address written exactly the way
/// RFC 5952 §4 writes it, lowercase hex included. Only hex groups and one `::` are
/// read, so an embedded IPv4 part or a zone id is denied.
fn is_canonical_ipv6(text: &[u8]) -> bool {
    parse_ipv6(text).is_some_and(|groups| write_ipv6(&groups).as_bytes() == text)
}

/// Reads up to eight 16-bit groups, with at most one `::` standing for zero groups.
/// This is deliberately loose (it reads either hex case, for one): [`is_canonical_ipv6`]
/// then requires the text to be exactly what [`write_ipv6`] writes for the result,
/// which rejects every malformed or non-canonical text (uppercase hex, too many or too
/// few groups, a second `::`, a `::` that stands for one group). `None` only where
/// reading could not even produce groups.
fn parse_ipv6(text: &[u8]) -> Option<[u16; 8]> {
    let (head, tail) = match text.windows(2).position(|pair| pair == b"::") {
        Some(at) => (
            text.get(..at)?,
            text.get(at..)
                .and_then(|from_colons| from_colons.get(2..))?,
        ),
        None => (text, &[][..]),
    };
    let head = parse_ipv6_groups(head)?;
    let tail = parse_ipv6_groups(tail)?;
    let mut groups = [0u16; 8];
    for (slot, group) in groups.iter_mut().zip(&head) {
        *slot = *group;
    }
    for (slot, group) in groups.iter_mut().rev().zip(tail.iter().rev()) {
        *slot = *group;
    }
    Some(groups)
}

/// Reads `:`-separated groups of 1 to 4 hex digits (so each fits in 16 bits). The
/// empty text is no groups.
fn parse_ipv6_groups(text: &[u8]) -> Option<Vec<u16>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    let mut groups = Vec::new();
    for group in text.split(|&byte| byte == b':') {
        if !matches!(group.len(), 1..=4) {
            return None;
        }
        let mut value = 0u16;
        for &digit in group {
            value = value
                .checked_mul(16)?
                .checked_add(u16::from(hex_digit_value(digit)?))?;
        }
        groups.push(value);
    }
    Some(groups)
}

/// RFC 5952 §4: lowercase hex, no leading zeros, and the longest run of two or more
/// zero groups (the first, on a tie) written as `::`.
fn write_ipv6(groups: &[u16; 8]) -> String {
    // The longest run of zero groups and where it starts; the first wins a tie.
    let (mut best_start, mut best_len) = (0, 0);
    for start in 0..groups.len() {
        let run = groups
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take_while(|&&group| group == 0)
            .count();
        if run > best_len {
            (best_start, best_len) = (start, run);
        }
    }
    let join = |groups: &[u16]| {
        groups
            .iter()
            .map(|group| alloc::format!("{group:x}"))
            .collect::<Vec<String>>()
            .join(":")
    };
    if best_len < 2 {
        return join(groups);
    }
    let head = groups.get(..best_start).unwrap_or_default();
    let tail = groups
        .get(best_start..)
        .and_then(|from_run| from_run.get(best_len..))
        .unwrap_or_default();
    alloc::format!("{}::{}", join(head), join(tail))
}

/// Port: one to five digits, no leading zero (which also rules out port 0), at most
/// 65535, and not the scheme's default. An explicit default (`:443` on https) is
/// denied rather than merged with no port: the default is filled in only when the port
/// is absent (RFC 3986 §6.2.3 prefers omitting it). An empty port after a colon is
/// denied rather than read as "default".
fn canonical_port(port: &[u8], scheme: Scheme) -> Result<u16, Denial> {
    let well_formed = !port.is_empty()
        && port.len() <= 5
        && port.iter().all(u8::is_ascii_digit)
        && port.first() != Some(&b'0');
    if !well_formed {
        return Err(Denial::MalformedPort);
    }
    match decimal_value(port).and_then(|value| u16::try_from(value).ok()) {
        Some(value) if value != scheme.default_port() => Ok(value),
        _ => Err(Denial::MalformedPort),
    }
}

/// Drops the query: it is never part of a target. A fragment is never sent in a request
/// target (RFC 9112 §3.2), so a `#` anywhere means something upstream is confused, and
/// it denies.
fn drop_query(path_and_query: &[u8]) -> Result<&[u8], Denial> {
    if path_and_query.contains(&b'#') {
        return Err(Denial::MalformedPath);
    }
    Ok(path_and_query
        .split(|&byte| byte == b'?')
        .next()
        .unwrap_or_default())
}

/// Path: compared exactly, byte for byte, with no transformation at all. Everything
/// that is not already in its one canonical spelling, or that servers read
/// differently, is denied:
///
/// - It must start with `/`.
/// - Only these bytes may appear as-is: letters, digits, `- . _ ~`, and
///   `! $ & ' ( ) * + , = : @ /`. Everything else must be percent-encoded, and some
///   things are denied even then (below). `;` is denied because some frameworks strip
///   `;parameters` before routing and some don't; `\` because some servers treat it
///   as `/`.
/// - A `%` must be followed by two **uppercase** hex digits. RFC 3986 §6.2.2.1 says
///   `%c3` and `%C3` are equal, but a server that routes on the raw path keeps them
///   apart, so lowercase hex is denied rather than uppercased.
/// - An encoded `/` (`%2F`), `\` (`%5C`), `%` (`%25`, double encoding), `;` (`%3B`) or
///   control byte is denied: decoding it changes the path's structure, or depends on
///   how many times a server decodes.
/// - An encoded letter, digit or `- . _ ~` is denied. RFC 3986 says it means the same
///   as the plain byte, but a server that routes on the raw path sees something else.
///   (`%2E` is in this group, which also closes encoded dot segments.)
/// - The bytes the path stands for, once every `%XX` is read as the byte it names,
///   must be well-formed UTF-8 ([`Utf8Decoder`]). An ill-formed sequence has no one
///   meaning, and real servers have decoded overlong forms back into `.`, `/` and
///   `\`, so it is denied rather than passed along.
/// - No `.` or `..` segment, and no empty segment (`//`). A trailing `/` is allowed
///   and is significant: `/a` and `/a/` are different targets.
///
/// Non-ASCII arrives percent-encoded and stays that way, compared as bytes and never
/// Unicode-normalized, so NFC and NFD spellings of a name are different targets.
fn canonical_path(path: &[u8]) -> Result<String, Denial> {
    if path.first() != Some(&b'/') {
        return Err(Denial::MalformedPath);
    }
    let mut utf8 = Utf8Decoder::new();
    let mut bytes = path.iter().copied();
    while let Some(byte) = bytes.next() {
        // The byte this position stands for: the byte itself, or the one its `%XX`
        // escape names. `None` when the position is denied on its own.
        let stands_for = if byte == b'%' {
            let high = bytes.next().and_then(uppercase_hex_value);
            let low = bytes.next().and_then(uppercase_hex_value);
            match (high, low) {
                (Some(high), Some(low)) => {
                    hex_byte(high, low).filter(|&byte| may_stay_encoded(byte))
                }
                _ => None,
            }
        } else if is_plain_path_byte(byte) {
            Some(byte)
        } else {
            None
        };
        // Every byte the path stands for goes through the decoder, so a sequence split
        // across escapes and plain bytes alike is checked as one stream.
        if !stands_for.is_some_and(|byte| utf8.push(byte)) {
            return Err(Denial::MalformedPath);
        }
    }
    // A sequence the path ends in the middle of is ill-formed too.
    if !utf8.is_complete() {
        return Err(Denial::MalformedPath);
    }
    let mut segments = path.split(|&byte| byte == b'/').skip(1).peekable();
    while let Some(segment) = segments.next() {
        let is_last = segments.peek().is_none();
        // An empty segment is fine only as the last one (a trailing `/`).
        if matches!(segment, b"." | b"..") || (segment.is_empty() && !is_last) {
            return Err(Denial::MalformedPath);
        }
    }
    Ok(ascii_to_string(path))
}

/// The WHATWG Encoding standard's
/// [UTF-8 decoder](https://encoding.spec.whatwg.org/#utf-8-decoder), as a state machine
/// fed one byte at a time.
///
/// It is written as the standard's table rather than as a list of bytes to reject,
/// because a list is always the payloads someone has already seen. `%C0%AF` (an
/// overlong `/`) is only the best-known family: `%E0%80%AF` says the same thing in
/// three bytes and `%F0%80%80%AF` in four, and both start with a lead byte a list
/// built from the two-byte payloads lets through. The table rejects all of them, plus
/// the surrogates (`%ED%A0%80`) and everything above U+10FFFF (`%F5%80%80%80`),
/// without naming a single payload.
///
/// The code point itself is never built: the boundaries below already carry every
/// rule, so tracking how many continuation bytes are still owed, and the range the
/// next one must fall in, is the whole state.
///
/// Rejecting these is also what RFC 3629 requires: a decoder must not accept an
/// overlong form, a surrogate, or a value above U+10FFFF
/// ([RFC 3629 §3](https://www.rfc-editor.org/rfc/rfc3629#section-3)).
struct Utf8Decoder {
    /// How many continuation bytes the sequence in progress still owes. Zero means no
    /// sequence is in progress.
    bytes_needed: u8,
    /// The range the next continuation byte must fall in. It is `0x80..=0xBF` except
    /// right after a lead byte that narrows it: `0xE0` (which rules out three-byte
    /// overlongs), `0xED` (surrogates), `0xF0` (four-byte overlongs) and `0xF4`
    /// (above U+10FFFF).
    lower_boundary: u8,
    upper_boundary: u8,
}

impl Utf8Decoder {
    fn new() -> Self {
        Utf8Decoder {
            bytes_needed: 0,
            lower_boundary: 0x80,
            upper_boundary: 0xBF,
        }
    }

    /// Feeds one byte. `false` as soon as the stream cannot be well-formed UTF-8; the
    /// decoder is not used again after that.
    fn push(&mut self, byte: u8) -> bool {
        if self.bytes_needed == 0 {
            let (needed, lower, upper) = match byte {
                0x00..=0x7F => return true,
                0xC2..=0xDF => (1, 0x80, 0xBF),
                0xE0 => (2, 0xA0, 0xBF),
                0xE1..=0xEC | 0xEE..=0xEF => (2, 0x80, 0xBF),
                0xED => (2, 0x80, 0x9F),
                0xF0 => (3, 0x90, 0xBF),
                0xF1..=0xF3 => (3, 0x80, 0xBF),
                0xF4 => (3, 0x80, 0x8F),
                // 0x80..=0xC1 (a stray continuation byte, or a two-byte overlong
                // lead) and 0xF5..=0xFF (above U+10FFFF) are never a lead byte.
                _ => return false,
            };
            self.bytes_needed = needed;
            self.lower_boundary = lower;
            self.upper_boundary = upper;
            return true;
        }
        if byte < self.lower_boundary || byte > self.upper_boundary {
            return false;
        }
        // Only the first continuation byte of a sequence can be narrowed; the rest of
        // them take the plain range back.
        self.lower_boundary = 0x80;
        self.upper_boundary = 0xBF;
        self.bytes_needed = self.bytes_needed.saturating_sub(1);
        true
    }

    /// Whether no sequence is half-finished, so the stream may end here.
    fn is_complete(&self) -> bool {
        self.bytes_needed == 0
    }
}

/// RFC 3986 §2.3 unreserved characters.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Bytes a path may carry without percent-encoding: RFC 3986 `pchar` and `/`, minus
/// `;`. Excludes space, `?`, `#`, `\`, `%` and every non-ASCII byte.
fn is_plain_path_byte(byte: u8) -> bool {
    is_unreserved(byte)
        || matches!(
            byte,
            b'/' | b':'
                | b'@'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b'='
        )
}

/// Whether a percent-encoded byte is kept (encoded) rather than denied.
fn may_stay_encoded(decoded: u8) -> bool {
    !(is_unreserved(decoded)
        || decoded.is_ascii_control()
        || matches!(decoded, b'/' | b'\\' | b'%' | b';'))
}

/// The byte two hex digit values stand for. `None` only if a value is not a hex digit
/// value (above 15), which the callers never pass.
fn hex_byte(high: u8, low: u8) -> Option<u8> {
    high.checked_mul(16)?.checked_add(low)
}

/// A path's percent-encoding digit: `0-9` or `A-F`. Lowercase is not canonical.
fn uppercase_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'F' => byte.checked_sub(b'A')?.checked_add(10),
        _ => decimal_digit_value(byte),
    }
}

/// An IPv6 group's digit: `0-9`, `a-f` or `A-F`. Reading uppercase here is fine:
/// [`is_canonical_ipv6`] then denies any text that is not lowercase.
fn hex_digit_value(byte: u8) -> Option<u8> {
    uppercase_hex_value(byte.to_ascii_uppercase())
}

fn decimal_digit_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => byte.checked_sub(b'0'),
        _ => None,
    }
}

/// The value of some ASCII digits, or `None` if a byte is not a digit or the value
/// does not fit in 32 bits (callers pass at most five digits, so it always fits).
fn decimal_value(digits: &[u8]) -> Option<u32> {
    digits.iter().try_fold(0u32, |sum, &digit| {
        sum.checked_mul(10)?
            .checked_add(u32::from(decimal_digit_value(digit)?))
    })
}

/// Only called on bytes already checked to be ASCII, so each byte is one `char`.
fn ascii_to_string(ascii: &[u8]) -> String {
    ascii.iter().map(|&byte| char::from(byte)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    /// The HTTP target of a request, or its denial.
    fn http(request: &RequestFacts) -> Result<HttpTarget, Denial> {
        canonicalize(request).map(|target| match target {
            Target::Http(http) => http,
        })
    }

    /// The raw request facts of a request written as text.
    fn request<'a>(
        method: &'a str,
        scheme: &'a str,
        authority: &'a str,
        path: &'a str,
    ) -> RequestFacts<'a> {
        crate::target::test_support::facts(method, scheme, authority, path)
    }

    /// The target of a GET to `https://example.com` + `path`.
    fn path_of(path: &str) -> Result<String, Denial> {
        http(&request("GET", "https", "example.com", path)).map(|t| t.path().to_string())
    }

    fn host_of(authority: &str) -> Result<String, Denial> {
        http(&request("GET", "https", authority, "/")).map(|t| t.host().to_string())
    }

    fn port_of(authority: &str) -> Result<u16, Denial> {
        http(&request("GET", "https", authority, "/")).map(|t| t.port())
    }

    // --- the whole target ---------------------------------------------------------

    #[test]
    fn a_plain_request_becomes_its_five_fields() {
        let target = http(&request("GET", "https", "example.com", "/orders/7?page=2")).unwrap();
        assert_eq!(target.method(), "GET");
        assert_eq!(target.scheme(), "https");
        assert_eq!(target.host(), "example.com");
        assert_eq!(target.port(), 443);
        assert_eq!(target.path(), "/orders/7");
    }

    // --- limits -------------------------------------------------------

    #[test]
    fn each_field_at_its_limit_is_read() {
        let method = "M".repeat(MAX_METHOD_BYTES);
        let path = "/".to_string() + &"a".repeat(MAX_PATH_BYTES - 1);
        assert!(canonicalize(&request(&method, "https", "example.com", &path)).is_ok());
        // A scheme and an authority at their limits are read (and then rejected on
        // their content, not their length).
        let scheme = "h".repeat(MAX_SCHEME_BYTES);
        assert_eq!(
            canonicalize(&request("GET", &scheme, "example.com", "/")),
            Err(Denial::UnsupportedScheme)
        );
        let authority = "a".repeat(MAX_HOST_BYTES) + ":65535";
        assert_eq!(authority.len(), MAX_AUTHORITY_BYTES);
        assert!(canonicalize(&request("GET", "https", &authority, "/")).is_ok());
    }

    #[test]
    fn host_over_253_bytes_is_denied() {
        assert!(host_of(&"a".repeat(MAX_HOST_BYTES)).is_ok());
        assert_eq!(
            host_of(&"a".repeat(MAX_HOST_BYTES + 1)),
            Err(Denial::MalformedHost)
        );
        let ipv6 = "[".to_string() + &"1:".repeat(126) + "]";
        assert_eq!(ipv6.len(), MAX_HOST_BYTES + 1);
        assert_eq!(host_of(&ipv6), Err(Denial::MalformedHost));
    }

    #[test]
    fn each_field_over_its_limit_is_denied_before_any_field_is_read() {
        // Every field is malformed, and the method (read first) denies as
        // `MalformedMethod` as soon as anything is read. So `RequestTooLong` with any
        // one field over its limit proves that field's length is checked before any
        // field is read.
        let bad = ["GE T", "ftp", "user@example.com", "/a/../b"];
        assert_eq!(
            canonicalize(&request(bad[0], bad[1], bad[2], bad[3])),
            Err(Denial::MalformedMethod)
        );
        let over_long = [
            " ".repeat(MAX_METHOD_BYTES + 1),
            "f".repeat(MAX_SCHEME_BYTES + 1),
            "@".repeat(MAX_AUTHORITY_BYTES + 1),
            "/..".repeat(MAX_PATH_BYTES),
        ];
        for (field, too_long) in over_long.iter().enumerate() {
            let mut fields = bad;
            fields[field] = too_long;
            assert_eq!(
                canonicalize(&request(fields[0], fields[1], fields[2], fields[3])),
                Err(Denial::RequestTooLong),
                "field {field}"
            );
        }
    }

    #[test]
    fn a_long_path_is_denied_even_if_the_extra_bytes_are_query() {
        let path = "/?".to_string() + &"q".repeat(MAX_PATH_BYTES);
        assert_eq!(path_of(&path), Err(Denial::RequestTooLong));
    }

    // --- method ---------------------------------------------------------------------

    #[test]
    fn method_is_kept_exactly_and_never_case_folded() {
        let target = http(&request("get", "https", "example.com", "/")).unwrap();
        assert_eq!(target.method(), "get");
        let target = http(&request("M-SEARCH", "https", "example.com", "/")).unwrap();
        assert_eq!(target.method(), "M-SEARCH");
    }

    #[test]
    fn method_may_use_every_tchar() {
        let all = "!#$%&'*+-.^_`|~09azAZ";
        let target = http(&request(all, "https", "example.com", "/")).unwrap();
        assert_eq!(target.method(), all);
    }

    #[test]
    fn method_that_is_not_a_token_is_denied() {
        for method in [
            "", "GE T", "GET;", "G\"T", "GE(T", "GÉT", "GET\n", "G/T", "G:T",
        ] {
            assert_eq!(
                canonicalize(&request(method, "https", "example.com", "/")),
                Err(Denial::MalformedMethod),
                "{method:?}"
            );
        }
    }

    // --- scheme ---------------------------------------------------------------------

    #[test]
    fn a_lowercase_scheme_is_kept() {
        for scheme in ["http", "https"] {
            let target = http(&request("GET", scheme, "example.com", "/")).unwrap();
            assert_eq!(target.scheme(), scheme);
        }
    }

    #[test]
    fn a_scheme_not_in_lowercase_is_denied_not_folded() {
        for scheme in ["HTTP", "HTTPS", "Http", "hTTpS", "httpS"] {
            assert_eq!(
                canonicalize(&request("GET", scheme, "example.com", "/")),
                Err(Denial::UnsupportedScheme),
                "{scheme:?}"
            );
        }
    }

    #[test]
    fn schemes_other_than_http_and_https_are_denied() {
        for scheme in ["", "ftp", "ws", "wss", "https:", "http ", "httpss"] {
            assert_eq!(
                canonicalize(&request("GET", scheme, "example.com", "/")),
                Err(Denial::UnsupportedScheme),
                "{scheme:?}"
            );
        }
    }

    // --- host -----------------------------------------------------------------------

    #[test]
    fn a_lowercase_host_is_kept_exactly() {
        for host in [
            "example.com",
            "my_service-2.internal",
            "127.0.0.1",
            "a-1.b_2",
        ] {
            assert_eq!(host_of(host), Ok(host.to_string()), "{host:?}");
        }
    }

    #[test]
    fn a_host_not_in_lowercase_is_denied_not_folded() {
        // A router may keep these apart from their lowercase spelling (Go's ServeMux
        // matches the host byte for byte), so folding them would be a merge.
        for host in [
            "EXAMPLE.COM",
            "Example.com",
            "example.Com",
            "exAmple.com",
            "example.coM",
            "XN--exmple-cua.com",
            "0X7F.example",
            "A",
        ] {
            assert_eq!(host_of(host), Err(Denial::MalformedHost), "{host:?}");
        }
    }

    #[test]
    fn ipv6_literal_is_kept_in_brackets() {
        assert_eq!(host_of("[::1]"), Ok("[::1]".to_string()));
        assert_eq!(
            host_of("[2001:db8::1]:8443"),
            Ok("[2001:db8::1]".to_string())
        );
        assert_eq!(port_of("[::1]:8443"), Ok(8443));
    }

    #[test]
    fn ipv6_hex_not_in_lowercase_is_denied_not_folded() {
        for literal in [
            "[2001:DB8::1]",
            "[2001:Db8::1]",
            "[FE80::1]",
            "[::ABCD]",
            "[fe80::abcD]",
            "[::FFFF:1]",
        ] {
            assert_eq!(host_of(literal), Err(Denial::MalformedHost), "{literal:?}");
        }
    }

    #[test]
    fn ipv6_in_rfc_5952_form_is_accepted() {
        for literal in [
            "[::1]",
            "[::]",
            "[1::]",
            "[2001:db8::1]",
            "[1:2:3:4:5:6:7:8]",
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]",
            // The longest run of zeros is the one compressed...
            "[1:0:0:2::3]",
            // ...and the first one on a tie.
            "[1::2:0:0:3:4]",
            // A single zero group is never compressed.
            "[1:0:2:3:4:5:6:7]",
            "[0:1:2:3:4:5:6:7]",
            "[1:2:3:4:5:6:7:0]",
            "[1:2:3:4:5:6::]",
            "[::1:2:3:4:5:6]",
            "[fe80::abcd:ef01]",
        ] {
            assert_eq!(host_of(literal), Ok(literal.to_string()), "{literal:?}");
        }
    }

    #[test]
    fn ipv6_not_in_rfc_5952_form_is_denied() {
        for literal in [
            "[0::1]",
            "[::0:1]",
            "[0:0:0:0:0:0:0:1]",
            "[0000::1]",
            "[01::1]",
            "[1:0:0:2:0:0:0:3]",
            "[1:0:0:2::0:3]",
            "[1:0:0:0:2::3]",
            "[1:2:3:4:5:6:7::]",
            "[::1:2:3:4:5:6:7]",
            "[1::0]",
            "[1:2:3:4:5:6:7:8:9]",
            "[1:2:3:4:5:6:7]",
            "[1::2::3]",
            "[:::]",
            "[:1::]",
            "[::1:]",
            "[1:]",
            "[:1]",
            "[12345::]",
            "[::ffff:192.0.2.1]",
            "[192.0.2.1::]",
            "[0:1:2:3:4:5:192.0.02.1]",
            "[fe80::1%25eth0]",
            "[::1 ]",
        ] {
            assert_eq!(host_of(literal), Err(Denial::MalformedHost), "{literal:?}");
        }
    }

    #[test]
    fn a_dotted_quad_is_an_ordinary_host() {
        for host in [
            "192.0.2.1",
            "0.0.0.0",
            "255.255.255.255",
            "1.2.3.4",
            "10.0.0.10",
            "100.200.250.9",
        ] {
            assert_eq!(host_of(host), Ok(host.to_string()), "{host:?}");
        }
    }

    #[test]
    fn a_host_that_ends_in_a_number_must_be_a_dotted_quad() {
        // Browsers and many resolvers read each of these as an IPv4 address, in
        // decimal, octal or hex, so each has more than one reading and is denied.
        for host in [
            "127",
            "88",
            "0x7f1",
            "127.1",
            "127.0.1",
            "0x7f.0.0.1",
            "0X7F.0.0.1",
            "2130706433",
            "0x",
            "0x100000000",
            "0999999999999999999",
            "256.0.0.1",
            "1.2.3.256",
            "1.2.3.999",
            "1.2.3.1000",
            "127.0.0.01",
            "127.00.0.1",
            "010.0.0.1",
            "1.2.3.4.5",
            "a.1",
            "example.0x10",
            "1.2.3.0x4",
        ] {
            assert_eq!(host_of(host), Err(Denial::MalformedHost), "{host:?}");
        }
    }

    #[test]
    fn a_name_that_only_looks_numeric_is_a_name() {
        // The last label is not a number, so nobody reads these as IPv4 addresses.
        for host in [
            "1.2.3.com",
            "0x7f.example",
            "a1",
            "1a",
            "1e3",
            "0xg",
            "0x1g",
            "1-2",
            "1_2",
        ] {
            assert_eq!(host_of(host), Ok(host.to_string()), "{host:?}");
        }
    }

    #[test]
    fn bad_hosts_are_denied() {
        let bad = [
            "",
            ":443",
            "example.com.",
            ".example.com",
            "a..b",
            "user@example.com",
            "user:pass@example.com",
            "@example.com",
            "exa mple.com",
            "exämple.com",
            "xn--exmple-cua.com%2F",
            "example.com/",
            "[::1",
            "[]",
            "[1.2.3.4]",
            "[::g]",
            "[0::1]",
            "127.1",
            "0x7f.0.0.1",
            "[::1]x",
            "[::1]]",
            "::1",
            "[v1.fe80::a]",
            "[fe80::1%25eth0]",
            "exa;mple.com",
            "*.example.com",
        ];
        for authority in bad {
            let result = canonicalize(&request("GET", "https", authority, "/"));
            assert!(
                matches!(
                    result,
                    Err(Denial::MalformedHost) | Err(Denial::MalformedPort)
                ),
                "{authority:?} gave {result:?}"
            );
        }
    }

    #[test]
    fn userinfo_is_a_host_denial_even_with_a_colon() {
        assert_eq!(host_of("user:pass@example.com"), Err(Denial::MalformedHost));
    }

    #[test]
    fn host_denials_are_host_denials() {
        for authority in [
            "",
            "example.com.",
            "a..b",
            "[::1",
            "[::1]x",
            "[]",
            "exämple.com",
            "::1",
        ] {
            assert_eq!(
                host_of(authority),
                Err(Denial::MalformedHost),
                "{authority:?}"
            );
        }
    }

    #[test]
    fn punycode_is_an_ordinary_name() {
        assert_eq!(
            host_of("xn--exmple-cua.com"),
            Ok("xn--exmple-cua.com".to_string())
        );
    }

    // --- port -----------------------------------------------------------------------

    #[test]
    fn default_port_is_filled_from_the_scheme() {
        assert_eq!(port_of("example.com"), Ok(443));
        let target = http(&request("GET", "http", "example.com", "/")).unwrap();
        assert_eq!(target.port(), 80);
    }

    #[test]
    fn explicit_default_port_is_denied() {
        // Filling the default in when the port is absent is the one right answer;
        // merging an explicit `:443` with no port is not needed, so it is denied.
        assert_eq!(
            canonicalize(&request("GET", "https", "example.com:443", "/")),
            Err(Denial::MalformedPort)
        );
        assert_eq!(
            canonicalize(&request("GET", "http", "example.com:80", "/")),
            Err(Denial::MalformedPort)
        );
        assert_eq!(
            canonicalize(&request("GET", "https", "[::1]:443", "/")),
            Err(Denial::MalformedPort)
        );
    }

    #[test]
    fn the_other_schemes_default_port_is_an_ordinary_port() {
        assert_eq!(port_of("example.com:80"), Ok(80));
        let target = http(&request("GET", "http", "example.com:443", "/")).unwrap();
        assert_eq!(target.port(), 443);
    }

    #[test]
    fn authority_is_written_back_without_the_default_port() {
        let https = |authority: &str| {
            http(&request("GET", "https", authority, "/"))
                .unwrap()
                .authority()
        };
        assert_eq!(https("example.com"), "example.com");
        assert_eq!(https("example.com:8443"), "example.com:8443");
        assert_eq!(https("example.com:80"), "example.com:80");
        assert_eq!(https("[::1]:1"), "[::1]:1");
        let target = http(&request("GET", "http", "example.com:443", "/")).unwrap();
        assert_eq!(target.authority(), "example.com:443");
        let target = http(&request("GET", "http", "example.com", "/")).unwrap();
        assert_eq!(target.authority(), "example.com");
    }

    #[test]
    fn explicit_ports_are_read() {
        assert_eq!(port_of("example.com:1"), Ok(1));
        assert_eq!(port_of("example.com:8443"), Ok(8443));
        assert_eq!(port_of("example.com:65535"), Ok(65535));
        assert_eq!(port_of("example.com:10"), Ok(10));
    }

    #[test]
    fn bad_ports_are_denied() {
        for authority in [
            "example.com:",
            "example.com:0",
            "example.com:00",
            "example.com:0443",
            "example.com:443",
            "example.com:00443",
            "example.com:65536",
            "example.com:99999",
            "example.com:100000",
            "example.com:4294967376",
            "example.com:44a",
            "example.com:+443",
            "example.com:-1",
            "example.com: 443",
            "example.com:443:443",
            "[::1]:",
            "[::1]:0",
        ] {
            assert_eq!(
                port_of(authority),
                Err(Denial::MalformedPort),
                "{authority:?}"
            );
        }
    }

    // --- path -----------------------------------------------------------------------

    #[test]
    fn query_is_dropped() {
        assert_eq!(path_of("/a?x=1"), Ok("/a".to_string()));
        assert_eq!(path_of("/a?"), Ok("/a".to_string()));
        assert_eq!(path_of("/a?x=/../;%zz"), Ok("/a".to_string()));
    }

    #[test]
    fn fragment_is_denied_even_in_the_query() {
        assert_eq!(path_of("/a#top"), Err(Denial::MalformedPath));
        assert_eq!(path_of("/a?x=1#top"), Err(Denial::MalformedPath));
    }

    #[test]
    fn path_must_start_with_a_slash() {
        for path in ["", "a", "*", "?x", "http://example.com/a", "%2Fa"] {
            assert_eq!(path_of(path), Err(Denial::MalformedPath), "{path:?}");
        }
    }

    #[test]
    fn trailing_slash_is_significant() {
        assert_eq!(path_of("/a/"), Ok("/a/".to_string()));
        assert_eq!(path_of("/a"), Ok("/a".to_string()));
        assert_eq!(path_of("/"), Ok("/".to_string()));
    }

    #[test]
    fn path_case_is_kept() {
        assert_eq!(path_of("/Orders"), Ok("/Orders".to_string()));
    }

    #[test]
    fn dot_segments_are_denied() {
        for path in [
            "/.", "/..", "/a/.", "/a/..", "/./a", "/../a", "/a/./b", "/a/../b", "/a/../",
        ] {
            assert_eq!(path_of(path), Err(Denial::MalformedPath), "{path:?}");
        }
    }

    #[test]
    fn dots_that_are_not_whole_segments_are_fine() {
        for path in ["/...", "/a.b", "/.well-known/x", "/a..", "/..a"] {
            assert_eq!(path_of(path), Ok(path.to_string()), "{path:?}");
        }
    }

    #[test]
    fn empty_segments_are_denied() {
        for path in ["//", "//a", "/a//b", "/a//"] {
            assert_eq!(path_of(path), Err(Denial::MalformedPath), "{path:?}");
        }
    }

    #[test]
    fn every_plain_path_byte_is_kept() {
        let path = "/azAZ09-._~!$&'()*+,=:@";
        assert_eq!(path_of(path), Ok(path.to_string()));
    }

    #[test]
    fn bytes_that_must_be_encoded_are_denied_as_is() {
        for path in [
            "/a b",
            "/a;b",
            "/a\\b",
            "/a\"b",
            "/a<b",
            "/a>b",
            "/a^b",
            "/a`b",
            "/a{b",
            "/a|b",
            "/a}b",
            "/a[b",
            "/a]b",
            "/a\tb",
            "/a\u{0}b",
            "/a\u{7f}b",
            "/café",
        ] {
            assert_eq!(path_of(path), Err(Denial::MalformedPath), "{path:?}");
        }
    }

    #[test]
    fn non_utf8_bytes_are_denied() {
        let raw = RequestFacts {
            method: b"GET",
            scheme: b"https",
            authority: b"example.com",
            path: b"/a\xffb",
        };
        assert_eq!(canonicalize(&raw), Err(Denial::MalformedPath));
    }

    #[test]
    fn uppercase_percent_hex_is_kept_exactly() {
        // Every escape here decodes to well-formed UTF-8.
        for path in [
            "/caf%C3%A9",
            "/a%2Ab",
            "/%E2%82%AC",
            "/%C2%AB%C2%BB",
            "/%3A%3C",
        ] {
            assert_eq!(path_of(path), Ok(path.to_string()), "{path:?}");
        }
    }

    #[test]
    fn lowercase_percent_hex_is_denied_not_uppercased() {
        // RFC 3986 calls these equal to their uppercase forms, but a server routing
        // on the raw path keeps them apart, so folding them would be a merge.
        for path in [
            "/caf%c3%a9",
            "/caf%C3%a9",
            "/caf%c3%A9",
            "/a%2ab",
            "/%e2%82%ac",
            "/%Ab",
            "/%aB",
            "/%3a",
            "/%3c",
            "/%fF",
        ] {
            assert_eq!(path_of(path), Err(Denial::MalformedPath), "{path:?}");
        }
    }

    #[test]
    fn nfc_and_nfd_are_different_targets() {
        // "é" as one code point (NFC) and as "e" + combining acute (NFD).
        assert_ne!(path_of("/caf%C3%A9"), path_of("/cafe%CC%81"));
        assert_eq!(path_of("/cafe%CC%81"), Ok("/cafe%CC%81".to_string()));
    }

    #[test]
    fn encoded_reserved_and_other_bytes_stay_encoded() {
        // Non-ASCII bytes appear here in their well-formed UTF-8 spelling.
        for path in [
            "/%20", "/%21", "/%3A", "/%3F", "/%23", "/%40", "/%2C", "/%7B", "/%C2%80", "/%C3%BF",
            "/%22",
        ] {
            assert_eq!(path_of(path), Ok(path.to_string()), "{path:?}");
        }
    }

    // --- the path decodes to well-formed UTF-8 (WHATWG Encoding, RFC 3629) ---------

    #[test]
    fn well_formed_utf8_of_every_length_is_accepted() {
        // One byte per length, plus the smallest and the largest code point each
        // length can carry, so the rule cannot be satisfied by denying all non-ASCII.
        for path in [
            "/caf%C3%A9",           // U+00E9, two bytes
            "/%C2%80",              // U+0080, the smallest two-byte code point
            "/%DF%BF",              // U+07FF, the largest
            "/%E0%A0%80",           // U+0800, the smallest three-byte code point
            "/%EF%BF%BF",           // U+FFFF, the largest
            "/%ED%9F%BF",           // U+D7FF, right below the surrogates
            "/%EE%80%80",           // U+E000, right above them
            "/%F0%90%80%80",        // U+10000, the smallest four-byte code point
            "/%F1%80%80%80",        // U+40000, a lead byte with no narrowed boundary
            "/%F3%BF%BF%BF",        // U+FFFFF, the last one before 0xF4 narrows it
            "/%F4%8F%BF%BF",        // U+10FFFF, the largest code point there is
            "/a%C3%A9b%E2%82%AC/c", // several sequences and plain bytes in one path
        ] {
            assert_eq!(path_of(path), Ok(path.to_string()), "{path:?}");
        }
    }

    #[test]
    fn overlong_encodings_are_denied_at_every_length() {
        // The whole reason the rule is the WHATWG decoder's table and not a list of
        // bytes: the published payloads are all two-byte (`%C0%AF` is IIS's overlong
        // `/`), and a list built from them lets the three- and four-byte forms of the
        // same character straight through. Each pair below is the same code point
        // written overlong and, for the accepted comparison, written the short way.
        for path in [
            "/a/..%C0%AF../b",       // overlong '/', two bytes (CVE-2000-0884)
            "/a/..%E0%80%AF../b",    // the same '/', three bytes
            "/a/..%F0%80%80%AF../b", // and four
            "/%C0%AE%C0%AE/admin",   // overlong '..'
            "/admin%C0%80",          // overlong NUL
            "/a/..%C1%9C../admin",   // overlong '\'
            "/%E0%9F%BF",            // U+07FF written in three bytes instead of two
            "/%F0%8F%BF%BF",         // U+FFFF written in four bytes instead of three
        ] {
            assert_eq!(path_of(path), Err(Denial::MalformedPath), "{path:?}");
        }
    }

    #[test]
    fn surrogates_and_code_points_above_the_maximum_are_denied() {
        for path in [
            "/a%ED%A0%80b",    // U+D800, a lone high surrogate
            "/a%ED%BF%BFb",    // U+DFFF, the last surrogate
            "/a%F4%90%80%80b", // U+110000, one past the largest code point
            "/a%F5%80%80%80b", // a lead byte no code point can use
            "/a%FF%FEb",       // a UTF-16 byte order mark, decoded as UTF-8
        ] {
            assert_eq!(path_of(path), Err(Denial::MalformedPath), "{path:?}");
        }
    }

    #[test]
    fn a_sequence_the_path_does_not_finish_is_denied() {
        for path in [
            "/a%C3",       // a two-byte sequence, one byte short, at the end
            "/a%E2%82",    // a three-byte sequence, one byte short
            "/a%F0%9F%92", // a four-byte sequence, one byte short
            "/a%C3b",      // a plain byte where a continuation byte must be
            "/a%C3/b",     // a '/' where a continuation byte must be
            "/a%E2%82b",   // the same, one byte further in
            "/a%80b",      // a continuation byte with no lead byte
            "/a%BFb",
        ] {
            assert_eq!(path_of(path), Err(Denial::MalformedPath), "{path:?}");
        }
    }

    #[test]
    fn broken_percent_encodings_are_denied() {
        for path in ["/%", "/%4", "/%G1", "/%1G", "/%%41", "/a%", "/a%2"] {
            assert_eq!(path_of(path), Err(Denial::MalformedPath), "{path:?}");
        }
    }

    #[test]
    fn encodings_that_change_meaning_are_denied() {
        for path in [
            "/a%2Fb",
            "/a%2fb",
            "/a%5Cb",
            "/a%5cb",
            "/a%25",
            "/a%2541",
            "/a%3Bb",
            "/a%3bb",
            "/a%00",
            "/a%0A",
            "/a%1F",
            "/a%7F",
            "/%2E",
            "/%2E%2E",
            "/a/%2e%2e/b",
        ] {
            assert_eq!(path_of(path), Err(Denial::MalformedPath), "{path:?}");
        }
    }

    #[test]
    fn encoded_unreserved_bytes_are_denied() {
        for path in [
            "/%61", "/%41", "/%30", "/%39", "/%7A", "/%5A", "/%2D", "/%5F", "/%7E",
        ] {
            assert_eq!(path_of(path), Err(Denial::MalformedPath), "{path:?}");
        }
    }

    #[test]
    fn neighbours_of_the_denied_encodings_are_kept() {
        // One either side of each denied range, so an off-by-one in a range shows up.
        for path in [
            "/%20", "/%2C", "/%2B", "/%3A", "/%40", "/%5B", "/%5D", "/%60", "/%7B", "/%7D", "/%24",
        ] {
            assert_eq!(path_of(path), Ok(path.to_string()), "{path:?}");
        }
    }

    #[test]
    fn canonical_fields_never_contain_the_token_separators() {
        // The token format needs no escaping because no canonical field can hold `;`
        // or a space. Pin that for every byte value, appended to every text field.
        for byte in 0u8..=255 {
            let method = [b"GET".as_slice(), &[byte]].concat();
            let authority = [b"example.com".as_slice(), &[byte]].concat();
            let path = [b"/".as_slice(), &[byte]].concat();
            let requests = [
                RequestFacts {
                    method: &method,
                    scheme: b"https",
                    authority: b"example.com",
                    path: b"/",
                },
                RequestFacts {
                    method: b"GET",
                    scheme: b"https",
                    authority: &authority,
                    path: b"/",
                },
                RequestFacts {
                    method: b"GET",
                    scheme: b"https",
                    authority: b"example.com",
                    path: &path,
                },
            ];
            for raw in requests {
                if let Ok(target) = http(&raw) {
                    let authority = target.authority();
                    for text in [target.method(), &authority, target.path()] {
                        assert!(!text.contains(';') && !text.contains(' '), "{text:?}");
                    }
                }
            }
        }
    }
}
