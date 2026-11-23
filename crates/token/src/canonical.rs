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
//! the accepted cost. The rule table is in `docs/canonicalizer.md`.
//!
//! **Folding nothing is not the same as rewriting nothing.** The rule the policy needs
//! is that the map from request to target is *injective*: apart from the dropped query,
//! two requests a real server keeps apart never get one target. A rewrite that is
//! injective and has exactly one output per input breaks no rule, and there are two of
//! them. The port rule fills in the scheme's default when no port is given (and denies
//! that default written out, so the two spellings never meet). An MCP value is
//! **percent-encoded for storage** ([`store_mcp_value`]), because the token's two
//! separators would otherwise end a caveat body early. Neither one merges anything:
//! distinct inputs still give distinct targets.
//!
//! **Two encodings meet on an MCP value, and they belong to different people.** The
//! *wire* encoding is MCP's `=?base64?…?=` sentinel: theirs, decided by them, undone on
//! the way in so the rules are applied to the value a server would compare. The
//! *storage* encoding is this file's percent-encoding: ours, applied on the way into a
//! caveat body, and invisible on the wire. A value is read through the first and stored
//! through the second, so the bytes in a caveat body are not the bytes on the wire, and
//! reading a stored caveat back goes through [`canonicalize_stored`] rather than
//! [`canonicalize`].
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
//! token format checks a stored caveat by running it back through `canonicalize_stored`, and
//! observe, learn, seal and check never look at a rule. So this rule set can be
//! replaced wholesale by rewriting this one file and the conformance vectors, under a new
//! caveat kind if it widens anything.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::target::{HttpTarget, McpTarget, RequestFacts, Target};
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

/// The longest `Mcp-Method` accepted, in bytes. MCP method names are short and fixed by
/// the protocol (`tools/call`, `resources/read`, `prompts/get`); 64 bytes is room for
/// every one of them and for a namespaced extension, and nothing longer is read.
pub const MAX_MCP_METHOD_BYTES: usize = 64;

/// The longest `Mcp-Name` accepted, in bytes, counting a base64 wrapper when there is
/// one. A tool name is only `SHOULD`-limited to 128 characters, but the same header
/// carries a `resources/read` URI, which is a full URI, so the limit is the path's
/// order of magnitude rather than the tool name's.
pub const MAX_MCP_NAME_BYTES: usize = 1024;

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
/// Every field is checked against its byte limit before any field is read, the MCP
/// fields included when the request carries them. The fields are then read in order
/// (method, scheme, authority, path, then the MCP pair), and the first bad one names
/// the denial. No rule reads a fact from outside the request; the only rule that reads
/// a second field is the port rule, which reads the scheme to fill in a missing port
/// and to deny that default written out.
///
/// Whether the request carries MCP facts decides the target's **kind**, and nothing
/// else does: `None` gives a [`Target::Http`], `Some` gives a [`Target::Mcp`]. It is
/// not a mode — the same bytes always give the same target, and no token or
/// configuration is consulted.
pub fn canonicalize(request: &RequestFacts) -> Result<Target, Denial> {
    canonicalize_fields(request, McpSpelling::Wire)
}

/// Reads a **stored** caveat's fields back: the same rules as [`canonicalize`], except
/// that the two MCP values are read in the spelling a caveat body holds them in
/// (percent-encoded, [`stored_mcp_value`]) rather than the spelling they arrive in on
/// the wire (MCP's base64 sentinel, [`canonical_mcp_value`]).
///
/// The two are the same function for every other field, and for an `http` caveat they
/// are the same function outright: only the MCP values have a storage spelling that
/// differs from their wire spelling.
///
/// It takes [`RequestFacts`] because a caveat body carries exactly the same fields a
/// request does; they are stored bytes, not received ones, which is the whole
/// difference this entry point names. `format.rs` is the only caller.
pub(crate) fn canonicalize_stored(caveat: &RequestFacts) -> Result<Target, Denial> {
    canonicalize_fields(caveat, McpSpelling::Stored)
}

/// Which spelling of an MCP value the fields being read carry. Every other field reads
/// the same either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpSpelling {
    /// As a server received it: plain, or inside MCP's base64 sentinel.
    Wire,
    /// As a caveat body holds it: percent-encoded by [`store_mcp_value`].
    Stored,
}

/// The body both entry points share.
fn canonicalize_fields(request: &RequestFacts, spelling: McpSpelling) -> Result<Target, Denial> {
    let mcp_over_limit = request.mcp.is_some_and(|mcp| {
        mcp.method.len() > MAX_MCP_METHOD_BYTES || mcp.name.len() > MAX_MCP_NAME_BYTES
    });
    if request.method.len() > MAX_METHOD_BYTES
        || request.scheme.len() > MAX_SCHEME_BYTES
        || request.authority.len() > MAX_AUTHORITY_BYTES
        || request.path.len() > MAX_PATH_BYTES
        || mcp_over_limit
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
    let http = HttpTarget::new(method, scheme, host, port, path);

    // The MCP fields are the last thing read, and whether they are there at all is what
    // decides the target's kind. One request still gives exactly one target.
    match request.mcp {
        None => Ok(Target::Http(http)),
        Some(mcp) => {
            let mcp_method = read_mcp_value(mcp.method, MAX_MCP_METHOD_BYTES, spelling)
                .ok_or(Denial::MalformedMcpMethod)?;
            let mcp_name = read_mcp_value(mcp.name, MAX_MCP_NAME_BYTES, spelling)
                .ok_or(Denial::MalformedMcpName)?;
            Ok(Target::Mcp(McpTarget::new(http, mcp_method, mcp_name)))
        }
    }
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
/// - An IPv4-mapped address (`::ffff:0:0/96`) is denied in **both** its spellings, hex
///   and dotted, because RFC 5952 does not give it one canonical text form
///   ([`is_ipv4_mapped`]).
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
/// RFC 5952 §4 writes it, lowercase hex included, and is not IPv4-mapped. Only hex
/// groups and one `::` are read, so an embedded IPv4 part or a zone id is denied.
fn is_canonical_ipv6(text: &[u8]) -> bool {
    parse_ipv6(text)
        .is_some_and(|groups| !is_ipv4_mapped(&groups) && write_ipv6(&groups).as_bytes() == text)
}

/// Whether an address carries the IPv4-mapped prefix `::ffff:0:0/96`
/// ([RFC 4291 §2.5.5.2](https://www.rfc-editor.org/rfc/rfc4291#section-2.5.5.2)).
///
/// These addresses have no single text form, so **both** spellings are denied. RFC 5952
/// §4 compresses zero groups and writes hex, which gives `[::ffff:7f00:1]`.
/// [RFC 5952 §5](https://www.rfc-editor.org/rfc/rfc5952#section-5) then recommends the
/// mixed, dotted notation for addresses with a well-known IPv4-embedding prefix, which
/// gives `[::ffff:127.0.0.1]` for the same 128 bits. §4 alone would make the hex
/// spelling canonical and the dotted one a denial; that is backwards, because the
/// dotted one is what real software writes. Rust's `std::net::Ipv6Addr` and Python's
/// `ipaddress` both serialise this prefix in the dotted form, so an adapter that reads
/// `:authority` through its language's IP type and writes it back emits the spelling
/// §4 rejects — every IPv4-mapped literal in such a deployment would be a false denial.
///
/// Accepting the dotted spelling as well would be a *widening* of a rule, which needs a new
/// caveat kind (see `docs/canonicalizer.md`). Denying both is a tightening, which is safe
/// in place: an existing token that lists one of these stops reading back and denies as a
/// whole. False denials for IPv4-mapped literals are the accepted cost, and they are the
/// same cost either spelling arrives in.
///
/// **This does not extend to the neighbouring well-known prefixes.** The NAT64 prefix
/// `64:ff9b::/96` ([RFC 6052 §2.1](https://www.rfc-editor.org/rfc/rfc6052#section-2.1))
/// is a well-known IPv4-embedding prefix too, but Rust and Python both leave it in hex,
/// so no parser disagrees about how to write it and `[64:ff9b::c000:201]` stays
/// accepted (vector `host_ipv6_nat64_prefix_kept`).
fn is_ipv4_mapped(groups: &[u16; 8]) -> bool {
    matches!(groups, [0, 0, 0, 0, 0, 0xffff, _, _])
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

/// The bytes an MCP header value carries when it is base64-wrapped, before and after
/// the payload. MCP makes these markers case-sensitive and lowercase, so `=?BASE64?`
/// never opens a wrapper. A plain value of that shape ending in `?=` is still denied,
/// because it reads as one ([`reads_as_a_wrapper`]).
const SENTINEL_OPEN: &[u8] = b"=?base64?";
const SENTINEL_CLOSE: &[u8] = b"?=";

/// Reads one MCP value in whichever spelling it arrived in.
fn read_mcp_value(raw: &[u8], limit: usize, spelling: McpSpelling) -> Option<String> {
    match spelling {
        McpSpelling::Wire => canonical_mcp_value(raw, limit),
        McpSpelling::Stored => stored_mcp_value(raw),
    }
}

/// An `Mcp-Method` or `Mcp-Name` value as a server received it, read into the one
/// spelling a caveat body stores it as.
///
/// Returns the **stored** spelling ([`store_mcp_value`]), or `None` to deny. Nothing is
/// folded: one value has one stored spelling and one wire spelling, and the map between
/// them runs both ways without loss.
///
/// **Why the sentinel has to be decoded before anything else is decided.** MCP lets a
/// value travel base64-wrapped (`=?base64?Z2V0X3dlYXRoZXI=?=`) as well as plain
/// (`get_weather`), and requires a server to decode a wrapped value before comparing it
/// with the body. Comparing the raw bytes would therefore give one destination two
/// targets, which is the merge this canonicalizer exists to prevent — and worse, it
/// would let a value that breaks the rules below arrive wrapped and be stored as if it
/// were an ordinary opaque name. So the value is decoded, the rules are applied to what
/// it decodes to, the wrapping itself is checked, and only then is the value written
/// into its stored spelling:
///
/// - **The body of the value.** Non-empty, and every byte is printable ASCII
///   (`0x20..=0x7E`). That denies a control byte and every non-ASCII byte in one rule.
///   A space and a `;` are *inside* this class, and reaching them is required: both are
///   legal in a conforming value (an `Mcp-Name` may carry an internal space, and a
///   `resources/read` name is a full URI, where `;` is legal in a segment), and both are
///   the token's separators, so the caveat body carries them percent-encoded instead of
///   denying them. See [`store_mcp_value`].
/// - **Exactly one spelling per value.** MCP requires a client to wrap a value it
///   cannot spell as plain ASCII — non-ASCII, a control byte, or leading or trailing
///   whitespace — and a value that itself reads as a wrapper (`=?…?=`) can only ever
///   arrive wrapped, because the markers would otherwise be read as the wrapper they
///   look like. [`must_be_wrapped`] is that condition, and a value must arrive wrapped
///   exactly when it holds: wrapping something that did not need it is denied rather
///   than folded, and so is sending something plain that had to be wrapped. One value,
///   one wire spelling.
/// - **Canonical base64 only**, when there is a wrapper: the standard alphabet
///   (`A-Za-z0-9+/`), padded to a multiple of four, `=` only at the very end, and the
///   bits the padding drops all zero. Base64 otherwise spells one value several ways
///   (base64url, unpadded, spare trailing bits), and several spellings of one value is
///   the same merge again. These checks together are the "re-encoding must give back
///   exactly what arrived" property, written out rather than round-tripped.
/// - **The stored spelling has to fit the field's limit.** A value is at most `limit`
///   bytes on the wire, but storing it can treble a byte (`;` becomes `%3B`), so a value
///   that is mostly separators can overflow the field it would be stored in. Such a
///   value is denied here rather than sealed into a caveat that could never be read
///   back. It is a false denial, and it is the only one this rule adds.
fn canonical_mcp_value(raw: &[u8], limit: usize) -> Option<String> {
    let payload = raw
        .strip_prefix(SENTINEL_OPEN)
        .and_then(|rest| rest.strip_suffix(SENTINEL_CLOSE));
    let value = match payload {
        Some(payload) => base64_decode(payload)?,
        None => raw.to_vec(),
    };
    let body_is_canonical =
        !value.is_empty() && value.iter().all(|&byte| matches!(byte, 0x20..=0x7E));
    if !body_is_canonical || must_be_wrapped(&value) != payload.is_some() {
        return None;
    }
    let stored = store_mcp_value(&value);
    (stored.len() <= limit).then_some(stored)
}

/// Whether MCP leaves this value no plain spelling, so it can only arrive wrapped.
///
/// Two reasons, and they come from different places. MCP's own trigger is a value that
/// cannot travel as plain ASCII: non-ASCII, a control byte, or **leading or trailing
/// whitespace** — an internal space is explicitly not a trigger, so `us west 1` travels
/// literally. The first two cannot reach this function, because the body rule above has
/// already denied them, and the only whitespace left after that rule is the space
/// itself; so what survives of MCP's trigger here is a leading or trailing space.
/// The second reason is this canonicalizer's own: a value that reads as a wrapper would
/// be taken for one if it were sent plain, so it has no plain spelling either.
fn must_be_wrapped(value: &[u8]) -> bool {
    value.first() == Some(&b' ') || value.last() == Some(&b' ') || reads_as_a_wrapper(value)
}

/// Whether a value would be read as a base64 wrapper if it were sent plain, so MCP
/// leaves it no plain spelling. Four bytes is the shortest value whose opening and
/// closing markers do not overlap.
fn reads_as_a_wrapper(value: &[u8]) -> bool {
    value.len() >= 4 && value.starts_with(b"=?") && value.ends_with(SENTINEL_CLOSE)
}

/// The stored spelling of a byte a caveat body cannot carry as itself, or `None` for
/// every byte it can.
///
/// **Three bytes, and one table for both directions.** A space and a `;` are the token's
/// two field separators, so a caveat body that carried either would end early;
/// `%` is the escape itself, and leaving it plain would give `us west 1` and the
/// literal `us%20west%201` one stored spelling, which is the merge this file exists to
/// prevent. Nothing else is encoded: encoding a byte that does not have to be would be a
/// second stored spelling of one value, exactly the way `canonical_path` denies `%41`
/// for `A`. [`store_mcp_value`] writes what this names and [`stored_mcp_value`] accepts
/// what this names, so the two cannot drift apart.
fn escaped_in_storage(byte: u8) -> Option<&'static str> {
    match byte {
        b' ' => Some("%20"),
        b'%' => Some("%25"),
        b';' => Some("%3B"),
        _ => None,
    }
}

/// Whether a byte stands for itself in a caveat body.
fn is_plain_stored_byte(byte: u8) -> bool {
    matches!(byte, 0x21..=0x7E) && escaped_in_storage(byte).is_none()
}

/// Writes a value the way a caveat body holds it: every byte as itself, except the three
/// [`escaped_in_storage`] names.
///
/// This is the **storage** encoding, not a wire one. It is this file's, it never travels,
/// and it is what lets a conforming value carrying a space or a `;` be expressed at all.
/// It is minimal (nothing else is encoded) and canonical (uppercase hex, one escape per
/// byte), so each value has exactly one stored spelling, and [`stored_mcp_value`] accepts
/// exactly the spellings this writes.
///
/// Every byte reaching this is printable ASCII, checked by the body rule above, so each
/// one is a single `char`.
fn store_mcp_value(value: &[u8]) -> String {
    let mut stored = String::new();
    for &byte in value {
        match escaped_in_storage(byte) {
            Some(escape) => stored.push_str(escape),
            None => stored.push(char::from(byte)),
        }
    }
    stored
}

/// An MCP value as a caveat body holds it: accepted only in the one spelling
/// [`store_mcp_value`] writes, and returned unchanged.
///
/// The loop is `canonical_path`'s, and deliberately so — the two rules are the same
/// discipline, and they share [`uppercase_hex_value`] and [`hex_byte`]:
///
/// - Non-empty.
/// - A byte standing for itself must be one [`is_plain_stored_byte`] names.
/// - A `%` must be followed by two **uppercase** hex digits, and they must name one of
///   the three bytes that had to be encoded. `%41` for `A` is denied as a second
///   spelling of a value, and `%3b` is denied for its lowercase hex, both for the same
///   reasons the path rule denies them.
///
/// The classes differ from the path's, because a value is opaque bytes and a path is a
/// URI: a path denies `%3B` outright, where a value must be able to carry one.
fn stored_mcp_value(stored: &[u8]) -> Option<String> {
    if stored.is_empty() {
        return None;
    }
    let mut bytes = stored.iter().copied();
    while let Some(byte) = bytes.next() {
        let is_canonical = if byte == b'%' {
            let high = bytes.next().and_then(uppercase_hex_value);
            let low = bytes.next().and_then(uppercase_hex_value);
            match (high, low) {
                (Some(high), Some(low)) => {
                    hex_byte(high, low).is_some_and(|decoded| escaped_in_storage(decoded).is_some())
                }
                _ => false,
            }
        } else {
            is_plain_stored_byte(byte)
        };
        if !is_canonical {
            return None;
        }
    }
    Some(ascii_to_string(stored))
}

/// Reads canonical padded standard-alphabet base64, or `None`.
///
/// Deliberately strict, because base64 is a place one value has several spellings and
/// every extra spelling is a second name for one destination: the length must be a
/// multiple of four, `=` may appear only at the end of the last group and only once or
/// twice, and the bits the padding drops must be zero. `-` and `_` (base64url) are not
/// in the alphabet and deny.
fn base64_decode(text: &[u8]) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(4) {
        return None;
    }
    let groups = text.as_chunks::<4>().0;
    let last_group = groups.len().checked_sub(1)?;
    let mut decoded = Vec::new();
    for (index, group) in groups.iter().enumerate() {
        let mut values = [0u8; 4];
        let mut padding = 0usize;
        for (slot, &byte) in values.iter_mut().zip(group) {
            if byte == b'=' {
                if index != last_group {
                    return None;
                }
                padding = padding.checked_add(1)?;
            } else if padding == 0 {
                *slot = base64_value(byte)?;
            } else {
                // `=` may only trail: `A=B=` is not base64.
                return None;
            }
        }
        if padding > 2 {
            return None;
        }
        // Four 6-bit values are 24 bits, so they are the low three bytes of a u32.
        let packed = values.iter().try_fold(0u32, |sum, &value| {
            sum.checked_mul(64)?.checked_add(u32::from(value))
        })?;
        let bytes = packed.to_be_bytes();
        let triple = bytes.get(1..)?;
        let kept = 3usize.checked_sub(padding)?;
        // The bits the padding drops must be zero, or one value has two spellings.
        if triple.get(kept..)?.iter().any(|&byte| byte != 0) {
            return None;
        }
        decoded.extend_from_slice(triple.get(..kept)?);
    }
    Some(decoded)
}

/// A standard-alphabet base64 digit's value (RFC 4648 §4). `=` is padding and is
/// handled by the caller, not here.
fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => byte.checked_sub(b'A'),
        b'a'..=b'z' => byte.checked_sub(b'a')?.checked_add(26),
        b'0'..=b'9' => byte.checked_sub(b'0')?.checked_add(52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
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

/// Kani proof harnesses for the rules in this file. Behind `#[cfg(kani)]`, which only
/// Kani's own compiler driver sets, so an ordinary build never sees them.
#[cfg(kani)]
#[path = "canonical_kani.rs"]
mod kani_proofs;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    /// The HTTP target of a request, or its denial.
    fn http(request: &RequestFacts) -> Result<HttpTarget, Denial> {
        canonicalize(request).map(|target| match target {
            Target::Http(http) => http,
            Target::Mcp(mcp) => mcp.http().clone(),
        })
    }

    /// The MCP target of a request, or its denial. Panics if the request had no MCP
    /// facts, since then the test asked for the wrong kind.
    fn mcp(request: &RequestFacts) -> Result<McpTarget, Denial> {
        canonicalize(request).map(|target| match target {
            Target::Mcp(mcp) => mcp,
            Target::Http(_) => panic!("the request carries MCP facts"),
        })
    }

    /// The canonical `Mcp-Name` of an otherwise ordinary MCP call, or its denial.
    fn mcp_name_of(name: &str) -> Result<String, Denial> {
        mcp(&crate::target::test_support::mcp_facts(
            "POST",
            "https",
            "mcp.example.com",
            "/mcp",
            "tools/call",
            name,
        ))
        .map(|target| target.name().to_string())
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
    fn ipv4_mapped_addresses_are_denied_in_both_spellings() {
        // RFC 5952 §4 compresses and writes hex; §5 recommends the dotted form for a
        // well-known IPv4-embedding prefix. Two recommendations, two spellings, no one
        // canonical text, so neither is accepted. Denying both is a tightening; making
        // the dotted one the accepted spelling would widen the rule and need a new caveat kind.
        for literal in [
            "[::ffff:7f00:1]",
            "[::ffff:127.0.0.1]",
            "[::ffff:c000:201]",
            "[::ffff:192.0.2.1]",
            "[::ffff:0:0]",
        ] {
            assert_eq!(host_of(literal), Err(Denial::MalformedHost), "{literal:?}");
        }
    }

    #[test]
    fn only_the_mapped_prefix_itself_is_denied() {
        // The rule is `::ffff:0:0/96` and nothing around it: one bit off the prefix,
        // and the address is an ordinary one with one RFC 5952 spelling again. The
        // NAT64 prefix is a well-known IPv4-embedding prefix too, but Rust and Python
        // both write it in hex, so nothing disagrees about it and it stays accepted.
        for literal in [
            "[64:ff9b::c000:201]",
            "[::fffe:7f00:1]",
            "[1::ffff:7f00:1]",
            "[::1:ffff:7f00:1]",
        ] {
            assert_eq!(host_of(literal), Ok(literal.to_string()), "{literal:?}");
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
            mcp: None,
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

    // --- byte classes, closed over all 256 values ----------------------------------

    // Five rules below are stated as a byte *class*: which bytes a path may carry as
    // themselves, which bytes an RFC 9110 token may hold, which bytes a host name may
    // hold, which bytes an MCP value may carry, and which bytes a caveat body may hold
    // as themselves. A hand-picked sample of bytes cannot see a class that has quietly
    // gained or lost a member, so each test here loops over all 256 values.
    //
    // Each oracle is written as an explicit table in ASCII order. That is on purpose:
    // the rules themselves are written as `is_ascii_*` plus a `matches!` arm, so a
    // find-and-replace edit to a rule cannot also rewrite the oracle it is checked
    // against. An oracle spelled the same way as its rule silently agrees with
    // whatever the rule becomes.

    /// RFC 3986 `pchar` plus `/`, minus `;`, written out. `?` is in the table because
    /// it is not a path byte at all: it starts the query, so `/a?b` is the accepted
    /// target `/a`.
    const PATH_BYTE_OR_QUERY: &[u8] =
        b"!$&'()*+,-./0123456789:=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~";

    /// RFC 9110 §5.6.2 `tchar`, written out.
    const TOKEN_BYTE: &[u8] =
        b"!#$%&'*+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz|~";

    /// The bytes a host name may hold, written out.
    const HOST_NAME_BYTE: &[u8] = b"-.0123456789_abcdefghijklmnopqrstuvwxyz";

    /// Every byte an MCP **value** may carry, written out in ASCII order: the space
    /// through `~`. The space and the `;` are in it — a conforming value may hold
    /// either, and the caveat body carries them encoded rather than denying them.
    const MCP_VALUE_BYTE: &[u8] =
        b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

    /// Every byte a **caveat body** may hold as itself: the table above, minus the three
    /// that have to be escaped there.
    const STORED_VALUE_BYTE: &[u8] =
        b"!\"#$&'()*+,-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

    /// The only three bytes a caveat body may hold percent-encoded, written out.
    const ESCAPED_BYTE: &[u8] = b" %;";

    /// Whether a raw path is accepted. `path_of` takes text; these tests need bytes.
    fn accepts_path(path: &[u8]) -> bool {
        canonicalize(&RequestFacts {
            method: b"GET",
            scheme: b"https",
            authority: b"example.com",
            path,
            mcp: None,
        })
        .is_ok()
    }

    /// Whether a raw method is accepted.
    fn accepts_method(method: &[u8]) -> bool {
        canonicalize(&RequestFacts {
            method,
            scheme: b"https",
            authority: b"example.com",
            path: b"/a",
            mcp: None,
        })
        .is_ok()
    }

    /// Whether a raw authority is accepted.
    fn accepts_authority(authority: &[u8]) -> bool {
        canonicalize(&RequestFacts {
            method: b"GET",
            scheme: b"https",
            authority,
            path: b"/a",
            mcp: None,
        })
        .is_ok()
    }

    #[test]
    fn a_path_holds_exactly_the_plain_bytes_the_rule_names() {
        for byte in 0u8..=255 {
            let path = [b'/', b'a', byte, b'b'];
            assert_eq!(
                accepts_path(&path),
                PATH_BYTE_OR_QUERY.contains(&byte),
                "path byte {byte:#04x}"
            );
        }
    }

    #[test]
    fn a_method_holds_exactly_the_rfc_9110_token_bytes() {
        for byte in 0u8..=255 {
            let method = [b'G', byte, b'T'];
            assert_eq!(
                accepts_method(&method),
                TOKEN_BYTE.contains(&byte),
                "method byte {byte:#04x}"
            );
        }
    }

    #[test]
    fn a_host_name_holds_exactly_the_bytes_the_rule_names() {
        for byte in 0u8..=255 {
            let authority = [b'a', byte, b'b'];
            assert_eq!(
                accepts_authority(&authority),
                HOST_NAME_BYTE.contains(&byte),
                "host byte {byte:#04x}"
            );
        }
    }

    #[test]
    fn canonical_fields_are_printable_ascii_only() {
        // A token is one line of printable ASCII carried in an HTTP header value, so a
        // canonical field may never hold a control byte, a space, a `;` or anything
        // above 0x7E. Pin it for every byte value, appended to every text field in
        // turn.
        for byte in 0u8..=255 {
            let method = [b"GET".as_slice(), &[byte]].concat();
            let authority = [b"example.com".as_slice(), &[byte]].concat();
            let path = [b"/a".as_slice(), &[byte]].concat();
            let requests = [
                RequestFacts {
                    method: &method,
                    scheme: b"https",
                    authority: b"example.com",
                    path: b"/a",
                    mcp: None,
                },
                RequestFacts {
                    method: b"GET",
                    scheme: b"https",
                    authority: &authority,
                    path: b"/a",
                    mcp: None,
                },
                RequestFacts {
                    method: b"GET",
                    scheme: b"https",
                    authority: b"example.com",
                    path: &path,
                    mcp: None,
                },
            ];
            for raw in requests {
                if let Ok(target) = http(&raw) {
                    let authority = target.authority();
                    for text in [target.method(), target.scheme(), &authority, target.path()] {
                        for byte in text.bytes() {
                            assert!((0x21..=0x7E).contains(&byte), "{text:?} holds {byte:#04x}");
                        }
                    }
                }
            }
        }
    }

    // --- the MCP fields ----------------------------------------------------------

    /// A plain value is kept byte for byte, like every other field here.
    #[test]
    fn a_plain_mcp_value_is_kept_exactly() {
        for name in [
            "get_document",
            "delete_document",
            "A",
            "a.b-c_d",
            "file:///projects/myapp/config.json",
            "=?base64",
            "not-a-wrapper?=",
            "=?x?",
        ] {
            assert_eq!(mcp_name_of(name), Ok(name.to_string()), "{name:?}");
        }
        let target = mcp(&crate::target::test_support::mcp_facts(
            "POST",
            "https",
            "mcp.example.com",
            "/mcp",
            "resources/read",
            "file:///a",
        ))
        .unwrap();
        assert_eq!(target.method(), "resources/read");
        assert_eq!(target.name(), "file:///a");
    }

    /// The token's two separators can never reach a caveat body — but a conforming
    /// value may carry either, so they are stored percent-encoded rather than denied.
    #[test]
    fn a_separator_inside_a_value_is_stored_encoded_never_denied() {
        assert_eq!(
            mcp_name_of("get document"),
            Ok("get%20document".to_string())
        );
        assert_eq!(mcp_name_of("file:///a;b"), Ok("file:///a%3Bb".to_string()));
        // The escape itself: a literal `%` is encoded too, or one value would have two
        // stored spellings.
        assert_eq!(mcp_name_of("a%20b"), Ok("a%2520b".to_string()));
        assert_eq!(mcp_name_of("100%"), Ok("100%25".to_string()));
        // Neither separator reaches the stored spelling of any of them.
        for name in ["get document", "file:///a;b", "a%20b", "a b;c%d"] {
            let stored = mcp_name_of(name).unwrap();
            assert!(
                !stored.contains(' ') && !stored.contains(';'),
                "{name:?} stored as {stored:?}"
            );
        }
    }

    /// `us west 1` is a conforming MCP value: MCP wraps a value in its base64 sentinel
    /// for non-ASCII, a control byte or *leading or trailing* whitespace, and an
    /// internal space is none of those, so the value travels literally. It has exactly
    /// one legal spelling: the plain form, stored percent-encoded.
    #[test]
    fn a_value_with_an_internal_space_has_exactly_one_legal_spelling() {
        // The one legal spelling: plain on the wire, encoded in storage.
        assert_eq!(mcp_name_of("us west 1"), Ok("us%20west%201".to_string()));
        // And the other spellings a client might reach for are all still denied, so
        // "exactly one" is the whole claim: the gratuitously wrapped form...
        assert_eq!(
            mcp_name_of("=?base64?dXMgd2VzdCAx?="),
            Err(Denial::MalformedMcpName)
        );
        // ...and the storage spelling sent as if it were a wire value, which is an
        // ordinary different value (`us%20west%201`, with two literal `%`) and is
        // stored as that instead.
        assert_eq!(
            mcp_name_of("us%20west%201"),
            Ok("us%2520west%25201".to_string())
        );
        // One stored spelling, so the two are different destinations and neither can
        // stand in for the other.
        assert_ne!(mcp_name_of("us west 1"), mcp_name_of("us%20west%201"));
    }

    /// A value MCP itself requires to be wrapped: leading or trailing whitespace. The
    /// wrapper is the only way it can travel, so the wrapped form is the accepted one,
    /// and it stores as the value it stands for.
    #[test]
    fn a_value_that_legitimately_requires_the_sentinel_arrives_wrapped() {
        // " get_document" and "get_document ", each wrapped.
        assert_eq!(
            mcp_name_of("=?base64?IGdldF9kb2N1bWVudA==?="),
            Ok("%20get_document".to_string())
        );
        assert_eq!(
            mcp_name_of("=?base64?Z2V0X2RvY3VtZW50IA==?="),
            Ok("get_document%20".to_string())
        );
        // Sent plain, the same values are denied: MCP leaves them no plain spelling.
        assert_eq!(mcp_name_of(" get_document"), Err(Denial::MalformedMcpName));
        assert_eq!(mcp_name_of("get_document "), Err(Denial::MalformedMcpName));
        // A lone space is a leading *and* a trailing one, and it is a value.
        assert_eq!(mcp_name_of("=?base64?IA==?="), Ok("%20".to_string()));
        assert_eq!(mcp_name_of(" "), Err(Denial::MalformedMcpName));
    }

    /// Empty, control bytes, `DEL` and non-ASCII: one rule, `0x20..=0x7E`. None of these
    /// is widened by storage encoding — a value that MCP would wrap for any of these
    /// reasons is still denied in both spellings, because a caveat body is ASCII.
    #[test]
    fn an_mcp_value_that_is_not_printable_ascii_is_denied() {
        assert_eq!(mcp_name_of(""), Err(Denial::MalformedMcpName));
        assert_eq!(mcp_name_of("get\tname"), Err(Denial::MalformedMcpName));
        assert_eq!(mcp_name_of("get\nname"), Err(Denial::MalformedMcpName));
        assert_eq!(mcp_name_of("get\u{7f}name"), Err(Denial::MalformedMcpName));
        assert_eq!(mcp_name_of("caf\u{e9}"), Err(Denial::MalformedMcpName));
        // Wrapped, the way MCP requires for exactly these values: still denied, because
        // the rules are applied to what the wrapper stands for. "get\tname" and "café".
        assert_eq!(
            mcp_name_of("=?base64?Z2V0CW5hbWU=?="),
            Err(Denial::MalformedMcpName)
        );
        assert_eq!(
            mcp_name_of("=?base64?Y2Fmw6k=?="),
            Err(Denial::MalformedMcpName)
        );
    }

    /// Every byte value, in one pass: exactly the printable ASCII bytes are carried, and
    /// nothing else is. The byte is put *between* two others, because a leading or
    /// trailing space is MCP's own wrapping trigger and is a rule of its own (above).
    #[test]
    fn an_mcp_value_holds_exactly_the_bytes_the_rule_names() {
        for byte in 0u8..=255 {
            let name = [b"a".as_slice(), &[byte], b"b".as_slice()].concat();
            let facts = RequestFacts {
                mcp: Some(crate::target::McpFacts {
                    method: b"tools/call",
                    name: &name,
                }),
                ..crate::target::test_support::facts("POST", "https", "mcp.example.com", "/mcp")
            };
            assert_eq!(
                canonicalize(&facts).is_ok(),
                MCP_VALUE_BYTE.contains(&byte),
                "byte {byte:#04x} in an Mcp-Name"
            );
        }
    }

    /// The same closure, one layer in: which bytes a **caveat body** may hold as
    /// themselves, and which escapes it may hold at all. A value's byte class and its
    /// stored byte class are two rules, and only the second one is what `format.rs`
    /// relies on when it promises a body holds no separator.
    #[test]
    fn a_stored_mcp_value_holds_exactly_the_plain_bytes_and_escapes_the_rule_names() {
        for byte in 0u8..=255 {
            let stored = [b"a".as_slice(), &[byte], b"b".as_slice()].concat();
            assert_eq!(
                stored_mcp_value(&stored).is_some(),
                STORED_VALUE_BYTE.contains(&byte),
                "stored byte {byte:#04x}"
            );
        }
        // Every two-digit escape, all 256 of them, in uppercase and in lowercase hex:
        // only the three bytes that *had* to be encoded may appear encoded, and only in
        // uppercase. `%41` for `A` and `%3b` for `;` are the two ways a second stored
        // spelling of one value could get in, and both are denied.
        for byte in 0u8..=255 {
            let upper = alloc::format!("a%{byte:02X}b");
            assert_eq!(
                stored_mcp_value(upper.as_bytes()).is_some(),
                ESCAPED_BYTE.contains(&byte),
                "escape {upper:?}"
            );
            let lower = alloc::format!("a%{byte:02x}b");
            if lower != upper {
                assert!(
                    stored_mcp_value(lower.as_bytes()).is_none(),
                    "lowercase escape {lower:?}"
                );
            }
        }
        // A `%` that names nothing at all is denied the same way a path's is.
        for stored in ["%", "%2", "%2G", "a%", "a%2", "%%20", "%20%", ""] {
            assert!(stored_mcp_value(stored.as_bytes()).is_none(), "{stored:?}");
        }
    }

    /// Round trip, over every value the byte rule admits: a value's stored spelling
    /// reads back, reads back to itself, and is the only stored spelling it has.
    #[test]
    fn every_admitted_value_stores_and_reads_back_unchanged() {
        for byte in MCP_VALUE_BYTE.iter().copied() {
            // Between two plain bytes, so no value here needs the wrapper.
            let value = [b'a', byte, b'b'];
            let stored = store_mcp_value(&value);
            assert_eq!(
                stored_mcp_value(stored.as_bytes()).as_deref(),
                Some(stored.as_str()),
                "byte {byte:#04x}"
            );
            // The wire reading gives the same stored bytes, so observe and decode agree.
            assert_eq!(
                canonical_mcp_value(&value, MAX_MCP_NAME_BYTES).as_deref(),
                Some(stored.as_str()),
                "byte {byte:#04x}"
            );
            // Two distinct values never share a stored spelling.
            let other = *b"azb";
            assert_eq!(
                stored == store_mcp_value(&other),
                value == other,
                "byte {byte:#04x}"
            );
        }
    }

    /// A stored value the limit cannot hold is denied rather than sealed into a caveat
    /// that could not be read back.
    #[test]
    fn a_value_whose_stored_spelling_would_not_fit_is_denied() {
        // Every `;` trebles, so a value of separators fills the field three times as
        // fast. This one is well inside the wire limit and lands exactly on the stored
        // one.
        let fits = ";".repeat(MAX_MCP_NAME_BYTES / 3) + &"a".repeat(MAX_MCP_NAME_BYTES % 3);
        assert!(fits.len() <= MAX_MCP_NAME_BYTES);
        let stored = mcp_name_of(&fits).unwrap();
        assert_eq!(stored.len(), MAX_MCP_NAME_BYTES);
        // One more separator, and the stored spelling no longer fits, so the value is
        // denied rather than sealed into a caveat that could not be read back.
        let one_more = ";".to_string() + &fits;
        assert!(one_more.len() <= MAX_MCP_NAME_BYTES);
        assert_eq!(
            mcp_name_of(&one_more),
            Err(Denial::MalformedMcpName),
            "a value inside the wire limit whose stored spelling is not"
        );
    }

    /// The rule that keeps one value from having two names: wrapping something that
    /// did not have to be wrapped is denied, never folded onto the plain spelling.
    #[test]
    fn a_value_wrapped_when_it_did_not_need_to_be_is_denied() {
        // "get_document" and "tools/call", each wrapped.
        assert_eq!(
            mcp_name_of("=?base64?Z2V0X2RvY3VtZW50?="),
            Err(Denial::MalformedMcpName)
        );
        assert_eq!(
            mcp_name_of("=?base64?dG9vbHMvY2FsbA==?="),
            Err(Denial::MalformedMcpName)
        );
    }

    /// The other half of the same rule: a value that would read as a wrapper has no
    /// plain spelling, so it must arrive wrapped. The markers are case-sensitive, so
    /// `=?BASE64?...?=` is an ordinary value that happens to look like one.
    ///
    /// The wrapper is a *wire* spelling, so it never reaches the stored one: what is
    /// stored is the value the wrapper stands for, which for these values needs no
    /// escaping at all.
    #[test]
    fn a_value_that_reads_as_a_wrapper_must_arrive_wrapped() {
        // "=?BASE64?Zm9v?=" sent plain: denied, because it reads as a wrapper.
        assert_eq!(
            mcp_name_of("=?BASE64?Zm9v?="),
            Err(Denial::MalformedMcpName)
        );
        // The same value, wrapped the way MCP requires: accepted, and stored as the
        // value itself, because that is what the wrapper stood for.
        assert_eq!(
            mcp_name_of("=?base64?PT9CQVNFNjQ/Wm05dj89?="),
            Ok("=?BASE64?Zm9v?=".to_string())
        );
        // A value too short to have two markers is not one, so it stays plain.
        assert_eq!(mcp_name_of("=?="), Ok("=?=".to_string()));
        assert_eq!(mcp_name_of("=?x?="), Err(Denial::MalformedMcpName));
        assert_eq!(mcp_name_of("=?base64?PT94Pz0=?="), Ok("=?x?=".to_string()));
        assert_eq!(mcp_name_of("=?not-base64?="), Err(Denial::MalformedMcpName));
        assert_eq!(
            mcp_name_of("=?base64?PT9ub3QtYmFzZTY0Pz0=?="),
            Ok("=?not-base64?=".to_string())
        );
    }

    /// Why decode at all: the rules are applied to what the wrapper stands
    /// for. A separator inside base64 can no longer break the token's grammar, because
    /// the storage encoding would catch it either way — but it is still denied, and by
    /// the rule that matters now: the value needed no wrapping, so the wrapped spelling
    /// is a second spelling of it.
    #[test]
    fn a_wrapper_is_decoded_before_the_value_rules_are_applied() {
        // "get document" and "get;document", wrapped. Neither needed the wrapper.
        assert_eq!(
            mcp_name_of("=?base64?Z2V0IGRvY3VtZW50?="),
            Err(Denial::MalformedMcpName)
        );
        assert_eq!(
            mcp_name_of("=?base64?Z2V0O2RvY3VtZW50?="),
            Err(Denial::MalformedMcpName)
        );
        // Sent plain, the way MCP requires for a value with an internal separator, both
        // are accepted and stored encoded.
        assert_eq!(
            mcp_name_of("get document"),
            Ok("get%20document".to_string())
        );
        assert_eq!(
            mcp_name_of("get;document"),
            Ok("get%3Bdocument".to_string())
        );
    }

    /// Base64 spells one value several ways, and every extra spelling would be a second
    /// name for one destination. Only the canonical spelling is read.
    #[test]
    fn only_canonical_base64_is_read() {
        for payload in [
            "PT9CQVNFNjQ_Wm05dj89",
            "PT9CQVNFNjQ/Wm05dj89=",
            "PT9CQVNFNjQ/Wm05dj8",
            "PT9CQVNFNjQ/=m05dj89",
            "====",
            "QR==",
            "",
        ] {
            let wrapped = alloc::format!("=?base64?{payload}?=");
            assert_eq!(
                mcp_name_of(&wrapped),
                Err(Denial::MalformedMcpName),
                "{wrapped:?}"
            );
        }
        // "A" wrapped: canonical base64, but the value needs no wrapping, so it is the
        // one-spelling rule that denies it, not the base64 rule.
        assert_eq!(
            mcp_name_of("=?base64?QQ==?="),
            Err(Denial::MalformedMcpName)
        );
    }

    /// Each MCP field names its own denial, and both are checked against their byte
    /// limits before any field is read.
    #[test]
    fn each_mcp_field_is_named_and_bounded_on_its_own() {
        let bad = |method: &str, name: &str| {
            canonicalize(&crate::target::test_support::mcp_facts(
                "POST",
                "https",
                "mcp.example.com",
                "/mcp",
                method,
                name,
            ))
        };
        // A tab is a control byte, which no spelling of a value may carry.
        assert_eq!(
            bad("tools	call", "get_document"),
            Err(Denial::MalformedMcpMethod)
        );
        assert_eq!(
            bad("tools/call", "get	document"),
            Err(Denial::MalformedMcpName)
        );
        // The method is read first, so it names the denial when both are bad.
        assert_eq!(
            bad("tools	call", "get	document"),
            Err(Denial::MalformedMcpMethod)
        );

        // At the limit each field is read; one byte over, the length denial wins even
        // though every other field is malformed too.
        let at_method = "m".repeat(MAX_MCP_METHOD_BYTES);
        let at_name = "n".repeat(MAX_MCP_NAME_BYTES);
        assert!(bad(&at_method, &at_name).is_ok());
        let over_method = "m".repeat(MAX_MCP_METHOD_BYTES.saturating_add(1));
        let over_name = "n".repeat(MAX_MCP_NAME_BYTES.saturating_add(1));
        for facts in [
            crate::target::test_support::mcp_facts("!", "HTTPS", "X", "a", &over_method, "n"),
            crate::target::test_support::mcp_facts("!", "HTTPS", "X", "a", "m", &over_name),
        ] {
            assert_eq!(canonicalize(&facts), Err(Denial::RequestTooLong));
        }
    }
}
