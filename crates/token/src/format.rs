//! The token's byte format. This is the only module that knows it.
//!
//! Two versions, `v1` and `v2`, both expected to be replaced (probably by a standard
//! format) later. Everything else goes through [`encode`], [`encode_for`], [`present`]
//! and [`lists`], so that change stays inside this file.
//!
//! # The grammar
//!
//! In ABNF (RFC 5234), where `SP` is one space:
//!
//! ```text
//! token     = v1-token / v2-token
//! v1-token  = "v1" *( ";" caveat )
//! v2-token  = "v2" ";" run-id *( ";" caveat )
//! run-id    = 1*64( ALPHA / DIGIT / "-" / "_" )
//! caveat    = kind SP body
//! kind      = 1*( %x61-7A / DIGIT / "-" )   ; lowercase letters, digits, "-"
//! body      = http-body / mcp-body          ; one per kind this build knows
//! http-body = method SP scheme SP authority SP path
//! mcp-body  = http-body SP mcp-value SP mcp-value
//! mcp-value = 1*( plain / escape )
//! plain     = %x21-24 / %x26-3A / %x3C-7E    ; printable ASCII, no SP, "%" or ";"
//! escape    = "%20" / "%25" / "%3B"          ; the three bytes a body cannot hold
//! ```
//!
//! For example, a token allowing two destinations:
//!
//! ```text
//! v1;http GET https example.com /orders;http POST https example.com:8443 /orders
//! ```
//!
//! one allowing a single MCP tool call:
//!
//! ```text
//! v1;mcp POST https mcp.example.com /mcp tools/call get_document
//! ```
//!
//! and the same set again, named by the run it was sealed for:
//!
//! ```text
//! v2;run-1;mcp POST https mcp.example.com /mcp tools/call get_document
//! ```
//!
//! # `v2` and the run id
//!
//! `v2` is `v1` with exactly one field in front of the caveats: an opaque [`RunId`]
//! label that the caller supplies. It has no internal structure: it is bytes from a
//! small alphabet, compared exactly and never folded, and this build attaches no
//! meaning to any part of it.
//!
//! A token rides in a request header through every hop to its destination, so anything in
//! it is exposed to every proxy, every log and the destination itself. Keep secrets and
//! personal data out of the id.
//!
//! **A version bump rather than a field smuggled into `v1`.** A `v1` token has no room
//! for a field, so carrying one there would mean deciding whether the first `;`-piece is
//! a run id or a caveat by trying to parse it both ways — the token telling the reader
//! how to read it, which is the shape this format exists to rule out. With a version tag the
//! shape is fixed before a byte of the body is read. `v1` is unchanged and still valid,
//! and carries no id.
//!
//! **The id is structurally unreachable from `gate::check`** — see [`Caveats`].
//!
//! - Every caveat starts with its kind, so a later kind of destination (for example a
//!   JSON-RPC operation or a queue topic) can be added as a new kind with its own body,
//!   without changing how `v1` tokens are read. A well-formed kind this build does not
//!   know denies the whole token (`UnknownCaveatKind`): a gate never skips a caveat it
//!   cannot read.
//! - Each field is exactly what the canonicalizer produces for it. The authority is the
//!   host, plus `:port` only when the port is not the scheme's default, which is the
//!   one spelling the canonicalizer accepts back. An `mcp` caveat is an `http` caveat's
//!   four fields followed by the two MCP values, in that order, because an MCP call is
//!   an HTTP request plus the operation it names. Those two are the only fields whose
//!   stored spelling is not the spelling they arrived in: the canonicalizer
//!   percent-encodes a space, a `%` and a `;` on the way in, and reads that spelling
//!   back on the way out, so the separators below stay separators.
//! - Caveats are in ascending order with no repeats, so a caveat set has exactly one
//!   token. A token with zero caveats (`v1`) is valid and allows nothing.
//! - Nothing here escapes anything: `;` and space never appear in a canonical field by
//!   the time it is written (a method is an RFC 9110 token, which excludes both; a host
//!   is letters, digits, `-`, `_`, `.` or a bracketed IPv6 literal; a port is digits; a
//!   path denies `;` and has spaces percent-encoded; an MCP value is stored
//!   percent-encoded, which is the canonicalizer's rule and not this module's). Every
//!   byte is printable ASCII, so the token fits in an HTTP header value.
//! - The token has no flags, modes, wildcards or options. It only lists destinations,
//!   plus (in `v2`) the id of the run it was sealed for, which nothing that checks it
//!   can read. It never changes how it is checked. The kind says what a caveat
//!   is, not how to check it.
//!
//! Decoding is strict: anything not in the exact form [`encode`] and [`encode_for`]
//! write is denied. One harmless exception: a stored MCP value whose required wire form
//! is over its byte limit reads back, but no request can match it. Each stored caveat
//! is read back through the canonicalizer's rules, so the `http` kind in `v1` means "an
//! HTTP target under this rule set": a rule that is later tightened makes old caveats
//! deny, and a rule may never be widened without a new kind (see `canonical.rs`).
//!
//! The token is not signed yet. The grammar above is public, so anyone who can write
//! the token header can list any canonical target by hand, and [`lists`] will
//! honor it. The README lists this as a known limit until signing lands.

use alloc::string::String;
use alloc::vec::Vec;

use crate::canonical::canonicalize_stored;
use crate::{CaveatSet, Denial, HttpTarget, McpFacts, RequestFacts, Target};

/// The longest token accepted, in bytes. Checked before the token is read.
/// Some servers and proxies allow a single header less than 8 KiB, so a token near this
/// size may not reach the gate. A deployment should check the header limit of every hop.
pub const MAX_TOKEN_BYTES: usize = 8192;

/// The longest run id a `v2` token may carry, in bytes. Checked before the id is read.
///
/// 64 bytes holds every identifier shape a caller is likely to have already: a UUID in
/// its dashed form (36), a ULID (26), a W3C trace id in hex (32), or a short
/// human-readable name with a counter on the end. It is a byte limit, never a character
/// count.
pub const MAX_RUN_ID_BYTES: usize = 64;

const VERSION_1: &[u8] = b"v1";
const VERSION_2: &[u8] = b"v2";
const CAVEAT_SEPARATOR: u8 = b';';
const FIELD_SEPARATOR: u8 = b' ';

/// An opaque label the caller supplies for a token.
///
/// It is compared as exact bytes and never folded, so `R-1` and `r-1` are two runs. The
/// alphabet is `A-Z`, `a-z`, `0-9`, `-` and `_`, which excludes both of the token's
/// separators, so a run id can never break the grammar around it.
///
/// **Unlike a [`Caveat`](crate::Caveat), this has a public constructor, and that is
/// deliberate.** A caveat limits reach and may only come from the canonicalizer. A run id
/// grants nothing: it is a label, and the library attaches no meaning to it. Whoever seals
/// the token chooses it, so that caller must be able to build one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RunId<'a> {
    text: &'a str,
}

impl<'a> RunId<'a> {
    /// Reads a run id, or names why it is not one.
    ///
    /// Empty, longer than [`MAX_RUN_ID_BYTES`], or carrying any byte outside the
    /// alphabet above gives [`Denial::MalformedRunId`] — the same rule, and the same
    /// name, that denies a token carrying one.
    pub fn new(bytes: &'a [u8]) -> Result<RunId<'a>, Denial> {
        if bytes.is_empty() || bytes.len() > MAX_RUN_ID_BYTES {
            return Err(Denial::MalformedRunId);
        }
        if !bytes
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(Denial::MalformedRunId);
        }
        // Every accepted byte is ASCII, so this cannot fail; it is written as a
        // conversion rather than an assumption so there is no unwrap here.
        core::str::from_utf8(bytes)
            .map(|text| RunId { text })
            .map_err(|_| Denial::MalformedRunId)
    }

    /// The id as text, for writing it into a record.
    pub fn as_str(&self) -> &'a str {
        self.text
    }
}

/// The caveat region of a presented token: **the only thing `gate::check` is ever
/// handed**, and the reason the run id cannot reach it.
///
/// Two barriers, either of which would be enough on its own:
///
/// - **By type.** The one field is private to this crate, and this type has no public
///   accessor of any kind — not even a `Debug` that prints its contents. `gate` is a
///   different crate, so reaching the field from `check` is `error[E0616]`, a compile
///   error rather than a rule someone has to remember. The check to run by hand is
///   recorded in the tests at the bottom of this file, for the same reason the
///   `Target` one is (a compile-fail test crate would mean a proc-macro dependency).
/// - **By construction.** [`present`] cuts the token *after* the version and the run id,
///   so the bytes behind this handle do not contain the id at all. Even a caller that
///   could read the field would find no id in it — and no version tag either, so the
///   whole check is a function of the caveat region and the request, and of
///   nothing else the token carries.
///
/// This is the same discipline as caveat construction (no public constructor): make it
/// the shape of the code, not a policy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Caveats<'a> {
    /// Everything after the `;` that follows the version (and, in `v2`, the run id):
    /// the caveats, still separated by `;`. `None` when there is no such `;` at all,
    /// which is a token that lists nothing.
    body: Option<&'a [u8]>,
}

impl core::fmt::Debug for Caveats<'_> {
    /// Prints a length, never the bytes. A token's insides never leave this module, and
    /// a derived `Debug` would be a way around that.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Caveats")
            .field("bytes", &self.body.map_or(0, <[u8]>::len))
            .finish()
    }
}

/// A token split into the two things it carries: the run it was sealed for, and the
/// destinations it lists.
///
/// Splitting is the only way to either one, and from that point on they are separate
/// types that cannot be got back from each other. A caller keeps this; the
/// check is handed only [`Presented::caveats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presented<'a> {
    run: Option<RunId<'a>>,
    caveats: Caveats<'a>,
}

impl<'a> Presented<'a> {
    /// The run this token was sealed for, or `None` for a `v1` token, which carries no
    /// id.
    pub fn run(&self) -> Option<RunId<'a>> {
        self.run
    }

    /// The caveat region, for `gate::check`. See [`Caveats`].
    pub fn caveats(&self) -> Caveats<'a> {
        self.caveats
    }
}

/// The kind tag of an HTTP caveat.
const HTTP_KIND: &[u8] = b"http";

/// The kind tag of an MCP caveat.
///
/// **A kind names the rules its body is read under**, and [`Caveats`] carries no version
/// tag on purpose, so `decode` has no version to branch on: the kind is the only thing
/// that pins those rules. Once tokens are in use, a change to what an `mcp`
/// body *means* — the storage encoding is exactly such a change — is a new kind rather
/// than a new version. No tokens are in use yet.
const MCP_KIND: &[u8] = b"mcp";

/// Why a caveat set could not be sealed into a token.
///
/// `#[non_exhaustive]` so a later version can add a case without breaking callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SealError {
    /// The token would be longer than [`MAX_TOKEN_BYTES`], so `gate` would deny it.
    TokenTooLong,
}

/// Writes a caveat set as a `v1` token: the destinations, and nothing else.
///
/// Stops as soon as the token would be longer than [`MAX_TOKEN_BYTES`], so a huge set
/// costs no more than one token's worth of writing.
pub fn encode(set: &CaveatSet) -> Result<String, SealError> {
    let mut token = String::new();
    push_str(&mut token, VERSION_1);
    write_caveats(token, set)
}

/// Writes a caveat set as a `v2` token: the run it was sealed for, then the same
/// destinations, written by the same code.
pub fn encode_for(run: RunId<'_>, set: &CaveatSet) -> Result<String, SealError> {
    let mut token = String::new();
    push_str(&mut token, VERSION_2);
    token.push(char::from(CAVEAT_SEPARATOR));
    token.push_str(run.as_str());
    write_caveats(token, set)
}

/// The half both versions share: every caveat, in order, onto whatever prefix the
/// version wrote. Nothing about a caveat depends on which version is in front of it.
fn write_caveats(mut token: String, set: &CaveatSet) -> Result<String, SealError> {
    for caveat in set.caveats() {
        token.push(char::from(CAVEAT_SEPARATOR));
        write_caveat(&mut token, caveat.target());
        if token.len() > MAX_TOKEN_BYTES {
            return Err(SealError::TokenTooLong);
        }
    }
    Ok(token)
}

/// Splits a token into the run it names and the caveats it lists, or names why it is not
/// a token this build can read.
///
/// The byte limits are checked here, before anything is read, so a caller that
/// goes on to `gate::check` has already paid for them once.
pub fn present(token: &[u8]) -> Result<Presented<'_>, Denial> {
    if token.is_empty() {
        return Err(Denial::EmptyToken);
    }
    if token.len() > MAX_TOKEN_BYTES {
        return Err(Denial::TokenTooLong);
    }
    let (version, after_version) = split_at_separator(token);
    match version {
        VERSION_1 => Ok(Presented {
            run: None,
            caveats: Caveats {
                body: after_version,
            },
        }),
        VERSION_2 => {
            // A `v2` token always carries a run id, so the separator after the version
            // is required: `v2` on its own is not an empty-set token, it is a token
            // missing its id.
            let after = after_version.ok_or(Denial::MalformedRunId)?;
            let (run, after_run) = split_at_separator(after);
            Ok(Presented {
                run: Some(RunId::new(run)?),
                caveats: Caveats { body: after_run },
            })
        }
        _ => Err(Denial::UnknownVersion),
    }
}

/// Everything up to the first `;`, and everything after it — `None` when there is no
/// `;` at all, which is a token with nothing following that field.
fn split_at_separator(bytes: &[u8]) -> (&[u8], Option<&[u8]>) {
    match bytes.iter().position(|&byte| byte == CAVEAT_SEPARATOR) {
        Some(at) => {
            let (field, rest) = bytes.split_at(at);
            // `rest` starts with the separator, so dropping one byte always succeeds.
            (field, rest.get(1..))
        }
        None => (bytes, None),
    }
}

/// Reads a presented token's caveats and says whether they list `target`.
///
/// The target comes only from the caller, never from the token. The decoded caveat set
/// never leaves this module, so a hand-written token can never be turned into a
/// caveat set and sealed again. It can still be checked, and until tokens are signed
/// a hand-written token that lists a target in canonical form allows it.
pub fn lists(caveats: Caveats<'_>, target: &Target) -> Result<bool, Denial> {
    Ok(decode(caveats)?.lists(target))
}

/// Pushes ASCII bytes onto a `String`. The version tags and kind tags are ASCII, so each
/// byte is one char.
fn push_str(out: &mut String, ascii: &[u8]) {
    out.extend(ascii.iter().map(|&byte| char::from(byte)));
}

fn write_caveat(out: &mut String, target: &Target) {
    let separator = char::from(FIELD_SEPARATOR);
    // The kind tags are ASCII, so each byte is one char.
    let kind = match target {
        Target::Http(_) => HTTP_KIND,
        Target::Mcp(_) => MCP_KIND,
    };
    push_str(out, kind);
    match target {
        Target::Http(http) => write_http_body(out, http),
        Target::Mcp(mcp) => {
            write_http_body(out, mcp.http());
            out.push(separator);
            out.push_str(mcp.method());
            out.push(separator);
            out.push_str(mcp.name());
        }
    }
}

/// The four HTTP fields, each preceded by the field separator. Shared, because an `mcp`
/// body starts with exactly the same four.
fn write_http_body(out: &mut String, http: &HttpTarget) {
    let separator = char::from(FIELD_SEPARATOR);
    out.push(separator);
    out.push_str(http.method());
    out.push(separator);
    out.push_str(http.scheme());
    out.push(separator);
    out.push_str(&http.authority());
    out.push(separator);
    out.push_str(http.path());
}

/// Reads the caveat region. It holds no version tag and no run id, so this — and
/// therefore every verdict — depends on nothing the token carries but the caveats.
fn decode(caveats: Caveats<'_>) -> Result<CaveatSet, Denial> {
    let mut targets: Vec<Target> = Vec::new();
    let Some(body) = caveats.body else {
        return Ok(CaveatSet::from_targets(targets));
    };
    for piece in body.split(|&byte| byte == CAVEAT_SEPARATOR) {
        let target = decode_caveat(piece)?;
        // Strictly ascending: no repeats, and only one way to write a given set.
        if targets.last().is_some_and(|previous| *previous >= target) {
            return Err(Denial::MalformedToken);
        }
        targets.push(target);
    }
    Ok(CaveatSet::from_targets(targets))
}

/// Reads one caveat: its kind tag, then the body that kind defines.
fn decode_caveat(piece: &[u8]) -> Result<Target, Denial> {
    let mut kind_and_body = piece.splitn(2, |&byte| byte == FIELD_SEPARATOR);
    let kind = kind_and_body.next().unwrap_or_default();
    let body = kind_and_body.next();
    let is_kind = !kind.is_empty()
        && kind
            .iter()
            .all(|&byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !is_kind {
        return Err(Denial::MalformedToken);
    }
    // The kind is read before the body, so a kind this build does not know is named as
    // such whatever follows it, and a caveat is never skipped.
    let is_mcp = match kind {
        HTTP_KIND => false,
        MCP_KIND => true,
        _ => return Err(Denial::UnknownCaveatKind),
    };
    let target = decode_body(body.ok_or(Denial::MalformedToken)?, is_mcp)?;
    // A stored caveat is valid only if writing its target back gives exactly the same
    // bytes. This keeps every rule in the canonicalizer: the format itself knows only
    // where the fields are. It rejects `HTTPS`, `Example.com`, `:0443`, `:443` on
    // https, `%c3`, `/a?x` and the like.
    let mut canonical = String::new();
    write_caveat(&mut canonical, &target);
    if canonical.as_bytes() != piece {
        return Err(Denial::MalformedToken);
    }
    Ok(target)
}

/// Reads a caveat body's fields back through the canonicalizer's rules: four fields for
/// an `http` caveat, six for an `mcp` one. The format knows only where the fields are;
/// every rule about what may be in them stays in `canonical.rs`.
///
/// It reads them through [`canonicalize_stored`], not `canonicalize`: these are bytes a
/// caveat body holds, and an MCP value's stored spelling is percent-encoded where its
/// wire spelling is base64-wrapped. For every other field, and for a whole `http`
/// caveat, the two are the same function.
fn decode_body(body: &[u8], is_mcp: bool) -> Result<Target, Denial> {
    let mut fields = body.split(|&byte| byte == FIELD_SEPARATOR);
    let (Some(method), Some(scheme), Some(authority), Some(path)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(Denial::MalformedToken);
    };
    let mcp = if is_mcp {
        let (Some(mcp_method), Some(mcp_name)) = (fields.next(), fields.next()) else {
            return Err(Denial::MalformedToken);
        };
        Some(McpFacts {
            method: mcp_method,
            name: mcp_name,
        })
    } else {
        None
    };
    if fields.next().is_some() {
        return Err(Denial::MalformedToken);
    }
    canonicalize_stored(&RequestFacts {
        method,
        scheme,
        authority,
        path,
        mcp,
    })
    .map_err(|_| Denial::MalformedToken)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::test_support::{facts, mcp_facts};
    use crate::{canonicalize, learn};
    use alloc::format;
    use alloc::vec;

    fn observe(method: &str, scheme: &str, authority: &str, path: &str) -> Target {
        canonicalize(&facts(method, scheme, authority, path)).unwrap()
    }

    /// An MCP call to `https://mcp.example.com/mcp`.
    fn call(mcp_method: &str, mcp_name: &str) -> Target {
        canonicalize(&mcp_facts(
            "POST",
            "https",
            "mcp.example.com",
            "/mcp",
            mcp_method,
            mcp_name,
        ))
        .unwrap()
    }

    fn get(path: &str) -> Target {
        observe("GET", "https", "example.com", path)
    }

    /// A token sealed from real observations: the only way tests get a valid one.
    fn sealed(observed: &[Target]) -> String {
        encode(&learn(observed)).unwrap()
    }

    /// The same, as a `v2` token sealed for one run.
    fn sealed_for(run: &str, observed: &[Target]) -> String {
        encode_for(run_id(run), &learn(observed)).unwrap()
    }

    fn run_id(text: &str) -> RunId<'_> {
        RunId::new(text.as_bytes()).unwrap()
    }

    /// Present, then check: the two steps every caller takes, in one place.
    fn token_lists(token: &[u8], target: &Target) -> Result<bool, Denial> {
        lists(present(token)?.caveats(), target)
    }

    fn assert_denied(tokens: &[&str], denial: Denial) {
        for token in tokens {
            assert_eq!(
                token_lists(token.as_bytes(), &get("/")),
                Err(denial),
                "{token:?}"
            );
        }
    }

    #[test]
    fn the_v1_format_is_as_documented() {
        let token = sealed(&[
            observe("POST", "https", "example.com", "/orders"),
            observe("GET", "https", "example.com", "/orders?page=2"),
            observe("GET", "http", "[::1]:8080", "/caf%C3%A9/"),
            observe("PUT", "https", "example.com:8443", "/orders"),
        ]);
        assert_eq!(
            token,
            "v1;http GET http [::1]:8080 /caf%C3%A9/;http GET https example.com /orders;\
             http POST https example.com /orders;http PUT https example.com:8443 /orders"
        );
    }

    #[test]
    fn an_empty_caveat_set_is_just_the_version() {
        assert_eq!(sealed(&[]), "v1");
        assert_eq!(token_lists(b"v1", &get("/")), Ok(false));
    }

    #[test]
    fn a_sealed_token_lists_what_was_learned_and_nothing_else() {
        let token = sealed(&[get("/a"), get("/b/")]);
        assert_eq!(token_lists(token.as_bytes(), &get("/a")), Ok(true));
        assert_eq!(token_lists(token.as_bytes(), &get("/b/")), Ok(true));
        assert_eq!(token_lists(token.as_bytes(), &get("/b")), Ok(false));
        assert_eq!(token_lists(token.as_bytes(), &get("/")), Ok(false));
    }

    #[test]
    fn decoding_gives_back_the_learned_set() {
        let set = learn(&[
            get("/a"),
            get("/b"),
            observe("PUT", "http", "x", "/"),
            observe("PUT", "http", "x:443", "/"),
            observe("GET", "https", "example.com:80", "/"),
        ]);
        let token = encode(&set).unwrap();
        assert_eq!(
            decode(present(token.as_bytes()).unwrap().caveats()),
            Ok(set)
        );
    }

    #[test]
    fn empty_token_is_denied() {
        assert_eq!(token_lists(b"", &get("/")), Err(Denial::EmptyToken));
    }

    #[test]
    fn over_long_token_is_denied_before_reading() {
        let token = vec![b'x'; MAX_TOKEN_BYTES + 1];
        assert_eq!(token_lists(&token, &get("/")), Err(Denial::TokenTooLong));
    }

    #[test]
    fn a_token_at_the_limit_is_read() {
        // Two caveats whose paths fill the token to exactly MAX_TOKEN_BYTES:
        // "v1" + 2 x ";http GET https example.com " is 58 bytes.
        let path_len = (MAX_TOKEN_BYTES - 58) / 2;
        let first = get(&format!("/a{}", "x".repeat(path_len - 2)));
        let second = get(&format!("/b{}", "x".repeat(path_len - 2)));
        let token = sealed(&[first.clone(), second]);
        assert_eq!(token.len(), MAX_TOKEN_BYTES);
        assert_eq!(token_lists(token.as_bytes(), &first), Ok(true));
    }

    #[test]
    fn the_longest_authority_reads_back() {
        // The host limit leaves room for a five-digit port in the authority.
        let authority = "a".repeat(253) + ":65535";
        let target = observe("GET", "https", &authority, "/");
        let token = sealed(core::slice::from_ref(&target));
        assert_eq!(token_lists(token.as_bytes(), &target), Ok(true));
    }

    #[test]
    fn sealing_more_than_fits_is_refused() {
        let long = |i: usize| get(&format!("/{i}{}", "a".repeat(4000)));
        assert!(encode(&learn(&[long(0)])).is_ok());
        assert_eq!(
            encode(&learn(&[long(0), long(1), long(2)])),
            Err(SealError::TokenTooLong)
        );
    }

    #[test]
    fn unknown_versions_are_denied() {
        assert_denied(
            &[
                "v3",
                "v3;http GET https example.com /",
                "V1",
                "V2",
                "v10",
                "v20",
                "v1 ",
                "v2 ",
                " v1",
                "1",
                "x",
                ";",
                "v",
                "v1\n",
            ],
            Denial::UnknownVersion,
        );
    }

    // --- v2 and the run id -------------------------------------------------------

    #[test]
    fn the_v2_format_is_as_documented() {
        let token = sealed_for(
            "run-1",
            &[
                observe("POST", "https", "example.com", "/orders"),
                observe("GET", "https", "example.com", "/orders?page=2"),
            ],
        );
        assert_eq!(
            token,
            "v2;run-1;http GET https example.com /orders;\
             http POST https example.com /orders"
        );
        assert_eq!(token_lists(token.as_bytes(), &get("/orders")), Ok(true));
    }

    #[test]
    fn a_v2_token_carries_the_run_and_a_v1_token_carries_none() {
        let with_run = sealed_for("run-1", &[get("/a")]);
        let presented = present(with_run.as_bytes()).unwrap();
        assert_eq!(presented.run().map(|run| run.as_str()), Some("run-1"));

        let without = sealed(&[get("/a")]);
        assert_eq!(present(without.as_bytes()).unwrap().run(), None);
    }

    #[test]
    fn an_empty_caveat_set_is_the_version_and_the_run() {
        let token = sealed_for("r-1", &[]);
        assert_eq!(token, "v2;r-1");
        assert_eq!(token_lists(token.as_bytes(), &get("/")), Ok(false));
        assert_eq!(
            present(token.as_bytes()).unwrap().caveats(),
            Caveats { body: None }
        );
    }

    /// As an equality rather than a claim: the run id changes the token's bytes
    /// and changes nothing the checker sees. The caveat region is byte for byte the same
    /// under every id, and the same as the `v1` token's.
    #[test]
    fn the_run_id_changes_no_verdict_and_no_caveat_byte() {
        let observed = [get("/a"), get("/b")];
        let plain = sealed(&observed);
        let plain_region = present(plain.as_bytes()).unwrap().caveats();
        for id in ["r-1", "r-2", "R-1", "a", &"z".repeat(MAX_RUN_ID_BYTES)] {
            let token = sealed_for(id, &observed);
            let presented = present(token.as_bytes()).unwrap();
            assert_eq!(presented.caveats(), plain_region, "run {id:?}");
            for (path, expected) in [("/a", true), ("/b", true), ("/c", false)] {
                assert_eq!(
                    lists(presented.caveats(), &get(path)),
                    Ok(expected),
                    "run {id:?} path {path:?}"
                );
            }
        }
    }

    /// The bytes handed to `check` do not carry the id, whatever the id is. This is the
    /// "by construction" half of the guarantee; the "by type" half is a compile error
    /// and is checked by hand (see `the_run_id_is_unreachable_from_check`).
    ///
    /// The claim is region *equality* with the `v1` token, not the absence of the id's
    /// bytes: an id may legitimately spell something a caveat also contains (`http`,
    /// `GET`), so a substring search would fail on a correct implementation. Equality is
    /// the stronger statement anyway — the region carries nothing the version or the id
    /// put there.
    #[test]
    fn the_caveat_region_is_the_same_bytes_whatever_the_run_is() {
        let observed = [get("/a"), get("/b")];
        let plain = sealed(&observed);
        let expected = present(plain.as_bytes()).unwrap().caveats().body;
        assert_eq!(
            expected,
            plain.as_bytes().get(3..),
            "the v1 region is everything after \"v1;\""
        );
        for id in ["run-1", "http", "GET", "example", "v1", "0"] {
            let token = sealed_for(id, &observed);
            let region = present(token.as_bytes()).unwrap().caveats().body;
            assert_eq!(region, expected, "run {id:?}");
        }
    }

    /// A NOTE, not a test that runs: the "by type" half of the guarantee is a compile
    /// error, and checking it needs a crate that must fail to build. The repo does not
    /// automate that, because a compile-fail test crate would pull in a proc-macro
    /// dependency, which the core does not allow. So it is recorded here, the
    /// same way the `Target` `E0603` check is recorded in `target.rs`, as a command to
    /// run by hand after changing this file:
    ///
    /// ```text
    /// cargo build -p gate 2>&1   # after adding, inside gate::check:
    /// //   let _ = caveats.body;
    /// # expected: error[E0616]: field `body` of struct `token::Caveats` is private
    /// ```
    #[test]
    fn the_run_id_is_unreachable_from_check() {
        // Inside this crate the field is reachable: the barrier is
        // the crate boundary, not an accessor someone could add without noticing.
        let token = sealed_for("r-1", &[get("/a")]);
        let region = present(token.as_bytes()).unwrap().caveats();
        assert!(region.body.is_some());
    }

    #[test]
    fn a_debug_of_the_caveat_region_prints_no_bytes() {
        let token = sealed_for("r-secret", &[get("/private")]);
        let printed = format!("{:?}", present(token.as_bytes()).unwrap().caveats());
        assert!(!printed.contains("private"), "{printed}");
        assert!(!printed.contains("r-secret"), "{printed}");
    }

    #[test]
    fn malformed_run_ids_are_denied() {
        assert_denied(
            &[
                // No id at all.
                "v2",
                "v2;",
                "v2;;http GET https example.com /",
                // Bytes outside the alphabet: the token's own separators first.
                "v2;http GET https example.com /",
                "v2;r 1;http GET https example.com /",
                "v2;r.1",
                "v2;r/1",
                "v2;r:1",
                "v2;r\n1",
                "v2;r\u{e9}1",
                "v2;r%201",
            ],
            Denial::MalformedRunId,
        );
    }

    #[test]
    fn a_run_id_at_the_limit_reads_back_and_one_byte_over_denies() {
        let longest = "a".repeat(MAX_RUN_ID_BYTES);
        let token = sealed_for(&longest, &[get("/a")]);
        assert_eq!(
            present(token.as_bytes()).unwrap().run().map(|r| r.as_str()),
            Some(longest.as_str())
        );
        let over = "a".repeat(MAX_RUN_ID_BYTES.saturating_add(1));
        assert_eq!(
            RunId::new(over.as_bytes()),
            Err(Denial::MalformedRunId),
            "one byte over the limit"
        );
        assert_eq!(
            token_lists(
                format!("v2;{over};http GET https example.com /").as_bytes(),
                &get("/")
            ),
            Err(Denial::MalformedRunId)
        );
    }

    #[test]
    fn a_run_id_is_never_folded() {
        assert_ne!(run_id("r-1"), run_id("R-1"));
        assert_eq!(run_id("R-1").as_str(), "R-1");
    }

    #[test]
    fn the_alphabet_is_exactly_what_is_documented() {
        for byte in 0u8..=255 {
            let allowed = byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_';
            assert_eq!(
                RunId::new(&[byte]).is_ok(),
                allowed,
                "byte {byte:#04x} ({:?})",
                char::from(byte)
            );
        }
        assert_eq!(RunId::new(b""), Err(Denial::MalformedRunId));
    }

    /// A `v2` token is checked by exactly the `v1` rules: the run id buys a caveat
    /// nothing, and a caveat that would deny under `v1` denies under `v2` too.
    #[test]
    fn a_v2_token_gets_no_leniency_from_its_run_id() {
        assert_denied(
            &[
                "v2;r-1;http GET HTTPS example.com /",
                "v2;r-1;http GET https Example.com /",
                "v2;r-1;http GET https example.com:443 /",
                "v2;r-1;http GET https example.com /a?x=1",
                "v2;r-1;http GET https example.com /;http GET https example.com /",
                "v2;r-1;http GET https example.com /b;http GET https example.com /a",
            ],
            Denial::MalformedToken,
        );
        assert_denied(&["v2;r-1;queue orders.created"], Denial::UnknownCaveatKind);
    }

    #[test]
    fn a_v2_token_at_the_byte_limit_is_refused_rather_than_truncated() {
        let long = |i: usize| get(&format!("/{i}{}", "a".repeat(4000)));
        let run = run_id("r-1");
        assert!(encode_for(run, &learn(&[long(0)])).is_ok());
        assert_eq!(
            encode_for(run, &learn(&[long(0), long(1), long(2)])),
            Err(SealError::TokenTooLong)
        );
    }

    #[test]
    fn malformed_v1_bodies_are_denied() {
        // Hand-written, and each one is not what `seal` would write.
        assert_denied(
            &[
                "v1;",
                "v1;;",
                "v1;http GET https example.com /;",
                "v1;http GET https example.com",
                "v1;http GET https example.com / extra",
                "v1;http GET  https example.com /",
                "v1;http GET https example.com /a b",
                "v1;http",
                "v1;http ",
                "v1; http GET https example.com /",
                "v1;HTTP GET https example.com /",
                "v1;Http GET https example.com /",
                "v1;ht_tp GET https example.com /",
                "v1;ht.tp GET https example.com /",
                "v1;GET https example.com 443 /",
                "v1;http GET HTTPS example.com /",
                "v1;http GET https Example.com /",
                "v1;http GET https EXAMPLE.COM /",
                "v1;http GET https [2001:DB8::1] /",
                "v1;http GET Https example.com /",
                "v1;http GET https example.com:443 /",
                "v1;http GET http example.com:80 /",
                "v1;http GET https example.com:0443 /",
                "v1;http GET https example.com:0 /",
                "v1;http GET https example.com:70000 /",
                "v1;http GET https example.com: /",
                "v1;http GET https example.com 443 /",
                "v1;http GET https 127.1 /",
                "v1;http GET https [0::1] /",
                "v1;http GET https example.com /caf%c3%a9",
                "v1;http GET https example.com /a?x=1",
                "v1;http GET https example.com /a#x",
                "v1;http GET https example.com /../a",
                "v1;http GET https example.com //a",
                "v1;http GET https example.com a",
                "v1;http GET https example.com /%61",
                "v1;http GET ftp example.com /",
                "v1;http G(T https example.com /",
                "v1;http GET https ex@mple.com /",
                "v1;http GET https example.com. /",
                "v1;http GET https example.com /\u{e9}",
                "v1;http GET https example.com /\n",
            ],
            Denial::MalformedToken,
        );
    }

    #[test]
    fn unknown_caveat_kinds_are_denied() {
        // Well-formed kinds this build does not know: a later format addition, never
        // skipped, so the whole token denies even when another caveat would match.
        // The kind is read before its body, so an unknown kind is named as such
        // whatever follows it.
        assert_denied(
            &[
                "v1;queue orders.created",
                "v1;queue",
                "v1;tcp example.com 8443",
                "v1;https GET https example.com /",
                "v1;http2 GET https example.com /",
                "v1;mcp2 POST https mcp.example.com /mcp tools/call get_document",
                "v1;0 x",
                "v1;-",
                "v1;http GET https example.com /;queue orders.created",
                "v1;queue orders.created;http GET https example.com /",
            ],
            Denial::UnknownCaveatKind,
        );
        let token = sealed(&[get("/")]) + ";jsonrpc tools/call";
        assert_eq!(
            token_lists(token.as_bytes(), &get("/")),
            Err(Denial::UnknownCaveatKind)
        );
    }

    #[test]
    fn the_mcp_kind_is_as_documented() {
        let token = sealed(&[call("tools/call", "get_document")]);
        assert_eq!(
            token,
            "v1;mcp POST https mcp.example.com /mcp tools/call get_document"
        );
        assert_eq!(
            token_lists(token.as_bytes(), &call("tools/call", "get_document")),
            Ok(true)
        );
    }

    /// A value carrying a space or a `;` is expressible, and has exactly one stored
    /// spelling.
    #[test]
    fn a_value_with_a_separator_seals_and_reads_back() {
        for (wire, stored) in [
            ("us west 1", "us%20west%201"),
            ("file:///a;b", "file:///a%3Bb"),
            ("a%20b", "a%2520b"),
        ] {
            let target = call("tools/call", wire);
            let token = sealed(core::slice::from_ref(&target));
            assert_eq!(
                token,
                format!("v1;mcp POST https mcp.example.com /mcp tools/call {stored}"),
                "{wire:?}"
            );
            assert_eq!(token_lists(token.as_bytes(), &target), Ok(true), "{wire:?}");
            // The stored spelling is not a wire spelling: sent as one it is a different
            // value, and the caveat does not list it.
            let other = call("tools/call", stored);
            assert_eq!(token_lists(token.as_bytes(), &other), Ok(false), "{wire:?}");
        }
    }

    /// The headline the kind exists for: at HTTP depth these two requests are the same
    /// bytes, and at MCP depth they are two destinations.
    #[test]
    fn the_same_post_with_two_operations_is_two_caveats() {
        let token = sealed(&[
            call("tools/call", "get_document"),
            call("tools/call", "delete_document"),
            call("resources/read", "file:///a"),
        ]);
        assert_eq!(
            token,
            "v1;mcp POST https mcp.example.com /mcp resources/read file:///a;\
             mcp POST https mcp.example.com /mcp tools/call delete_document;\
             mcp POST https mcp.example.com /mcp tools/call get_document"
        );
        let only_get = sealed(&[call("tools/call", "get_document")]);
        assert_eq!(
            token_lists(only_get.as_bytes(), &call("tools/call", "get_document")),
            Ok(true)
        );
        for other in [
            call("tools/call", "delete_document"),
            call("resources/read", "get_document"),
            call("prompts/get", "get_document"),
        ] {
            assert_eq!(token_lists(only_get.as_bytes(), &other), Ok(false));
        }
    }

    /// The two kinds never stand in for each other, in either direction.
    #[test]
    fn an_mcp_caveat_does_not_list_the_post_underneath_it() {
        let mcp = sealed(&[call("tools/call", "get_document")]);
        let post = observe("POST", "https", "mcp.example.com", "/mcp");
        assert_eq!(token_lists(mcp.as_bytes(), &post), Ok(false));

        let http = sealed(core::slice::from_ref(&post));
        assert_eq!(
            token_lists(http.as_bytes(), &call("tools/call", "get_document")),
            Ok(false)
        );
        assert_eq!(token_lists(http.as_bytes(), &post), Ok(true));
    }

    /// Both kinds in one token, ordered and read back.
    #[test]
    fn a_token_may_hold_both_kinds() {
        let token = sealed(&[
            observe("GET", "https", "mcp.example.com", "/health"),
            call("tools/call", "get_document"),
        ]);
        assert_eq!(
            token,
            "v1;http GET https mcp.example.com /health;\
             mcp POST https mcp.example.com /mcp tools/call get_document"
        );
        assert_eq!(
            token_lists(token.as_bytes(), &call("tools/call", "get_document")),
            Ok(true)
        );
        assert_eq!(
            token_lists(
                token.as_bytes(),
                &observe("GET", "https", "mcp.example.com", "/health")
            ),
            Ok(true)
        );
    }

    #[test]
    fn malformed_mcp_bodies_are_denied() {
        // Hand-written, and each one is not what `seal` would write.
        assert_denied(
            &[
                // The wrong number of fields, either way. A space still ends a field,
                // which is exactly why a value carrying one is stored encoded.
                "v1;mcp POST https mcp.example.com /mcp",
                "v1;mcp POST https mcp.example.com /mcp tools/call",
                "v1;mcp POST https mcp.example.com /mcp tools/call get_document extra",
                "v1;mcp POST https mcp.example.com /mcp tools/call get document",
                "v1;mcp ",
                // The HTTP half still runs through every HTTP rule.
                "v1;mcp POST HTTPS mcp.example.com /mcp tools/call get_document",
                "v1;mcp POST https MCP.example.com /mcp tools/call get_document",
                "v1;mcp POST https mcp.example.com:443 /mcp tools/call get_document",
                "v1;mcp POST https mcp.example.com /m%63p tools/call get_document",
                // And the MCP half runs through every rule about a *stored* value: an
                // empty one, a byte encoded that did not have to be, lowercase hex, and
                // an escape that names nothing.
                "v1;mcp POST https mcp.example.com /mcp tools/call ",
                "v1;mcp POST https mcp.example.com /mcp  get_document",
                "v1;mcp POST https mcp.example.com /mcp tools/call get%5Fdocument",
                "v1;mcp POST https mcp.example.com /mcp tools/call get%3bdocument",
                "v1;mcp POST https mcp.example.com /mcp tools/call get%2",
                "v1;mcp POST https mcp.example.com /mcp tools/call get%ZZdocument",
            ],
            Denial::MalformedToken,
        );
        // MCP header *values* are case-sensitive, so `TOOLS/CALL` is a well-formed
        // caveat naming a different operation, not a malformed one. Nothing is folded.
        let shouting = "v1;mcp POST https mcp.example.com /mcp TOOLS/CALL get_document";
        assert_eq!(
            token_lists(shouting.as_bytes(), &call("tools/call", "get_document")),
            Ok(false)
        );
        assert_eq!(
            token_lists(shouting.as_bytes(), &call("TOOLS/CALL", "get_document")),
            Ok(true)
        );
        // The sentinel is a *wire* spelling and never reaches a caveat body. A value
        // that reads as a wrapper travels wrapped and is stored as the value itself,
        // and the wrapper's own bytes are an ordinary different value.
        let stored = "v1;mcp POST https mcp.example.com /mcp tools/call =?BASE64?Zm9v?=";
        assert_eq!(
            token_lists(
                stored.as_bytes(),
                &call("tools/call", "=?base64?PT9CQVNFNjQ/Wm05dj89?=")
            ),
            Ok(true)
        );
        let wrapper_as_a_value =
            "v1;mcp POST https mcp.example.com /mcp tools/call =?base64?PT9CQVNFNjQ/Wm05dj89?=";
        assert_eq!(
            token_lists(
                wrapper_as_a_value.as_bytes(),
                &call("tools/call", "=?base64?PT9CQVNFNjQ/Wm05dj89?=")
            ),
            Ok(false)
        );
    }

    /// An `mcp` caveat sorts after every `http` one, and repeats and unsorted pairs
    /// deny the same way they do for `http`.
    #[test]
    fn mcp_caveats_are_sorted_and_unrepeated() {
        assert_denied(
            &[
                "v1;mcp POST https mcp.example.com /mcp tools/call a;\
                 mcp POST https mcp.example.com /mcp tools/call a",
                "v1;mcp POST https mcp.example.com /mcp tools/call b;\
                 mcp POST https mcp.example.com /mcp tools/call a",
                "v1;mcp POST https mcp.example.com /mcp tools/call a;\
                 http GET https mcp.example.com /health",
            ],
            Denial::MalformedToken,
        );
    }

    #[test]
    fn repeated_or_unsorted_caveats_are_denied() {
        assert_denied(
            &[
                "v1;http GET https example.com /;http GET https example.com /",
                "v1;http GET https example.com /b;http GET https example.com /a",
                "v1;http POST https example.com /;http GET https example.com /",
                "v1;http GET https example.com:8443 /;http GET https example.com /",
            ],
            Denial::MalformedToken,
        );
    }

    #[test]
    fn port_order_is_numeric_not_textual() {
        // 80 sorts before 443 as a number, after it as text; the sealed order is numeric.
        let token = sealed(&[
            observe("GET", "https", "example.com", "/"),
            observe("GET", "https", "example.com:80", "/"),
        ]);
        assert_eq!(
            token,
            "v1;http GET https example.com:80 /;http GET https example.com /"
        );
        assert_eq!(token_lists(token.as_bytes(), &get("/")), Ok(true));
    }

    #[test]
    fn a_malformed_caveat_denies_even_when_an_earlier_one_matches() {
        let token = sealed(&[get("/a")]) + ";http GET https example.com /../b";
        assert_eq!(
            token_lists(token.as_bytes(), &get("/a")),
            Err(Denial::MalformedToken)
        );
    }

    #[test]
    fn non_utf8_token_bytes_are_denied() {
        assert_eq!(
            token_lists(b"v1;http GET https example.com /\xff", &get("/")),
            Err(Denial::MalformedToken)
        );
        assert_eq!(
            token_lists(b"v1;\xff GET https example.com /", &get("/")),
            Err(Denial::MalformedToken)
        );
        assert_eq!(
            token_lists(b"\xffv1", &get("/")),
            Err(Denial::UnknownVersion)
        );
    }
}
