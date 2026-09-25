//! The token's byte format. This is the only module that knows it.
//!
//! The format is `v1` and is expected to be replaced (probably by a standard format)
//! later. Everything else goes through [`encode`] and [`token_lists`], so that change
//! stays inside this file.
//!
//! # The `v1` grammar
//!
//! In ABNF (RFC 5234), where `SP` is one space:
//!
//! ```text
//! token     = "v1" *( ";" caveat )
//! caveat    = kind SP body
//! kind      = 1*( %x61-7A / DIGIT / "-" )   ; lowercase letters, digits, "-"
//! body      = http-body / mcp-body          ; one per kind this build knows
//! http-body = method SP scheme SP authority SP path
//! mcp-body  = http-body SP mcp-method SP mcp-name
//! ```
//!
//! For example, a token allowing two destinations:
//!
//! ```text
//! v1;http GET https example.com /orders;http POST https example.com:8443 /orders
//! ```
//!
//! and one allowing a single MCP tool call:
//!
//! ```text
//! v1;mcp POST https mcp.example.com /mcp tools/call get_document
//! ```
//!
//! - Every caveat starts with its kind, so a later kind of destination (for example a
//!   JSON-RPC operation or a queue topic) can be added as a new kind with its own body,
//!   without changing how `v1` tokens are read. A well-formed kind this build does not
//!   know denies the whole token (`UnknownCaveatKind`): a gate never skips a caveat it
//!   cannot read.
//! - Each field is exactly what the canonicalizer produces for it. The authority is the
//!   host, plus `:port` only when the port is not the scheme's default, which is the
//!   one spelling the canonicalizer accepts back. An `mcp` caveat is an `http` caveat's
//!   four fields followed by the two MCP header values, in that order, because an MCP
//!   call is an HTTP request plus the operation it names.
//! - Caveats are in ascending order with no repeats, so a caveat set has exactly one
//!   token. A token with zero caveats (`v1`) is valid and allows nothing.
//! - No escaping is needed: `;` and space never appear in a canonical field (a method
//!   is an RFC 9110 token, which excludes both; a host is letters, digits, `-`, `_`,
//!   `.` or a bracketed IPv6 literal; a port is digits; a path denies `;` and has
//!   spaces percent-encoded; an MCP value is visible ASCII other than `;`). Every byte
//!   is printable ASCII, so the token fits in an HTTP header value.
//! - The token has no flags, modes, wildcards or options. It only lists destinations;
//!   it never changes how it is checked. The kind says what a caveat is, not
//!   how to check it.
//!
//! Decoding is strict: anything [`encode`] would not have written, byte for byte, is
//! denied. Each stored caveat is read back through the canonicalizer's rules, so the
//! `http` kind in `v1` means "an HTTP target under this rule set": a rule that is
//! later tightened makes old caveats deny, and a rule may never be widened without a new
//! kind (see `canonical.rs`).
//!
//! The token is not signed yet. The grammar above is public, so anyone who can write
//! the token header can list any canonical target by hand, and [`token_lists`] will
//! honor it.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{canonicalize, CaveatSet, Denial, HttpTarget, McpFacts, RequestFacts, Target};

/// The longest token accepted, in bytes. Checked before the token is read.
/// 8 KiB fits in a single HTTP header on common servers and proxies.
pub const MAX_TOKEN_BYTES: usize = 8192;

const VERSION: &[u8] = b"v1";
const CAVEAT_SEPARATOR: u8 = b';';
const FIELD_SEPARATOR: u8 = b' ';

/// The kind tag of an HTTP caveat.
const HTTP_KIND: &[u8] = b"http";

/// The kind tag of an MCP caveat.
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

/// Writes a caveat set as a token. Stops as soon as the token would be longer than
/// [`MAX_TOKEN_BYTES`], so a huge set costs no more than one token's worth of writing.
pub fn encode(set: &CaveatSet) -> Result<String, SealError> {
    let mut token = String::from("v1");
    for caveat in set.caveats() {
        token.push(char::from(CAVEAT_SEPARATOR));
        write_caveat(&mut token, caveat.target());
        if token.len() > MAX_TOKEN_BYTES {
            return Err(SealError::TokenTooLong);
        }
    }
    Ok(token)
}

/// Reads a token and says whether it lists `target`.
///
/// The target comes only from the caller, never from the token. The decoded caveat set
/// never leaves this module, so a hand-written token can never be turned into a
/// caveat set and sealed again. It can still be checked, and until tokens are signed
/// a hand-written token that lists a target in canonical form allows it.
pub fn token_lists(token: &[u8], target: &Target) -> Result<bool, Denial> {
    Ok(decode(token)?.lists(target))
}

fn write_caveat(out: &mut String, target: &Target) {
    let separator = char::from(FIELD_SEPARATOR);
    // The kind tags are ASCII, so each byte is one char.
    let kind = match target {
        Target::Http(_) => HTTP_KIND,
        Target::Mcp(_) => MCP_KIND,
    };
    out.extend(kind.iter().map(|&byte| char::from(byte)));
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

fn decode(token: &[u8]) -> Result<CaveatSet, Denial> {
    if token.is_empty() {
        return Err(Denial::EmptyToken);
    }
    if token.len() > MAX_TOKEN_BYTES {
        return Err(Denial::TokenTooLong);
    }
    let mut pieces = token.split(|&byte| byte == CAVEAT_SEPARATOR);
    if pieces.next() != Some(VERSION) {
        return Err(Denial::UnknownVersion);
    }
    let mut targets: Vec<Target> = Vec::new();
    for piece in pieces {
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
    canonicalize(&RequestFacts {
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
    use crate::learn;
    use crate::target::test_support::{facts, mcp_facts};
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
        assert_eq!(decode(token.as_bytes()), Ok(set));
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
                "v2",
                "v2;http GET https example.com /",
                "V1",
                "v10",
                "v1 ",
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
                // The wrong number of fields, either way.
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
                // And the MCP half runs through every MCP rule.
                "v1;mcp POST https mcp.example.com /mcp tools/call =?base64?Z2V0X2RvY3VtZW50?=",
                "v1;mcp POST https mcp.example.com /mcp tools/call =?BASE64?Zm9v?=",
                "v1;mcp POST https mcp.example.com /mcp tools/call =?base64?PT9CQVNFNjQ_Wm05dj89?=",
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
        // A value that reads as a wrapper travels wrapped, and reads back byte for byte.
        let wrapped =
            "v1;mcp POST https mcp.example.com /mcp tools/call =?base64?PT9CQVNFNjQ/Wm05dj89?=";
        assert_eq!(
            token_lists(
                wrapped.as_bytes(),
                &call("tools/call", "=?base64?PT9CQVNFNjQ/Wm05dj89?=")
            ),
            Ok(true)
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
