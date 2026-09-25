//! The canonicalizer's invariants, each pinned by a test named after it.
//!
//! No dependency and no second URL parser: correctness comes from the invariants
//! themselves, checked over a fixed-seed stream of hostile requests built from the
//! spellings that trip real parsers up (encoded dots and slashes, backslashes, `..;`,
//! tabs, non-ASCII, `0x7f`, brackets, `@`, upper- and lowercase hex, explicit ports,
//! numeric hosts), plus raw random bytes up to and past every limit.
//!
//! - **Idempotence**: writing a target back as a request and canonicalizing it again
//!   gives the same target, and writing that back gives the same bytes.
//! - **No merge**: if two requests get the same target, their method, scheme, host and
//!   path bytes are identical (nothing is case-folded), and their ports are equal (an
//!   absent port counting as the scheme's default). The query is the one named
//!   exception: it is dropped, so requests that differ only there share a target on
//!   purpose.
//! - **Totality and bounded cost**: any bytes, up to and past the limits, give a target
//!   or a named denial, never a panic, and a target is never longer than the limits.
//! - **One value, one spelling** (the `mcp` kind): no two accepted `Mcp-Method` or
//!   `Mcp-Name` byte strings stand for the same value. That is the same no-merge rule
//!   one layer in, where MCP's base64 wrapper would otherwise give one value two names.
//!
//! Half the hostile requests carry MCP header values as well, so every invariant sees
//! both kinds of target.
//!
//! The fixed seed makes every run identical, so a failure reproduces.

// A test binary: panicking is how a test fails. clippy.toml already exempts `#[test]`
// functions from the panic lints; this extends that to the helpers they call.
#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;

use gate::{
    observe, Denial, HttpTarget, McpFacts, RequestFacts, Target, MAX_AUTHORITY_BYTES,
    MAX_MCP_METHOD_BYTES, MAX_MCP_NAME_BYTES, MAX_METHOD_BYTES, MAX_PATH_BYTES, MAX_SCHEME_BYTES,
};

/// How many hostile requests each invariant sees. A few seconds in a debug build.
const HOSTILE_ROUNDS: usize = 200_000;

/// How many raw random-byte requests the totality test sees.
const RANDOM_ROUNDS: usize = 100_000;

/// xorshift64 (Marsaglia, 2003): tiny, deterministic, good enough to pick test bytes.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

const METHODS: &[&str] = &["GET", "get", "POST", "M-SEARCH", "G\tT", ""];
// Lowercase is weighted up: uppercase is always denied, and the invariants need
// plenty of accepted requests to compare.
const SCHEMES: &[&str] = &[
    "http", "https", "http", "https", "http", "https", "HTTP", "hTTps", "HTTPS", "ftp",
];
const HOST_PIECES: &[&str] = &[
    "a", "B", "x", "X", ".", "-", "_", "0", "1", "7", "f", "F", ":", "8", "4", "3", "@", "[", "]",
    "::", "::1", "%41", "\u{e9}", "xn--", "127", "0x7f", "0X7F", "255", "256", "01", "Example",
    "com", "\t", " ", "\u{7f}",
];
const HOSTS: &[&str] = &[
    "example.com",
    "example.com",
    "example.com",
    "a.b",
    "[2001:db8::1]",
    "Example.COM",
    "127.0.0.1",
    "127.1",
    "0x7f.0.0.1",
    "2130706433",
    "127.0.0.01",
    "[::1]",
    "[0::1]",
    "[::FFFF:1]",
    "[2001:DB8::1]",
    "[0:0:0:0:0:0:0:1]",
    "[::ffff:192.0.2.1]",
    "user@example.com",
    "example.com.",
];
const PORTS: &[&str] = &[
    "", "", "", ":443", ":80", ":8443", ":0443", ":", ":0", ":65535", ":65536", ":1", ":+1",
];
const PATH_PIECES: &[&str] = &[
    "/", "/", "/", "a", "B", ".", "..", "%2e", "%2E", "%2f", "%2F", "%5c", "%5C", "%41", "%61",
    "%c3%a9", "%C3%A9", "%3a", "%3A", "%zz", "%", ";", "..;", "\\", "?", "#", "~", "\u{e9}", " ",
    "\t", "%25", "%3f", "%3F", ":", "@", "+", "!", "%7f", "%7F", "%00",
];
const QUERIES: &[&str] = &["", "", "?", "?a=1", "?a=%2F", "?..", "?#"];
/// MCP header values, spelled every way the rules have something to say about:
/// plain, wrapped, wrapped when it need not have been, wrapped badly, and carrying the
/// token's own separators.
const MCP_VALUES: &[&str] = &[
    // Accepted spellings are weighted up, the way SCHEMES is, so the invariants below
    // see plenty of accepted MCP targets to compare with each other.
    "tools/call",
    "tools/call",
    "tools/call",
    "resources/read",
    "resources/read",
    "prompts/get",
    "get_document",
    "get_document",
    "get_document",
    "delete_document",
    "delete_document",
    "file:///projects/myapp/config.json",
    "a.b-c_d",
    "A",
    "=?=",
    // "=?BASE64?Zm9v?=" wrapped: it reads as a wrapper, so this is its one spelling.
    "=?base64?PT9CQVNFNjQ/Wm05dj89?=",
    "=?base64?PT9CQVNFNjQ/Wm05dj89?=",
    // Denied spellings. The unit tests cover these exhaustively; here they are just
    // enough to keep the accepted set meaningful.
    "",
    "get document",
    "get;document",
    " get_document",
    "caf\u{e9}",
    // "get_document" wrapped: canonical base64, but it needed no wrapping.
    "=?base64?Z2V0X2RvY3VtZW50?=",
    // "get document" and "get;document" wrapped: the separators, smuggled.
    "=?base64?Z2V0IGRvY3VtZW50?=",
    "=?base64?Z2V0O2RvY3VtZW50?=",
    // The same value as the accepted wrapper above, sent plain.
    "=?BASE64?Zm9v?=",
    // base64url, unpadded, spare trailing bits, padding in the middle, empty.
    "=?base64?PT9CQVNFNjQ_Wm05dj89?=",
    "=?base64?PT9CQVNFNjQ/Wm05dj8?=",
    "=?base64?QR==?=",
    "=?base64?PT9CQVNFNjQ/=m05dj89?=",
    "=?base64??=",
    "=?base64?",
    "=?x?=",
];

/// A hostile request: method, scheme, authority, path including any query, and the two
/// MCP header values when it carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Hostile {
    fields: [String; 4],
    mcp: Option<[String; 2]>,
}

fn hostile(rng: &mut Rng) -> Hostile {
    Hostile {
        fields: hostile_http(rng),
        mcp: Some([
            rng.pick(MCP_VALUES).to_string(),
            rng.pick(MCP_VALUES).to_string(),
        ]),
    }
}

/// The same request twice: once as an ordinary HTTP request, once as the MCP call it
/// would be with those two header values. Every invariant runs over both, so neither
/// kind of target gets half the rounds.
fn both_kinds(request: &Hostile) -> [Hostile; 2] {
    [
        Hostile {
            fields: request.fields.clone(),
            mcp: None,
        },
        request.clone(),
    ]
}

fn hostile_http(rng: &mut Rng) -> [String; 4] {
    let method = rng.pick(METHODS).to_string();
    let scheme = rng.pick(SCHEMES).to_string();
    let host = if rng.below(2) == 0 {
        rng.pick(HOSTS).to_string()
    } else {
        let mut host = String::new();
        for _ in 0..rng.below(5) {
            host.push_str(rng.pick(HOST_PIECES));
        }
        if rng.below(2) == 0 {
            host = format!("ex{host}.com");
        }
        host
    };
    let authority = host + rng.pick(PORTS);
    let mut path = String::from("/");
    for _ in 0..rng.below(6) {
        path.push_str(rng.pick(PATH_PIECES));
    }
    path.push_str(rng.pick(QUERIES));
    [method, scheme, authority, path]
}

fn facts(request: &Hostile) -> RequestFacts<'_> {
    RequestFacts {
        method: request.fields[0].as_bytes(),
        scheme: request.fields[1].as_bytes(),
        authority: request.fields[2].as_bytes(),
        path: request.fields[3].as_bytes(),
        mcp: request.mcp.as_ref().map(|[method, name]| McpFacts {
            method: method.as_bytes(),
            name: name.as_bytes(),
        }),
    }
}

/// A target's HTTP destination and, for an MCP target, the operation it names. Every
/// invariant below reads a target through this, so neither kind is skipped.
fn parts(target: &Target) -> (&HttpTarget, Option<(&str, &str)>) {
    match (target.as_http(), target.as_mcp()) {
        (Some(http), None) => (http, None),
        (None, Some(mcp)) => (mcp.http(), Some((mcp.method(), mcp.name()))),
        _ => panic!("a target is exactly one kind: {target:?}"),
    }
}

/// The request a target writes back to, for the idempotence test.
fn written_back(target: &Target) -> Hostile {
    let (http, mcp) = parts(target);
    Hostile {
        fields: [
            http.method().to_string(),
            http.scheme().to_string(),
            http.authority(),
            http.path().to_string(),
        ],
        mcp: mcp.map(|(method, name)| [method.to_string(), name.to_string()]),
    }
}

/// What the no-merge invariant compares, computed from the raw request alone by a
/// simple, separate reading: method, scheme and host bytes exactly as sent, the port
/// (the scheme's default when absent), the path bytes before any `?`, and the MCP
/// header values exactly as sent.
type RawKey = (String, String, String, u16, String, Option<[String; 2]>);

fn raw_key(request: &Hostile) -> RawKey {
    let [method, scheme, authority, path] = &request.fields;
    // Accepted authorities hold at most one `:` outside an IPv6 literal's brackets.
    let port_at = match authority.find(']') {
        Some(close) => authority[close..].find(':').map(|at| close + at),
        None => authority.find(':'),
    };
    let (host, port) = match port_at {
        Some(at) => (&authority[..at], authority[at + 1..].parse().unwrap()),
        None => (authority.as_str(), if scheme == "https" { 443 } else { 80 }),
    };
    let path = path.split('?').next().unwrap_or_default();
    (
        method.clone(),
        scheme.clone(),
        host.to_string(),
        port,
        path.to_string(),
        request.mcp.clone(),
    )
}

/// What an MCP header value stands for, read separately from the canonicalizer: the
/// bytes a base64 wrapper holds, or the value itself. Deliberately permissive, so it is
/// an oracle rather than a second copy of the rule -- anything the canonicalizer accepts
/// it reads the same way, and it also reads spellings the canonicalizer denies.
fn mcp_value_stands_for(raw: &str) -> String {
    let Some(payload) = raw
        .strip_prefix("=?base64?")
        .and_then(|rest| rest.strip_suffix("?="))
    else {
        return raw.to_string();
    };
    let digits: Vec<u32> = payload
        .trim_end_matches('=')
        .chars()
        .map(|digit| {
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                .find(digit)
                .map_or(u32::MAX, |value| value as u32)
        })
        .collect();
    if digits.contains(&u32::MAX) {
        return raw.to_string();
    }
    let mut bits = String::new();
    for value in digits {
        bits.push_str(&format!("{value:06b}"));
    }
    let bytes: Vec<u8> = bits
        .as_bytes()
        .as_chunks::<8>()
        .0
        .iter()
        .map(|byte| u8::from_str_radix(std::str::from_utf8(byte).unwrap(), 2).unwrap())
        .collect();
    String::from_utf8(bytes).unwrap_or_else(|_| raw.to_string())
}

fn is_named_request_denial(denial: Denial) -> bool {
    matches!(
        denial,
        Denial::RequestTooLong
            | Denial::MalformedMethod
            | Denial::UnsupportedScheme
            | Denial::MalformedHost
            | Denial::MalformedPort
            | Denial::MalformedPath
            | Denial::MalformedMcpMethod
            | Denial::MalformedMcpName
    )
}

#[test]
fn idempotence_a_target_written_back_canonicalizes_to_itself() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut accepted = 0;
    for round in 0..HOSTILE_ROUNDS {
        for request in both_kinds(&hostile(&mut rng)) {
            let Ok(target) = observe(&facts(&request)) else {
                continue;
            };
            accepted += 1;
            let written = written_back(&target);
            let again = observe(&facts(&written))
                .unwrap_or_else(|denial| panic!("round {round}: {written:?} denied: {denial:?}"));
            assert_eq!(again, target, "round {round}: {request:?} then {written:?}");
            assert_eq!(written_back(&again), written, "round {round}: {request:?}");
        }
    }
    println!("idempotence: {HOSTILE_ROUNDS} rounds x both kinds, {accepted} accepted");
    assert!(
        accepted > 1_000,
        "the generator must reach accepted requests"
    );
}

#[test]
fn no_merge_one_target_means_the_same_method_scheme_host_port_and_path() {
    let mut rng = Rng(0x0DDB_A11C_AFE5_EED5);
    let mut seen: BTreeMap<Target, (RawKey, Hostile)> = BTreeMap::new();
    let (mut accepted, mut shared) = (0, 0);
    for round in 0..HOSTILE_ROUNDS {
        for request in both_kinds(&hostile(&mut rng)) {
            let Ok(target) = observe(&facts(&request)) else {
                continue;
            };
            accepted += 1;
            let key = raw_key(&request);
            match seen.get(&target) {
                Some((first_key, first_request)) => {
                    shared += 1;
                    assert_eq!(
                        key, *first_key,
                        "round {round}: {request:?} and {first_request:?} merged into {target:?}"
                    );
                }
                None => {
                    seen.insert(target, (key, request));
                }
            }
        }
    }
    println!(
        "no merge: {HOSTILE_ROUNDS} hostile requests, {accepted} accepted, {} distinct \
         targets, {shared} repeats of a target, 0 merges",
        seen.len()
    );
    assert!(
        shared > 1_000,
        "the generator must produce repeated targets"
    );
}

/// Random bytes, mostly short, sometimes right around `limit`.
fn random_bytes(rng: &mut Rng, limit: usize) -> Vec<u8> {
    let len = match rng.below(10) {
        0 => limit + rng.below(3),
        1 => limit.saturating_sub(rng.below(3)),
        _ => rng.below(24),
    };
    (0..len).map(|_| rng.next() as u8).collect()
}

/// Checks one request: a target inside the limits, or a named denial. Never panics
/// (a panic fails the test).
fn assert_total_and_bounded(request: &RequestFacts, context: &str) {
    match observe(request) {
        Ok(target) => {
            let (http, mcp) = parts(&target);
            assert!(http.method().len() <= MAX_METHOD_BYTES, "{context}");
            assert!(http.scheme().len() <= MAX_SCHEME_BYTES, "{context}");
            assert!(http.authority().len() <= MAX_AUTHORITY_BYTES, "{context}");
            assert!(http.path().len() <= MAX_PATH_BYTES, "{context}");
            if let Some((method, name)) = mcp {
                assert!(method.len() <= MAX_MCP_METHOD_BYTES, "{context}");
                assert!(name.len() <= MAX_MCP_NAME_BYTES, "{context}");
            }
        }
        Err(denial) => assert!(is_named_request_denial(denial), "{context}: {denial:?}"),
    }
}

#[test]
fn totality_and_bounded_cost_any_bytes_give_a_bounded_target_or_a_named_denial() {
    let mut rng = Rng(0x5EED_F070_A117_0001);
    for round in 0..RANDOM_ROUNDS {
        let fields = [
            random_bytes(&mut rng, MAX_METHOD_BYTES),
            random_bytes(&mut rng, MAX_SCHEME_BYTES),
            random_bytes(&mut rng, MAX_AUTHORITY_BYTES),
            random_bytes(&mut rng, MAX_PATH_BYTES),
            random_bytes(&mut rng, MAX_MCP_METHOD_BYTES),
            random_bytes(&mut rng, MAX_MCP_NAME_BYTES),
        ];
        let request = RequestFacts {
            method: &fields[0],
            scheme: &fields[1],
            authority: &fields[2],
            path: &fields[3],
            mcp: (round % 2 == 0).then_some(McpFacts {
                method: &fields[4],
                name: &fields[5],
            }),
        };
        assert_total_and_bounded(&request, &format!("random round {round}"));
    }
    let mut rng = Rng(0x7074_A10F_4057_11E5);
    for round in 0..HOSTILE_ROUNDS {
        for request in both_kinds(&hostile(&mut rng)) {
            assert_total_and_bounded(&facts(&request), &format!("hostile round {round}"));
        }
    }

    // The worst shapes, filled to exactly each limit and one byte past it: every byte
    // is one the canonicalizer has to look at, so these are its most expensive inputs.
    for fill in [
        "%", "%4", "%41", "%C3", "/", "/.", "a/", ":", "[", "]", ":0", "::", "1.", "0x", "@", "?",
        "#", "\u{e9}",
    ] {
        for extra in [0, 1] {
            let path = "/".to_string() + &fill.repeat(MAX_PATH_BYTES);
            let path = &path.as_bytes()[..MAX_PATH_BYTES + extra];
            let authority = fill.repeat(MAX_AUTHORITY_BYTES + 1);
            let authority = &authority.as_bytes()[..MAX_AUTHORITY_BYTES + extra];
            let bracketed = "[".to_string() + &fill.repeat(MAX_AUTHORITY_BYTES);
            let bracketed = &bracketed.as_bytes()[..MAX_AUTHORITY_BYTES + extra];
            for (authority, path) in [
                (b"example.com".as_slice(), path),
                (authority, b"/".as_slice()),
                (bracketed, b"/".as_slice()),
            ] {
                let mcp_fill = fill.repeat(MAX_MCP_NAME_BYTES + 1);
                let mcp_name = &mcp_fill.as_bytes()[..MAX_MCP_NAME_BYTES + extra];
                let request = RequestFacts {
                    method: b"GET",
                    scheme: b"https",
                    authority,
                    path,
                    mcp: Some(McpFacts {
                        method: b"tools/call",
                        name: mcp_name,
                    }),
                };
                assert_total_and_bounded(&request, &format!("fill {fill:?} + {extra}"));
                let request = RequestFacts {
                    mcp: None,
                    ..request
                };
                assert_total_and_bounded(&request, &format!("fill {fill:?} + {extra}"));
            }
        }
    }
}

/// One value, one spelling. MCP lets a header value travel plain or base64-wrapped, so
/// without a rule one destination would have two names -- the merge this project exists
/// to prevent, one layer in from the URL. The canonicalizer answers it by accepting only
/// the one spelling MCP leaves open for each value, so this test reads what each
/// accepted value *stands for* with a separate, deliberately permissive decoder and
/// requires that no two accepted spellings stand for the same thing.
#[test]
fn one_value_one_spelling_no_two_accepted_mcp_values_stand_for_the_same_thing() {
    let mut rng = Rng(0x11CE_11CE_B0B0_0001);
    // What each value stands for -> the one accepted spelling of it seen so far.
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut accepted = 0;
    for round in 0..HOSTILE_ROUNDS {
        let request = hostile(&mut rng);
        let Ok(target) = observe(&facts(&request)) else {
            continue;
        };
        let (_, Some((method, name))) = parts(&target) else {
            continue;
        };
        accepted += 1;
        for value in [method, name] {
            let stands_for = mcp_value_stands_for(value);
            match seen.get(&stands_for) {
                Some(first) => assert_eq!(
                    first, value,
                    "round {round}: {first:?} and {value:?} both stand for {stands_for:?}"
                ),
                None => {
                    seen.insert(stands_for, value.to_string());
                }
            }
        }
    }
    println!(
        "one value one spelling: {accepted} accepted MCP targets, {} distinct values",
        seen.len()
    );
    // Lower than the other invariants' floor on purpose: an MCP target needs the HTTP
    // half of a deliberately hostile request to be accepted *and* both header values to
    // be accepted, so the two populations are not comparable. Several hundred is plenty
    // for what this guard is for.
    assert!(
        accepted > 500,
        "the generator must reach accepted MCP calls"
    );
    // The corpus really does offer two spellings of one value, so the assertion above
    // had something to catch: "=?BASE64?Zm9v?=" is in it plain and wrapped.
    assert_eq!(
        seen.get("=?BASE64?Zm9v?=").map(String::as_str),
        Some("=?base64?PT9CQVNFNjQ/Wm05dj89?="),
        "only the wrapped spelling may be accepted"
    );
}
