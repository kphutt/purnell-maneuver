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
    observe, Denial, HttpTarget, RequestFacts, Target, MAX_AUTHORITY_BYTES, MAX_METHOD_BYTES,
    MAX_PATH_BYTES, MAX_SCHEME_BYTES,
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
/// A hostile request: method, scheme, authority, and path including any query.
type Hostile = [String; 4];

fn hostile(rng: &mut Rng) -> Hostile {
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

fn facts(fields: &Hostile) -> RequestFacts<'_> {
    RequestFacts {
        method: fields[0].as_bytes(),
        scheme: fields[1].as_bytes(),
        authority: fields[2].as_bytes(),
        path: fields[3].as_bytes(),
    }
}

fn http(target: &Target) -> &HttpTarget {
    target
        .as_http()
        .expect("every target is an HTTP target today")
}

/// What the no-merge invariant compares, computed from the raw request alone by a
/// simple, separate reading: method, scheme and host bytes exactly as sent, the port
/// (the scheme's default when absent), and the path bytes before any `?`.
type RawKey = (String, String, String, u16, String);

fn raw_key(fields: &Hostile) -> RawKey {
    let [method, scheme, authority, path] = fields;
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
    )
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
    )
}

#[test]
fn idempotence_a_target_written_back_canonicalizes_to_itself() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut accepted = 0;
    for round in 0..HOSTILE_ROUNDS {
        let request = hostile(&mut rng);
        let Ok(target) = observe(&facts(&request)) else {
            continue;
        };
        accepted += 1;
        let first = http(&target);
        let written = [
            first.method().to_string(),
            first.scheme().to_string(),
            first.authority(),
            first.path().to_string(),
        ];
        let again = observe(&facts(&written))
            .unwrap_or_else(|denial| panic!("round {round}: {written:?} denied: {denial:?}"));
        assert_eq!(again, target, "round {round}: {request:?} then {written:?}");
        let second = http(&again);
        let rewritten = [
            second.method().to_string(),
            second.scheme().to_string(),
            second.authority(),
            second.path().to_string(),
        ];
        assert_eq!(rewritten, written, "round {round}: {request:?}");
    }
    println!("idempotence: {HOSTILE_ROUNDS} hostile requests, {accepted} accepted");
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
        let request = hostile(&mut rng);
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
            let http = http(&target);
            assert!(http.method().len() <= MAX_METHOD_BYTES, "{context}");
            assert!(http.scheme().len() <= MAX_SCHEME_BYTES, "{context}");
            assert!(http.authority().len() <= MAX_AUTHORITY_BYTES, "{context}");
            assert!(http.path().len() <= MAX_PATH_BYTES, "{context}");
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
        ];
        let request = RequestFacts {
            method: &fields[0],
            scheme: &fields[1],
            authority: &fields[2],
            path: &fields[3],
        };
        assert_total_and_bounded(&request, &format!("random round {round}"));
    }
    let mut rng = Rng(0x7074_A10F_4057_11E5);
    for round in 0..HOSTILE_ROUNDS {
        let request = hostile(&mut rng);
        assert_total_and_bounded(&facts(&request), &format!("hostile round {round}"));
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
                let request = RequestFacts {
                    method: b"GET",
                    scheme: b"https",
                    authority,
                    path,
                };
                assert_total_and_bounded(&request, &format!("fill {fill:?} + {extra}"));
            }
        }
    }
}
