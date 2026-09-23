//! A fuzz loop with no dependencies: random bytes as the token and as every request
//! field, fed to `gate::check`.
//!
//! It asserts that `check` never panics and always returns `Allowed` or a named
//! `Denial`, and that random tokens never allow anything. A fixed seed keeps every run
//! the same, so a failure reproduces. This is a cheap stand-in for `cargo fuzz` (which
//! needs a nightly toolchain and a C toolchain) until one is wired in.

// A test binary: panicking is how a test fails. clippy.toml already exempts `#[test]`
// functions from the panic lints; this extends that to the helpers they call.
#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use gate::{check, observe, Denial, RequestFacts, Target};

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

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Bytes that matter to the canonicalizer or the token format, so random input hits
/// the interesting branches far more often than uniform bytes would.
const INTERESTING: &[u8] = b"%/.;: ?#@[]\\vV1GETgethps0123456789aAcCfFxXzZ-_~!\t\x00\x7f\x80\xff";

fn random_bytes(rng: &mut Rng, limit: usize) -> Vec<u8> {
    // Mostly short, sometimes right around the limit.
    let len = match rng.below(10) {
        0 => limit + rng.below(3),
        1 => limit.saturating_sub(rng.below(3)),
        _ => rng.below(24),
    };
    (0..len)
        .map(|_| {
            if rng.below(4) == 0 {
                rng.next() as u8
            } else {
                *rng.pick(INTERESTING)
            }
        })
        .collect()
}

/// A plausible request, so sealed tokens and checks overlap often enough to allow.
fn plausible(rng: &mut Rng) -> [Vec<u8>; 4] {
    [
        rng.pick(&["GET", "POST", "get"]).as_bytes().to_vec(),
        rng.pick(&["https", "http", "HTTPS"]).as_bytes().to_vec(),
        rng.pick(&[
            "example.com",
            "Example.com",
            "example.com:443",
            "example.com:80",
            "example.com:0443",
            "example.com:",
            "[::1]:8080",
            "[0::1]",
            "a.b",
            "127.0.0.1",
            "127.1",
            "0x7f.0.0.1",
            "2130706433",
            "user@example.com",
        ])
        .as_bytes()
        .to_vec(),
        rng.pick(&[
            "/",
            "/a",
            "/a/",
            "/caf%c3%a9",
            "/caf%C3%A9",
            "/a?x",
            "/a/../b",
            "/a/%2e%2e/b",
            "/a/%2E./b",
            "/a%2Fb",
            "/a%2fb",
            "/a%5Cb",
            "/a\\b",
            "/a//b",
            "/%41",
            "/a%25",
            "/a#b",
        ])
        .as_bytes()
        .to_vec(),
    ]
}

/// The raw request facts of four generated fields.
fn facts(fields: &[Vec<u8>; 4]) -> RequestFacts<'_> {
    RequestFacts {
        method: &fields[0],
        scheme: &fields[1],
        authority: &fields[2],
        path: &fields[3],
    }
}

fn is_named(denial: Denial) -> bool {
    matches!(
        denial,
        Denial::EmptyToken
            | Denial::TokenTooLong
            | Denial::UnknownVersion
            | Denial::MalformedToken
            | Denial::UnknownCaveatKind
            | Denial::RequestTooLong
            | Denial::MalformedMethod
            | Denial::UnsupportedScheme
            | Denial::MalformedHost
            | Denial::MalformedPort
            | Denial::MalformedPath
            | Denial::NotListed
    )
}

#[test]
fn random_input_never_panics_and_always_gets_a_named_answer() {
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    for round in 0..20_000 {
        let request: [Vec<u8>; 4] = if rng.below(2) == 0 {
            plausible(&mut rng)
        } else {
            [
                random_bytes(&mut rng, gate::MAX_METHOD_BYTES),
                random_bytes(&mut rng, gate::MAX_SCHEME_BYTES),
                random_bytes(&mut rng, gate::MAX_AUTHORITY_BYTES),
                random_bytes(&mut rng, gate::MAX_PATH_BYTES),
            ]
        };
        match rng.below(3) {
            // Random bytes as the token: never allowed.
            0 => {
                let mut token = random_bytes(&mut rng, gate::MAX_TOKEN_BYTES);
                // Give it the right version, and sometimes the right kind, so the body
                // parser gets fuzzed too.
                match rng.below(3) {
                    0 => drop(token.splice(0..0, b"v1;".iter().copied())),
                    1 => drop(token.splice(0..0, b"v1;http ".iter().copied())),
                    _ => {}
                }
                match check(&token, &facts(&request)) {
                    Ok(_) => panic!("round {round}: random token {token:?} allowed a request"),
                    Err(denial) => assert!(is_named(denial), "round {round}: {denial:?}"),
                }
            }
            // A real sealed token: allowed exactly when the request was observed.
            1 => {
                let observed: Vec<Target> = (0..rng.below(4))
                    .filter_map(|_| observe(&facts(&plausible(&mut rng))).ok())
                    .collect();
                let token = seal::seal(&seal::learn(&observed)).unwrap();
                let listed = observe(&facts(&request)).is_ok_and(|t| observed.contains(&t));
                match check(token.as_bytes(), &facts(&request)) {
                    Ok(_) => assert!(listed, "round {round}: allowed an unobserved request"),
                    Err(denial) => {
                        assert!(is_named(denial), "round {round}: {denial:?}");
                        assert!(
                            !listed,
                            "round {round}: denied an observed request: {denial:?}"
                        );
                    }
                }
            }
            // A real sealed token with a few random edits: never panics.
            _ => {
                let observed: Vec<Target> = (0..1 + rng.below(3))
                    .filter_map(|_| observe(&facts(&plausible(&mut rng))).ok())
                    .collect();
                let mut token = seal::seal(&seal::learn(&observed)).unwrap().into_bytes();
                for _ in 0..1 + rng.below(3) {
                    let at = rng.below(token.len() + 1);
                    match rng.below(3) {
                        0 if at < token.len() => token[at] = *rng.pick(INTERESTING),
                        1 if at < token.len() => {
                            token.remove(at);
                        }
                        _ => token.insert(at, *rng.pick(INTERESTING)),
                    }
                }
                if let Err(denial) = check(&token, &facts(&request)) {
                    assert!(is_named(denial), "round {round}: {denial:?}");
                }
            }
        }
    }
}
