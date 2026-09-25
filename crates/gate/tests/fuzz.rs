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

/// A deliberately dumb, independent re-parser of a `v1` token: the oracle for the
/// mutated-token branch.
///
/// It knows nothing about `format.rs` and calls none of it. It splits the token on
/// `;`, drops the version, splits each caveat on a space, and takes the four fields
/// after the kind tag as literal bytes. A request is "spelled out" by the token when
/// its raw method, scheme and authority are byte for byte some caveat's, and its raw
/// path up to the first `?` is that caveat's path.
///
/// The `?` is the only thing this re-parser knows beyond splitting: dropping the query
/// is the canonicalizer's one documented merge. Every other rule
/// denies rather than rewrites, so an allowed request's raw bytes and the caveat it
/// matched must otherwise be identical. Being written here, by hand, from the token
/// grammar in `format.rs` rather than from the encoder matters: a bug shared by
/// the encoder and the decoder cannot hide from it.
fn spelled_out(token: &[u8], request: &[Vec<u8>; 4]) -> bool {
    let path = request[3]
        .split(|&byte| byte == b'?')
        .next()
        .unwrap_or_default();
    token.split(|&byte| byte == b';').skip(1).any(|caveat| {
        let fields: Vec<&[u8]> = caveat.split(|&byte| byte == b' ').collect();
        matches!(
            fields.as_slice(),
            [_kind, method, scheme, authority, listed_path]
                if *method == request[0].as_slice()
                    && *scheme == request[1].as_slice()
                    && *authority == request[2].as_slice()
                    && *listed_path == path
        )
    })
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
    let mut allow_hits = 0u32;
    let mut mutated_allow_hits = 0u32;
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
            //
            // `listed` below is computed by running the request through `observe` --
            // the same canonicalizer `check` uses. So this branch is a round-trip
            // self-consistency check, not an oracle: a canonicalizer that reads one
            // rule wrongly reads it wrongly on both sides and this branch still
            // passes. The independent oracle lives in the mutated-token branch below,
            // and in the hand-labelled rows of `exhaustive.rs`.
            1 => {
                // Keep each draw that produced an observation, so the checked request
                // can reuse one and actually get allowed, not just checked against
                // targets it almost never matches.
                let mut observed_draws: Vec<[Vec<u8>; 4]> = Vec::new();
                let observed: Vec<Target> = (0..rng.below(4))
                    .filter_map(|_| {
                        let fields = plausible(&mut rng);
                        let target = observe(&facts(&fields)).ok();
                        if target.is_some() {
                            observed_draws.push(fields);
                        }
                        target
                    })
                    .collect();
                // About half the time, check the exact bytes of an observed draw, so
                // `Ok(Allowed)` happens often enough to be a real assertion instead of
                // almost never firing.
                let request = if !observed_draws.is_empty() && rng.below(2) == 0 {
                    rng.pick(&observed_draws).clone()
                } else {
                    request
                };
                let token = seal::seal(&seal::learn(&observed)).unwrap();
                let listed = observe(&facts(&request)).is_ok_and(|t| observed.contains(&t));
                match check(token.as_bytes(), &facts(&request)) {
                    Ok(_) => {
                        allow_hits += 1;
                        assert!(listed, "round {round}: allowed an unobserved request");
                    }
                    Err(denial) => {
                        assert!(is_named(denial), "round {round}: {denial:?}");
                        assert!(
                            !listed,
                            "round {round}: denied an observed request: {denial:?}"
                        );
                    }
                }
            }
            // A real sealed token with a few random edits: never panics, and never
            // allows a request the edited token does not literally spell out.
            _ => {
                // Keep each draw that produced an observation, as branch 1 does. The
                // outer random request almost never matches what a mutated token
                // happens to list, so without this the `Ok` arm below -- the only
                // place the independent re-parser runs -- never executes at all.
                let mut observed_draws: Vec<[Vec<u8>; 4]> = Vec::new();
                let observed: Vec<Target> = (0..1 + rng.below(3))
                    .filter_map(|_| {
                        let fields = plausible(&mut rng);
                        let target = observe(&facts(&fields)).ok();
                        if target.is_some() {
                            observed_draws.push(fields);
                        }
                        target
                    })
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
                let request = if !observed_draws.is_empty() && rng.below(2) == 0 {
                    rng.pick(&observed_draws).clone()
                } else {
                    request
                };
                match check(&token, &facts(&request)) {
                    Err(denial) => assert!(is_named(denial), "round {round}: {denial:?}"),
                    Ok(_) => {
                        mutated_allow_hits += 1;
                        assert!(
                            spelled_out(&token, &request),
                            "round {round}: mutated token {token:?} allowed a request \
                             it does not spell out: {request:?}"
                        );
                    }
                }
            }
        }
    }
    println!(
        "real sealed token: {allow_hits} allow hits; \
         mutated token: {mutated_allow_hits} allow hits"
    );
    assert!(
        allow_hits > 100,
        "the real-token branch must reach Ok(Allowed) often, not almost never"
    );
    // The mutated branch's `Ok` arm is where the independent re-parser runs. If a
    // mutated token never allows anything, that arm never runs and the oracle is
    // vacuous.
    assert!(
        mutated_allow_hits > 0,
        "the mutated-token branch never reached Ok(Allowed), so its oracle never ran"
    );
}
