//! `gate` is the server side of `purnell-maneuver`: it observes requests and checks them
//! against tokens.
//!
//! - [`observe`] turns what a server reports about a request ([`RequestFacts`]) into the
//!   request's [`Target`]. While learning, observed targets go to `seal::learn`.
//! - [`present`] splits a token into the run it was sealed for ([`RunId`], `v2` only)
//!   and the destinations it lists ([`Caveats`]).
//! - [`check`] decides whether those destinations allow a request. The answer is
//!   [`Allowed`] or a named [`Denial`], never anything in between.
//! - [`compare_secrets`] compares two secrets in constant time.
//!
//! **`check` takes the caveats, never the token.** A `v2` token carries a run id, an
//! opaque label the caller supplies. `check` is handed [`Caveats`], an opaque handle
//! over the caveat region alone: the id is not in those bytes, and the handle's field
//! is private to the `token` crate, so there is no expression inside `check` that
//! reaches the id. A caller that wants the id asks [`Presented::run`] for it.
//!
//! Both `observe` and `check` use the one canonicalizer in the `token` crate, so a
//! request observed while learning and the same request checked later always get the
//! same target. `gate` never reads the token format itself; only the `token` crate's
//! format module does.
//!
//! `no_std`, no `unsafe`, and no panics outside tests: see the README's "Design rules".
#![no_std]

pub use token::{
    present, Caveats, Denial, HttpTarget, McpFacts, McpTarget, Presented, RequestFacts, RunId,
    Target, MAX_AUTHORITY_BYTES, MAX_MCP_METHOD_BYTES, MAX_MCP_NAME_BYTES, MAX_METHOD_BYTES,
    MAX_PATH_BYTES, MAX_RUN_ID_BYTES, MAX_SCHEME_BYTES, MAX_TOKEN_BYTES,
};

use subtle::ConstantTimeEq;
use token::{canonicalize, lists};

/// Proof that [`check`] allowed a request.
///
/// Only `gate` can make one: the field is private, and [`check`] builds it in exactly
/// one place. Everything else is a [`Denial`] (fail closed).
#[derive(Debug, PartialEq, Eq)]
pub struct Allowed {
    _private: (),
}

/// Observes a request: returns its target, for learning, or the reason it can't be
/// learned.
///
/// A request the canonicalizer denies can never be allowed later either, so it is
/// never learned.
pub fn observe(request: &RequestFacts) -> Result<Target, Denial> {
    canonicalize(request)
}

/// Checks whether `caveats` allow `request`.
///
/// - The target comes only from `request`. The caveats only list destinations; there
///   are no flags, modes, wildcards or options that change how this check runs, and a
///   `v2` token's run id is not among the bytes this function is given. Get `caveats` from
///   [`present`].
/// - The token is not signed yet, so it proves nothing about who wrote it: a
///   hand-written token that lists a target in canonical form allows it. See the README's
///   "Known limits".
/// - The target must match a listed caveat exactly, byte for byte, after the
///   canonicalizer. Targets are not secret, so this is plain equality, not the
///   constant-time comparison [`compare_secrets`] uses for secrets.
/// - Every input is checked against its byte limit before it is read.
/// - An empty caveat set allows nothing.
pub fn check(caveats: Caveats<'_>, request: &RequestFacts) -> Result<Allowed, Denial> {
    let target = canonicalize(request)?;
    if lists(caveats, &target)? {
        Ok(Allowed { _private: () })
    } else {
        Err(Denial::NotListed)
    }
}

/// The result of comparing two secrets.
///
/// A named enum rather than a bare `bool`, so a caller can't mix up which value means
/// "matched". This follows the README's "Design rules": bytes in, a small named enum out,
/// nothing else.
///
/// `#[non_exhaustive]`: a later version may add a variant (for example a
/// finer-grained "matched, but one side was empty" case). `#[non_exhaustive]` lets that
/// happen without it being a breaking change for existing callers, who already have to
/// handle an unknown case via a wildcard `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Comparison {
    /// The two inputs held the same bytes.
    Equal,
    /// The two inputs did not hold the same bytes (including when their lengths
    /// differ).
    NotEqual,
}

/// The maximum length, in bytes, that [`compare_secrets`] accepts for either input.
///
/// 4096 bytes (4 KiB) is generous headroom above real secrets: API keys and bearer
/// tokens are almost always well under 256 bytes, and even a large bundled credential
/// (a JWT with several claims, a PEM-encoded key) rarely exceeds a few KiB. The limit
/// exists so every caller — including a wasm host or an Envoy filter with a fixed
/// memory and CPU budget — gets a fixed upper bound on the cost of one call, instead of
/// a caller being able to force an unbounded-length comparison. Raise it if a real
/// caller needs more room; a real secret should never actually hit this limit.
pub const MAX_INPUT_LEN: usize = 4096;

/// Errors [`compare_secrets`] can return.
///
/// `#[non_exhaustive]`: one named case today, and later versions may add more named
/// error cases. `#[non_exhaustive]` lets this crate add a new variant later
/// without that being a breaking change for existing callers, who already have to
/// handle an unknown case via a wildcard `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GateError {
    /// `a`, `b`, or both were longer than [`MAX_INPUT_LEN`].
    InputTooLong,
}

/// Compares two secrets as raw bytes, in constant time.
///
/// This never case-folds or normalizes its inputs — it compares exactly the bytes
/// given, per the README's "Design rules". For any two inputs no longer than
/// [`MAX_INPUT_LEN`], comparison time does not depend on where the first differing
/// byte falls. As with any constant-time comparison, the *lengths* of `a` and `b` are
/// not kept secret: the underlying `subtle` comparison returns early when the lengths
/// differ, and the [`MAX_INPUT_LEN`] check below runs before it, comparing only
/// lengths. Both are fine because lengths are not secret here. If a caller's secret has
/// a variable length that itself must stay secret, hash it to a fixed length before
/// comparing.
///
/// Returns [`GateError::InputTooLong`] if either input is longer than
/// [`MAX_INPUT_LEN`], without allocating and without comparing any bytes.
pub fn compare_secrets(a: &[u8], b: &[u8]) -> Result<Comparison, GateError> {
    if a.len() > MAX_INPUT_LEN || b.len() > MAX_INPUT_LEN {
        return Err(GateError::InputTooLong);
    }
    if bool::from(a.ct_eq(b)) {
        Ok(Comparison::Equal)
    } else {
        Ok(Comparison::NotEqual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(path: &str) -> RequestFacts<'_> {
        RequestFacts {
            method: b"GET",
            scheme: b"https",
            authority: b"example.com",
            path: path.as_bytes(),
            mcp: None,
        }
    }

    /// Present, then check. Every caller does these two steps; this keeps the tests
    /// below reading as "does this token allow this request".
    fn check_token(token: &[u8], request: &RequestFacts) -> Result<Allowed, Denial> {
        check(present(token)?.caveats(), request)
    }

    #[test]
    fn observe_is_the_canonicalizer() {
        let target = observe(&get("/a?x=1")).unwrap();
        assert_eq!(target.as_http().map(HttpTarget::path), Some("/a"));
        assert_eq!(observe(&get("/a/../b")), Err(Denial::MalformedPath));
    }

    #[test]
    fn a_learned_request_is_allowed_and_nothing_else() {
        // `seal` is not a dependency of `gate`, so seal through `token` directly: the
        // same learn and encode that `seal::learn` and `seal::seal` call.
        let observed = [observe(&get("/a")).unwrap()];
        let token = token::encode(&token::learn(&observed)).unwrap();
        assert_eq!(
            check_token(token.as_bytes(), &get("/a?page=2")),
            Ok(Allowed { _private: () })
        );
        assert_eq!(
            check_token(token.as_bytes(), &get("/b")),
            Err(Denial::NotListed)
        );
    }

    #[test]
    fn an_empty_caveat_set_allows_nothing() {
        assert_eq!(check_token(b"v1", &get("/")), Err(Denial::NotListed));
        assert_eq!(check_token(b"v2;r-1", &get("/")), Err(Denial::NotListed));
    }

    #[test]
    fn a_bad_token_is_denied_before_any_request_is_read() {
        // Presenting happens first, so a token this build cannot read is refused
        // without the request ever being canonicalized. The request below is malformed
        // too, and the token's denial is the one that comes back.
        assert_eq!(check_token(b"", &get("/a/../b")), Err(Denial::EmptyToken));
    }

    #[test]
    fn a_bad_request_is_denied_before_the_caveats_are_read() {
        let caveats = present(b"v1").unwrap().caveats();
        assert_eq!(check(caveats, &get("/a/../b")), Err(Denial::MalformedPath));
    }

    /// KNOWN GAP, pinned on purpose: flip this test when tokens are signed. The token is
    /// unsigned and its grammar is public, so a token written by hand, never sealed
    /// from an observation, allows the target it lists. The types keep code from
    /// forging a caveat set; nothing yet keeps a person from forging a token.
    #[test]
    fn known_gap_until_signing_a_hand_written_canonical_token_is_allowed() {
        let delete_admin = RequestFacts {
            method: b"DELETE",
            path: b"/admin",
            ..get("/")
        };
        assert_eq!(
            check_token(b"v1;http DELETE https example.com /admin", &delete_admin),
            Ok(Allowed { _private: () })
        );
        assert_eq!(
            check_token(
                b"v2;r-1;http DELETE https example.com /admin",
                &delete_admin
            ),
            Ok(Allowed { _private: () })
        );
    }

    #[test]
    fn a_bad_token_is_denied_for_a_good_request() {
        assert_eq!(check_token(b"", &get("/")), Err(Denial::EmptyToken));
        assert_eq!(check_token(b"v9", &get("/")), Err(Denial::UnknownVersion));
        assert_eq!(
            check_token(b"v1;NOPE", &get("/")),
            Err(Denial::MalformedToken)
        );
        assert_eq!(
            check_token(b"v1;nope", &get("/")),
            Err(Denial::UnknownCaveatKind)
        );
        assert_eq!(check_token(b"v2", &get("/")), Err(Denial::MalformedRunId));
        assert_eq!(
            check_token(b"v2;r 1;http GET https example.com /", &get("/")),
            Err(Denial::MalformedRunId)
        );
    }

    /// The whole point of the split, stated as a test `gate` itself can make: the run id
    /// is read by the caller, the caveats go to `check`, and every id gives the
    /// same verdict for the same request.
    #[test]
    fn the_run_is_read_beside_the_check_and_never_inside_it() {
        let observed = [observe(&get("/a")).unwrap()];
        let set = token::learn(&observed);
        for id in ["r-1", "r-2", "R-1"] {
            let run = RunId::new(id.as_bytes()).unwrap();
            let token = token::encode_for(run, &set).unwrap();
            let presented = present(token.as_bytes()).unwrap();
            assert_eq!(presented.run().map(|run| run.as_str()), Some(id));
            assert!(check(presented.caveats(), &get("/a")).is_ok(), "{id}");
            assert_eq!(
                check(presented.caveats(), &get("/b")),
                Err(Denial::NotListed),
                "{id}"
            );
        }
    }

    #[test]
    fn equal_bytes_are_equal() {
        assert_eq!(
            compare_secrets(b"same-secret", b"same-secret"),
            Ok(Comparison::Equal)
        );
    }

    #[test]
    fn unequal_bytes_are_not_equal() {
        assert_eq!(
            compare_secrets(b"secret-one", b"secret-two"),
            Ok(Comparison::NotEqual)
        );
    }

    #[test]
    fn different_lengths_are_not_equal() {
        assert_eq!(
            compare_secrets(b"short", b"much-longer-secret"),
            Ok(Comparison::NotEqual)
        );
    }

    #[test]
    fn both_empty_are_equal() {
        assert_eq!(compare_secrets(b"", b""), Ok(Comparison::Equal));
    }

    #[test]
    fn one_empty_is_not_equal() {
        assert_eq!(compare_secrets(b"", b"x"), Ok(Comparison::NotEqual));
    }

    #[test]
    fn a_over_the_limit_is_rejected() {
        let a = [0x61u8; MAX_INPUT_LEN + 1];
        assert_eq!(compare_secrets(&a, b"short"), Err(GateError::InputTooLong));
    }

    #[test]
    fn b_over_the_limit_is_rejected() {
        let b = [0x61u8; MAX_INPUT_LEN + 1];
        assert_eq!(compare_secrets(b"short", &b), Err(GateError::InputTooLong));
    }

    #[test]
    fn both_exactly_at_the_limit_still_compares() {
        let a = [0x61u8; MAX_INPUT_LEN];
        let b = [0x61u8; MAX_INPUT_LEN];
        assert_eq!(compare_secrets(&a, &b), Ok(Comparison::Equal));
    }

    #[test]
    fn both_exactly_at_the_limit_and_unequal_still_compares() {
        let a = [0x61u8; MAX_INPUT_LEN];
        let mut b = [0x61u8; MAX_INPUT_LEN];
        b[MAX_INPUT_LEN - 1] = 0x62;
        assert_eq!(compare_secrets(&a, &b), Ok(Comparison::NotEqual));
    }
}
