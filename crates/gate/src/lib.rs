//! `gate` is the server side of `purnell-maneuver`: it observes requests and checks them
//! against tokens.
//!
//! - [`observe`] turns what a server reports about a request ([`RequestFacts`]) into the
//!   request's [`Target`]. While learning, observed targets go to `seal::learn`.
//! - [`check`] decides whether a token allows a request. The answer is [`Allowed`] or a
//!   named [`Denial`], never anything in between.
//! - [`compare_secrets`] compares two secrets in constant time.
//!
//! Both `observe` and `check` use the one canonicalizer in the `token` crate, so a
//! request observed while learning and the same request checked later always get the
//! same target. `gate` never reads the token format itself; only the `token` crate's
//! format module does.
//!
//! `no_std`, no `unsafe`, and no panics outside tests.
#![no_std]

pub use token::{
    Denial, HttpTarget, RequestFacts, Target, MAX_AUTHORITY_BYTES, MAX_METHOD_BYTES,
    MAX_PATH_BYTES, MAX_SCHEME_BYTES, MAX_TOKEN_BYTES,
};

use subtle::ConstantTimeEq;
use token::{canonicalize, token_lists};

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

/// Checks whether `token` allows `request`.
///
/// - The target comes only from `request`. The token only lists destinations; it has
///   no flags, modes, wildcards or options that change how this check runs.
/// - The token is not signed yet, so it proves nothing about who wrote it: a
///   hand-written token that lists a target in canonical form allows it.
/// - The target must match a listed caveat exactly, byte for byte, after the
///   canonicalizer. Targets are not secret, so this is plain equality, not the
///   constant-time comparison [`compare_secrets`] uses for secrets.
/// - Every input is checked against its byte limit before it is read.
/// - An empty caveat set allows nothing.
pub fn check(token: &[u8], request: &RequestFacts) -> Result<Allowed, Denial> {
    let target = canonicalize(request)?;
    if token_lists(token, &target)? {
        Ok(Allowed { _private: () })
    } else {
        Err(Denial::NotListed)
    }
}

/// The result of comparing two secrets.
///
/// A named enum rather than a bare `bool`, so a caller can't mix up which value means
/// "matched". Bytes in, a small named enum out, nothing else.
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
/// given. For any two inputs no longer than
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
        }
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
            check(token.as_bytes(), &get("/a?page=2")),
            Ok(Allowed { _private: () })
        );
        assert_eq!(check(token.as_bytes(), &get("/b")), Err(Denial::NotListed));
    }

    #[test]
    fn an_empty_caveat_set_allows_nothing() {
        assert_eq!(check(b"v1", &get("/")), Err(Denial::NotListed));
    }

    #[test]
    fn a_bad_request_is_denied_before_the_token_is_read() {
        assert_eq!(check(b"", &get("/a/../b")), Err(Denial::MalformedPath));
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
            check(b"v1;http DELETE https example.com /admin", &delete_admin),
            Ok(Allowed { _private: () })
        );
    }

    #[test]
    fn a_bad_token_is_denied_for_a_good_request() {
        assert_eq!(check(b"", &get("/")), Err(Denial::EmptyToken));
        assert_eq!(check(b"v9", &get("/")), Err(Denial::UnknownVersion));
        assert_eq!(check(b"v1;NOPE", &get("/")), Err(Denial::MalformedToken));
        assert_eq!(check(b"v1;nope", &get("/")), Err(Denial::UnknownCaveatKind));
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
