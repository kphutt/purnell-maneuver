//! `gate` is the verifying side of `purnell-maneuver`: it checks seals.
//!
//! This crate does no signing and no verification of tokens yet (see `seal`). It has one
//! operation so far: comparing two secrets as raw bytes in constant time.
//!
//! `no_std`, no `unsafe`, and no panics outside tests.
#![no_std]

use subtle::ConstantTimeEq;

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
