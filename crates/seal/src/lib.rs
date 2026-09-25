//! `seal` is the sealing side of `purnell-maneuver`: it learns a caveat set from observed
//! requests and seals it into a token.
//!
//! - [`learn`] turns targets that `gate::observe` produced into a [`CaveatSet`]. It is
//!   the only public way to get a caveat set. That shows its targets passed the
//!   canonicalizer, not that a real request happened.
//! - [`seal`] writes a caveat set as a token for `gate::check`.
//!
//! This crate does no signing and talks to no outside system; a token is only the listed
//! destinations. The format lives in the `token` crate, in one module, and `seal` never
//! writes token bytes itself.
//!
//! `no_std`, no `unsafe`, and no panics outside tests.
#![no_std]

extern crate alloc;

use alloc::string::String;

pub use token::{learn, Caveat, CaveatSet, HttpTarget, SealError, Target, MAX_TOKEN_BYTES};

/// Seals a caveat set into a token.
///
/// Fails only if the token would be longer than [`MAX_TOKEN_BYTES`], which `gate` would
/// deny anyway.
pub fn seal(caveat_set: &CaveatSet) -> Result<String, SealError> {
    token::encode(caveat_set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use token::{canonicalize, token_lists, RequestFacts};

    fn observe(path: &str) -> Target {
        canonicalize(&RequestFacts {
            method: b"GET",
            scheme: b"https",
            authority: b"example.com",
            path: path.as_bytes(),
            mcp: None,
        })
        .unwrap()
    }

    // These read the sealed token back through `token_lists` rather than comparing
    // bytes, so only the format module knows what a token looks like.

    #[test]
    fn a_sealed_token_lists_what_was_learned() {
        let token = seal(&learn(&[observe("/b"), observe("/a")])).unwrap();
        assert_eq!(token_lists(token.as_bytes(), &observe("/a")), Ok(true));
        assert_eq!(token_lists(token.as_bytes(), &observe("/b")), Ok(true));
        assert_eq!(token_lists(token.as_bytes(), &observe("/c")), Ok(false));
    }

    #[test]
    fn sealing_nothing_gives_a_valid_token_that_lists_nothing() {
        let token = seal(&learn(&[])).unwrap();
        assert_eq!(token_lists(token.as_bytes(), &observe("/")), Ok(false));
    }
}
