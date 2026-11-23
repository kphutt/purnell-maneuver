//! `seal` is the sealing side of `purnell-maneuver`: it learns a caveat set from observed
//! requests and seals it into a token.
//!
//! - [`learn`] turns targets that `gate::observe` produced into a [`CaveatSet`]. It is
//!   the only public way to get a caveat set. That shows its targets passed the
//!   canonicalizer, not that a real request happened.
//! - [`seal`] writes a caveat set as a `v1` token for `gate::check`.
//! - [`seal_for`] writes the same set as a `v2` token, naming the run it was sealed for.
//!   The id is an opaque label the caller supplies; see the `token` crate's format module.
//!
//! This crate does no signing and talks to no outside system; a token is only the listed
//! destinations. The format lives in the `token` crate, in one module, and `seal` never
//! writes token bytes itself.
//!
//! `no_std`, no `unsafe`, and no panics outside tests: see the README's "Design rules".
#![no_std]

extern crate alloc;

use alloc::string::String;

pub use token::{
    learn, Caveat, CaveatSet, HttpTarget, RunId, SealError, Target, MAX_RUN_ID_BYTES,
    MAX_TOKEN_BYTES,
};

/// Seals a caveat set into a `v1` token, which names no run.
///
/// Fails only if the token would be longer than [`MAX_TOKEN_BYTES`], which `gate` would
/// deny anyway.
pub fn seal(caveat_set: &CaveatSet) -> Result<String, SealError> {
    token::encode(caveat_set)
}

/// Seals a caveat set into a `v2` token, naming the run it was sealed for.
///
/// The same caveats, written by the same code, with one opaque id in front. The caller
/// chooses the id. This function writes no record: `seal` does no I/O.
///
/// Fails only for the same reason [`seal`] does.
pub fn seal_for(run: RunId<'_>, caveat_set: &CaveatSet) -> Result<String, SealError> {
    token::encode_for(run, caveat_set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use token::{canonicalize, lists, present, Denial, RequestFacts};

    /// Present, then ask: the two steps a gate takes. Kept here so the tests below read
    /// tokens back through the library rather than by comparing token text.
    fn token_lists(token: &[u8], target: &Target) -> Result<bool, Denial> {
        lists(present(token)?.caveats(), target)
    }

    fn run(text: &str) -> RunId<'_> {
        RunId::new(text.as_bytes()).unwrap()
    }

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
        let for_a_run = seal_for(run("r-1"), &learn(&[])).unwrap();
        assert_eq!(token_lists(for_a_run.as_bytes(), &observe("/")), Ok(false));
    }

    #[test]
    fn sealing_for_a_run_lists_exactly_what_sealing_without_one_does() {
        let set = learn(&[observe("/b"), observe("/a")]);
        let plain = seal(&set).unwrap();
        let named = seal_for(run("run-1"), &set).unwrap();
        assert_ne!(plain, named);
        for path in ["/a", "/b", "/c"] {
            assert_eq!(
                token_lists(plain.as_bytes(), &observe(path)),
                token_lists(named.as_bytes(), &observe(path)),
                "{path}"
            );
        }
    }

    #[test]
    fn a_sealed_token_carries_the_run_it_was_sealed_for() {
        let token = seal_for(run("run-1"), &learn(&[observe("/a")])).unwrap();
        let presented = present(token.as_bytes()).unwrap();
        assert_eq!(presented.run().map(|run| run.as_str()), Some("run-1"));
        assert_eq!(
            present(seal(&learn(&[observe("/a")])).unwrap().as_bytes())
                .unwrap()
                .run(),
            None
        );
    }
}
