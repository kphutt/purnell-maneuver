//! Caveats and the caveat set: the destinations a token allows.
//!
//! No code outside this crate can build a caveat or a caveat set. The only public way
//! to get a caveat set is [`learn`], and the only public way to get the targets it
//! learns from is the canonicalizer (`gate::observe`). Neither type has a public
//! constructor, and nothing public turns text into a caveat, so every caveat set holds
//! targets the canonicalizer accepted. That does not prove a real request happened: a
//! caller can build `RequestFacts` for any request.
//!
//! That is a property of the types, not of tokens. Until tokens are signed, anyone who
//! can write the token header can write a canonical caveat by hand, and `gate`
//! will honor it.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::borrow::Borrow;

use crate::Target;

/// One destination a token allows: a full target, matched by exact bytes. No prefixes,
/// no wildcards, no options.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Caveat {
    target: Target,
}

impl Caveat {
    /// The destination this caveat allows.
    pub fn target(&self) -> &Target {
        &self.target
    }
}

/// Lets the set be searched by target. A caveat is exactly its target (its only field),
/// so the two compare and order the same way, which `Borrow` requires.
impl Borrow<Target> for Caveat {
    fn borrow(&self) -> &Target {
        &self.target
    }
}

/// The destinations a token allows, as one set.
///
/// It is one set, looked up once, not a list of rules that are each
/// evaluated and then combined. An empty set allows nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaveatSet {
    caveats: BTreeSet<Caveat>,
}

impl CaveatSet {
    /// The caveats, in the order the token stores them. For reviewing a learned set
    /// before it is enforced.
    pub fn caveats(&self) -> impl Iterator<Item = &Caveat> {
        self.caveats.iter()
    }

    /// Whether the set lists this exact target: one lookup in the set. Targets are not
    /// secret, so this is a plain equality lookup, not a constant-time comparison (that
    /// is for secrets; see `gate::compare_secrets`).
    pub(crate) fn lists(&self, target: &Target) -> bool {
        self.caveats.contains(target)
    }

    /// Builds a set from targets that came out of the canonicalizer. Crate-private:
    /// callers use [`learn`]; the token decoder uses it for targets it has checked.
    pub(crate) fn from_targets(targets: Vec<Target>) -> CaveatSet {
        CaveatSet {
            caveats: targets
                .into_iter()
                .map(|target| Caveat { target })
                .collect(),
        }
    }
}

/// Learns a caveat set from observed targets: every distinct target becomes one caveat.
///
/// Learning trusts whatever it is given. Observe in a window you trust, and review the
/// learned set (with [`CaveatSet::caveats`]) before enforcing it.
pub fn learn(observed: &[Target]) -> CaveatSet {
    CaveatSet::from_targets(observed.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonicalize;
    use crate::target::test_support::facts;

    fn observe(authority: &str, path: &str) -> Target {
        canonicalize(&facts("GET", "https", authority, path)).unwrap()
    }

    #[test]
    fn learning_nothing_lists_nothing() {
        let set = learn(&[]);
        assert_eq!(set.caveats().count(), 0);
        assert!(!set.lists(&observe("example.com", "/")));
    }

    #[test]
    fn learning_lists_exactly_what_was_observed() {
        let set = learn(&[observe("example.com", "/a"), observe("example.com", "/b")]);
        assert!(set.lists(&observe("example.com", "/a")));
        assert!(set.lists(&observe("example.com", "/b?x=1")));
        assert!(!set.lists(&observe("example.com", "/c")));
        assert!(!set.lists(&observe("example.com", "/a/")));
        assert!(!set.lists(&observe("example.com:8443", "/a")));
        assert!(!set.lists(&observe("example.org", "/a")));
    }

    #[test]
    fn the_same_target_observed_twice_is_one_caveat() {
        let set = learn(&[
            observe("example.com", "/a"),
            observe("example.com", "/a?page=2"),
            observe("example.com", "/a"),
        ]);
        assert_eq!(set.caveats().count(), 1);
    }

    #[test]
    fn caveats_come_out_sorted() {
        let set = learn(&[observe("example.com", "/b"), observe("example.com", "/a")]);
        let paths: Vec<&str> = set
            .caveats()
            .filter_map(|c| c.target().as_http())
            .map(|http| http.path())
            .collect();
        assert_eq!(paths, ["/a", "/b"]);
    }
}
