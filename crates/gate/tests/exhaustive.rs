//! Exhaustive check over a small space of tricky requests.
//!
//! For every subset of the requests below: observe the subset, learn, seal, then check
//! every request against that token. The answer must match a separate, simple oracle:
//! each request is labelled by hand with the destination it names (or `None` if it must
//! be denied), and a request is allowed exactly when its label is `Some` and some
//! observed request has the same label.
//!
//! The labels are written by a person reading the rules, not computed by the
//! canonicalizer, so a canonicalizer bug that merges two destinations (a bypass) or
//! splits one (a false denial) shows up as a mismatch.

// A test binary: panicking is how a test fails. clippy.toml already exempts `#[test]`
// functions from the panic lints; this extends that to the helpers they call.
#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use gate::{check, observe, RequestFacts};

/// (method, scheme, authority, path, the destination a person says this names).
type Labelled = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
);

const REQUESTS: &[Labelled] = &[
    (
        "GET",
        "https",
        "example.com",
        "/a",
        Some("GET https://example.com:443/a"),
    ),
    // A query: the same destination.
    (
        "GET",
        "https",
        "example.com",
        "/a?x=1",
        Some("GET https://example.com:443/a"),
    ),
    // Scheme and host case are denied, not folded into the lowercase spelling.
    ("GET", "HTTPS", "example.com", "/a", None),
    ("GET", "https", "Example.COM", "/a", None),
    ("GET", "https", "EXAMPLE.COM", "/a", None),
    // The default port written out is denied, not merged with no port.
    ("GET", "https", "example.com:443", "/a", None),
    // Method case is significant.
    (
        "get",
        "https",
        "example.com",
        "/a",
        Some("get https://example.com:443/a"),
    ),
    // Trailing slash is significant.
    (
        "GET",
        "https",
        "example.com",
        "/a/",
        Some("GET https://example.com:443/a/"),
    ),
    // A dot segment is denied, not resolved to /a.
    ("GET", "https", "example.com", "/b/../a", None),
    // An encoded unreserved byte is denied, not decoded to /a.
    ("GET", "https", "example.com", "/%61", None),
    // Lowercase hex is denied, not folded into the uppercase spelling below.
    ("GET", "https", "example.com", "/caf%c3%a9", None),
    (
        "GET",
        "https",
        "example.com",
        "/caf%C3%A9",
        Some("GET https://example.com:443/caf\u{e9}"),
    ),
    // NFD spelling of the same word: a different destination.
    (
        "GET",
        "https",
        "example.com",
        "/cafe%CC%81",
        Some("GET https://example.com:443/cafe\u{301}"),
    ),
    // http on 443 is not https.
    (
        "GET",
        "http",
        "example.com:443",
        "/a",
        Some("GET http://example.com:443/a"),
    ),
    (
        "GET",
        "http",
        "example.com",
        "/a",
        Some("GET http://example.com:80/a"),
    ),
    // http with its default port written out: denied.
    ("GET", "http", "example.com:80", "/a", None),
    // A port of its own.
    (
        "GET",
        "https",
        "example.com:8443",
        "/a",
        Some("GET https://example.com:8443/a"),
    ),
    // Empty segment and trailing-dot host: denied.
    ("GET", "https", "example.com", "//a", None),
    ("GET", "https", "example.com.", "/a", None),
    // One IPv4 spelling, one IPv6 spelling; the others are denied.
    (
        "GET",
        "https",
        "127.0.0.1",
        "/a",
        Some("GET https://127.0.0.1:443/a"),
    ),
    ("GET", "https", "127.1", "/a", None),
    (
        "GET",
        "https",
        "[::1]",
        "/a",
        Some("GET https://[::1]:443/a"),
    ),
    ("GET", "https", "[0::1]", "/a", None),
    ("GET", "https", "[::A]", "/a", None),
    // One row per field-class boundary. Every row above is about a *shape* — a dot
    // segment, a host spelling, a port — so none of them says anything about which
    // bytes a field may hold, and a rule that quietly gained a byte would leave this
    // oracle green. These four are denied, so they never enter the subset enumeration
    // and the 2^n count is unchanged; they are still checked against every token.
    // A raw CR in the path: the header-injection primitive, since a canonical field
    // is carried in an HTTP header value.
    ("GET", "https", "example.com", "/a\rb", None),
    // A raw CR in the method, which is written into the token ahead of everything else.
    ("GE\rT", "https", "example.com", "/a", None),
    // A backslash in the host: WHATWG rewrites it to `/`, so a client and the gate
    // would disagree about where the authority ends.
    ("GET", "https", "exa\\mple.com", "/a", None),
    // A query byte in the host: the authority is not split on `?` the way a path is.
    ("GET", "https", "example.com?x=1", "/a", None),
];

fn facts(index: usize) -> RequestFacts<'static> {
    let (method, scheme, authority, path, _) = REQUESTS[index];
    RequestFacts {
        method: method.as_bytes(),
        scheme: scheme.as_bytes(),
        authority: authority.as_bytes(),
        path: path.as_bytes(),
        mcp: None,
    }
}

fn label(index: usize) -> Option<&'static str> {
    REQUESTS[index].4
}

#[test]
fn every_observed_subset_allows_exactly_what_the_oracle_says() {
    let n = REQUESTS.len();

    // The oracle's `None` must be exactly the canonicalizer's denials.
    for i in 0..n {
        assert_eq!(
            observe(&facts(i)).is_ok(),
            label(i).is_some(),
            "request {i}"
        );
    }

    // Observing a denied request learns nothing (it has no target), so only subsets of
    // the accepted requests can give different tokens. Enumerating those keeps the run
    // small; every request, denied ones included, is still checked against each token.
    let accepted: Vec<usize> = (0..n).filter(|&i| label(i).is_some()).collect();
    for subset in 0u32..(1 << accepted.len()) {
        let observed_indexes: Vec<usize> = accepted
            .iter()
            .enumerate()
            .filter(|(bit, _)| subset & (1 << bit) != 0)
            .map(|(_, &i)| i)
            .collect();
        let observed: Vec<gate::Target> = observed_indexes
            .iter()
            .map(|&i| observe(&facts(i)).unwrap())
            .collect();
        let token = seal::seal(&seal::learn(&observed)).unwrap();

        for i in 0..n {
            let oracle =
                label(i).is_some() && observed_indexes.iter().any(|&j| label(j) == label(i));
            let actual = check(token.as_bytes(), &facts(i)).is_ok();
            assert_eq!(actual, oracle, "subset {subset:#b}, request {i}");
        }
    }
}
