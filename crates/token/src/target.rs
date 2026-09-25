//! The plain data types the canonicalizer works between: what a server reports about a
//! request ([`RequestFacts`]) and the request's canonical destination ([`Target`]). No
//! rules live here; they are all in `canonical.rs`.

use alloc::string::String;

use crate::canonical::{self, Scheme};

/// What a server reports about one request, as the raw bytes it received.
///
/// Plain data: four byte strings, no parsing done yet. A server adapter fills this in
/// and hands it to `gate`; it must not decode, normalize or tidy anything first. The
/// canonicalizer decides what to accept, in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestFacts<'a> {
    /// The method exactly as received, for example `GET`. Case matters.
    pub method: &'a [u8],
    /// The scheme the request arrived over: `http` or `https` (HTTP/2 `:scheme`, or
    /// what the listener knows about TLS).
    pub scheme: &'a [u8],
    /// The one authority the server routed on: HTTP/2 `:authority`, or the `Host`
    /// header, for example `example.com` or `example.com:8443`. If the protocol offers
    /// the authority in more than one place (a `Host` header and `:authority`, or an
    /// absolute-form request line), the adapter must deny unless they are byte-for-byte
    /// identical; this struct has room for one value on purpose.
    pub authority: &'a [u8],
    /// The request target exactly as received, before any decoding: the path plus an
    /// optional `?query`, for example `/orders/7?page=2`. Never a framework's decoded
    /// or cleaned-up path.
    pub path: &'a [u8],
}

/// A request's target: the full destination it asks for, in canonical form.
///
/// One variant per kind of destination. Today there is one kind, an HTTP request
/// ([`HttpTarget`]); a later kind (for example a JSON-RPC operation or a queue topic)
/// is a new variant, and the token format already tags each caveat with its kind, so
/// adding one does not change how `v1` tokens are read.
///
/// There is no public way to build one except [`crate::canonicalize`], so every target
/// in the system came out of the one canonicalizer.
///
/// **`#[non_exhaustive]` is on the enum *and* on the variant, and the two do different
/// jobs.** On the enum it stops a downstream `match` from being exhaustive, so adding a
/// variant later is not a breaking change. It does **not** stop anyone from building a
/// variant they can already name: `Target::Http(payload)` compiles fine in a downstream
/// crate against an enum-level attribute alone. Only the attribute on the variant closes
/// that, and construction from outside then fails with `error[E0603]: tuple variant
/// `Http` is private` (see the note on the `tests` module).
///
/// Today that gap is small, because `HttpTarget` has private fields, no public
/// constructor, no `Default`, no `From` and no deserializer, so an outside crate can only
/// clone a target the canonicalizer already produced and re-wrap it. It does not stay
/// small: the growth path written above is "a later kind is a new variant", and the first
/// variant whose payload a caller can build would turn this into a forged target with no
/// compile error anywhere. The attribute is here so that variant cannot be added by
/// accident.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Target {
    /// An HTTP request: method, scheme, host, port and path.
    #[non_exhaustive]
    Http(HttpTarget),
}

impl Target {
    /// The HTTP destination, if this is an HTTP target (every target, today).
    pub fn as_http(&self) -> Option<&HttpTarget> {
        match self {
            Target::Http(http) => Some(http),
        }
    }
}

/// An HTTP request's destination, in canonical form.
///
/// Method, scheme, host, port and path. The query and fragment are never part of it.
/// Two requests have the same target exactly when these five values are the same bytes.
/// Private fields and no public constructor: only the canonicalizer makes one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HttpTarget {
    method: String,
    scheme: Scheme,
    host: String,
    port: u16,
    path: String,
}

impl HttpTarget {
    /// The method, exactly as sent, for example `GET`.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// `http` or `https`.
    pub fn scheme(&self) -> &str {
        self.scheme.as_str()
    }

    /// The host in lowercase, for example `example.com` or `[::1]`.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port the authority names, filled in from the scheme when it names none. It
    /// comes from the authority bytes and nothing else; a request carries no other port
    /// today.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The path, without query or fragment, for example `/orders/7`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The authority written back the one way the canonicalizer accepts it: the host,
    /// plus `:port` unless the port is the scheme's default. Feeding a target's method,
    /// scheme, authority and path back to the canonicalizer gives the same target.
    pub fn authority(&self) -> String {
        canonical::write_authority(self.scheme, &self.host, self.port)
    }

    /// Builds a target. Crate-private, and called only by the canonicalizer, so every
    /// target in the system came out of it.
    pub(crate) fn new(
        method: String,
        scheme: Scheme,
        host: String,
        port: u16,
        path: String,
    ) -> HttpTarget {
        HttpTarget {
            method,
            scheme,
            host,
            port,
            path,
        }
    }
}

/// Test helpers shared by this crate's unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use super::RequestFacts;

    /// Request facts from text, so a test can read as one line what a server would
    /// report as bytes.
    pub(crate) fn facts<'a>(
        method: &'a str,
        scheme: &'a str,
        authority: &'a str,
        path: &'a str,
    ) -> RequestFacts<'a> {
        RequestFacts {
            method: method.as_bytes(),
            scheme: scheme.as_bytes(),
            authority: authority.as_bytes(),
            path: path.as_bytes(),
        }
    }
}

/// Unit tests for the target types.
///
/// **The one property that matters most here cannot be tested from inside this crate,
/// and is recorded rather than asserted.** `Target::Http(..)` must not be buildable by
/// a downstream crate, but inside the defining crate `#[non_exhaustive]` has no effect
/// at all, so no test in this file can see the difference. Testing it needs a
/// *compile-fail* test — code that must not compile — and every crate that does that
/// (`trybuild` and friends) pulls in `serde_derive`, a proc-macro, which the
/// no-build-scripts, no-proc-macros rule forbids for these crates and their tests.
/// One property is not worth widening the dependency policy, so here is the check,
/// written out to be run by hand when `Target` changes:
///
/// ```text
/// # anywhere outside this workspace:
/// cargo new --lib forge && cd forge
/// # Cargo.toml: add an empty [workspace] table, then
/// #   token = { path = "<repo>/crates/token" }
/// # src/lib.rs:
/// #   use token::{canonicalize, RequestFacts, Target};
/// #   pub fn forge() -> Target {
/// #       let real = canonicalize(&RequestFacts {
/// #           method: b"GET", scheme: b"https", authority: b"example.com", path: b"/a",
/// #       }).unwrap();
/// #       Target::Http(real.as_http().unwrap().clone())
/// #   }
/// cargo build
/// ```
///
/// It must fail with:
///
/// ```text
/// error[E0603]: tuple variant `Http` is private
///    |
///    | #[non_exhaustive]
///    | ----------------- cannot be constructed because it is `#[non_exhaustive]`
/// ```
///
/// With `#[non_exhaustive]` on the enum alone this would build, so the attribute is on the
/// variant too.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonicalize;

    #[test]
    fn the_canonicalizer_is_the_way_in_and_as_http_is_the_way_out() {
        let target = canonicalize(&test_support::facts(
            "GET",
            "https",
            "example.com",
            "/a?x=1",
        ))
        .unwrap();
        let http = target.as_http().unwrap();
        assert_eq!(http.method(), "GET");
        assert_eq!(http.authority(), "example.com");
        assert_eq!(http.path(), "/a");
        // Re-wrapping is what a downstream crate cannot do; inside this crate it is
        // ordinary code, which is exactly why the module comment above exists.
        assert_eq!(Target::Http(http.clone()), target);
    }
}
