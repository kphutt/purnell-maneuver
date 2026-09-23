//! Every way a check (or an observation) can say no.

/// Why a request was denied.
///
/// Fail closed: the only way to be allowed is `gate::check` returning
/// `Allowed`. Every other outcome is one of these named cases, never a text message and
/// never a silent "probably fine".
///
/// `#[non_exhaustive]` so a later version can add a case without breaking callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Denial {
    /// The token was zero bytes long.
    EmptyToken,
    /// The token was longer than [`crate::MAX_TOKEN_BYTES`]. Checked before reading it.
    TokenTooLong,
    /// The token did not start with a version this build knows (only `v1` today).
    UnknownVersion,
    /// The token said `v1` but its body is not exactly what `seal` would have written.
    MalformedToken,
    /// The token holds a caveat of a kind this build does not know. A caveat is never
    /// skipped, so the whole token denies.
    UnknownCaveatKind,
    /// A request field was longer than its limit (method 32 bytes, scheme 16,
    /// authority 259, path with query 4096). Checked before reading any field.
    RequestTooLong,
    /// The method is empty or is not a valid HTTP token (RFC 9110 §9.1, §5.6.2).
    MalformedMethod,
    /// The scheme is not exactly `http` or `https`. Uppercase (`HTTPS`) is denied, not
    /// folded.
    UnsupportedScheme,
    /// The host has user info, is empty, is longer than 253 bytes, has an empty label or
    /// a trailing dot, uses a byte a host may not have (anything but lowercase ASCII
    /// letters, digits, `-`, `_`, `.`, or a bracketed IPv6 literal, so uppercase is
    /// denied, not folded), ends in a number without being a dotted quad (`127.1`,
    /// `0x7f.0.0.1`), or is an IPv6 literal not in RFC 5952 form (`[0::1]`,
    /// `[2001:DB8::1]`).
    MalformedHost,
    /// The port is empty, zero, has a leading zero, is not all digits, is above
    /// 65535, or is the scheme's default written out (`:443` on https, `:80` on http).
    MalformedPort,
    /// The path breaks one of the path rules.
    MalformedPath,
    /// The request is well formed, the token is well formed, and the token does not
    /// list the request's target. This includes every request checked against an empty
    /// caveat set.
    NotListed,
}
