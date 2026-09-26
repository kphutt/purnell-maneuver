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
    /// The token did not start with a version this build knows (`v1` or `v2` today).
    UnknownVersion,
    /// The token said `v2` but its run id is missing, empty, longer than
    /// [`crate::MAX_RUN_ID_BYTES`], or carries a byte outside `A-Z`, `a-z`, `0-9`, `-`
    /// and `_`. The same rule refuses a run id offered to
    /// [`RunId::new`](crate::RunId::new).
    MalformedRunId,
    /// The token named a version this build knows but its body is not exactly what
    /// `seal` would have written.
    MalformedToken,
    /// The token holds a caveat of a kind this build does not know. A caveat is never
    /// skipped, so the whole token denies.
    UnknownCaveatKind,
    /// A request field was longer than its limit (method 32 bytes, scheme 16,
    /// authority 259, path with query 4096, MCP method 64, MCP name 1024). Checked before
    /// reading any field.
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
    /// `0x7f.0.0.1`), is an IPv6 literal not in RFC 5952 form (`[0::1]`,
    /// `[2001:DB8::1]`), or is an IPv4-mapped IPv6 literal.
    MalformedHost,
    /// The port is empty, zero, has a leading zero, is not all digits, is above
    /// 65535, or is the scheme's default written out (`:443` on https, `:80` on http).
    MalformedPort,
    /// The path breaks one of the path rules.
    MalformedPath,
    /// The `Mcp-Method` value breaks one of the MCP value rules: it is empty, carries a
    /// byte that is not visible ASCII (so a space or a control byte), carries a `;`, is
    /// base64-wrapped when it did not have to be or unwrapped when it did, or its
    /// wrapping is not canonical base64.
    MalformedMcpMethod,
    /// The `Mcp-Name` value breaks one of the same MCP value rules as
    /// [`Denial::MalformedMcpMethod`].
    MalformedMcpName,
    /// The request is well formed, the token is well formed, and the token does not
    /// list the request's target. This includes every request checked against an empty
    /// caveat set.
    NotListed,
}

impl Denial {
    /// This variant's stable, snake_case name.
    ///
    /// The one place that maps a `Denial` to a name for anything outside this crate
    /// (a test vector file, a CLI's narration): everywhere else derives its name from
    /// here instead of keeping its own table. Written right next to the variants above,
    /// so a new variant is named in the same place it is added, and this match has no
    /// catch-all arm, so forgetting a variant here is a compile error in this crate --
    /// unlike a match on `Denial` outside it, which `#[non_exhaustive]` forces to carry
    /// a catch-all, and which a new variant would then reach silently.
    pub fn name(self) -> &'static str {
        match self {
            Denial::EmptyToken => "empty_token",
            Denial::TokenTooLong => "token_too_long",
            Denial::UnknownVersion => "unknown_version",
            Denial::MalformedRunId => "malformed_run_id",
            Denial::MalformedToken => "malformed_token",
            Denial::UnknownCaveatKind => "unknown_caveat_kind",
            Denial::RequestTooLong => "request_too_long",
            Denial::MalformedMethod => "malformed_method",
            Denial::UnsupportedScheme => "unsupported_scheme",
            Denial::MalformedHost => "malformed_host",
            Denial::MalformedPort => "malformed_port",
            Denial::MalformedPath => "malformed_path",
            Denial::MalformedMcpMethod => "malformed_mcp_method",
            Denial::MalformedMcpName => "malformed_mcp_name",
            Denial::NotListed => "not_listed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Every `Denial` variant, once. Kept complete by `assert_matches_every_variant`
    /// below: adding a variant to the enum without adding it here fails to compile,
    /// so this list cannot silently fall out of sync the way a maintained-by-hand
    /// mapping (with a catch-all arm) could.
    const ALL: &[Denial] = &[
        Denial::EmptyToken,
        Denial::TokenTooLong,
        Denial::UnknownVersion,
        Denial::MalformedRunId,
        Denial::MalformedToken,
        Denial::UnknownCaveatKind,
        Denial::RequestTooLong,
        Denial::MalformedMethod,
        Denial::UnsupportedScheme,
        Denial::MalformedHost,
        Denial::MalformedPort,
        Denial::MalformedPath,
        Denial::MalformedMcpMethod,
        Denial::MalformedMcpName,
        Denial::NotListed,
    ];

    /// Does nothing but match every case of `denial` with no catch-all arm: proof, at
    /// compile time, that `ALL` above still names every variant `Denial` has. If a
    /// variant is added to the enum but not to `ALL`, this function -- not just a
    /// runtime assertion -- fails to compile.
    fn assert_matches_every_variant(denial: Denial) {
        match denial {
            Denial::EmptyToken
            | Denial::TokenTooLong
            | Denial::UnknownVersion
            | Denial::MalformedRunId
            | Denial::MalformedToken
            | Denial::UnknownCaveatKind
            | Denial::RequestTooLong
            | Denial::MalformedMethod
            | Denial::UnsupportedScheme
            | Denial::MalformedHost
            | Denial::MalformedPort
            | Denial::MalformedPath
            | Denial::MalformedMcpMethod
            | Denial::MalformedMcpName
            | Denial::NotListed => {}
        }
    }

    #[test]
    fn every_variant_has_a_unique_name() {
        for denial in ALL {
            assert_matches_every_variant(*denial);
        }

        let mut names: Vec<&str> = ALL.iter().map(|denial| denial.name()).collect();
        let case_count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            case_count,
            "two Denial variants share a name: {names:?}"
        );
    }
}
