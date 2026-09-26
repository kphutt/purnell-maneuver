//! Kani proof harnesses for the canonicalizer.
//!
//! A test samples inputs; a model checker reasons about all of them at once. These
//! harnesses restate the canonicalizer's invariants so Kani can prove them over
//! **every** input inside a stated bound, rather than over the fixed-seed stream
//! `crates/gate/tests/invariants.rs` walks.
//!
//! They come in two groups, because the two cost very different amounts to check.
//!
//! **Group 1, the three invariants end to end.** The same three the invariants test
//! pins: totality, idempotence and no merge, each over whole `RequestFacts`.
//!
//! **None of the three finishes today.** The reason is in one function. Every
//! accepted request runs through
//! [`ascii_to_string`] three times, and `char::from(byte)` turns a byte at or above
//! `0x80` into a character UTF-8 encodes in **two** bytes — so with symbolic input the
//! `String`'s length, capacity and growth are all symbolic and the formula explodes.
//! The same function reached through [`canonical_method`] is cheap, because every byte
//! there is already known to be an ASCII token byte.
//!
//! They are kept here, complete and correct, because they are the statements worth
//! proving and because the cost is in Kani's model of `String`, not in the invariants.
//! Stubbing `ascii_to_string` is the likely smallest change to make them finish. Until
//! then `crates/gate/tests/invariants.rs` is what pins these three, 200,000 samples per
//! run.
//!
//! **Group 2, the rule layer.** One harness per rule, over the **whole** input domain
//! that rule can ever see — every byte value, every spelling of a scheme, every port.
//! Most are cheap, and several are *complete*: not a bound at all, but the entire
//! domain. They are what a regression gate should run. Most use `kani::cover!`, so they
//! cannot pass vacuously.
//!
//! Two do not finish, and both say why in their own comments: the IPv6 round
//! trip, and `a_written_mcp_value_reads_back_unchanged`, which hits the same `String`
//! cost as group 1.
//!
//! **Every harness needs `#[kani::unwind(N)]`, and the value matters more than it
//! looks.** A slice of symbolic length makes every loop over it unbounded as far as
//! CBMC is concerned, because unwinding happens before `kani::assume(len <= N)` is
//! applied. Without an explicit bound the solver does not terminate in any useful time.
//! The bound is safe to get wrong in only one direction: Kani checks an *unwinding
//! assertion*, so a value that is too small **fails loudly** rather than silently
//! verifying a truncated program. Never turn that check off. A value that is too large
//! is not free either — it grows the formula.
//!
//! Run with `cargo kani` on Linux. Nothing here is compiled by an ordinary build: the
//! module is behind `#[cfg(kani)]`, a cfg only Kani's own compiler driver sets.

// A proof harness fails by panicking, exactly like a test, so the crate's no-panic
// lints do not apply to it. Kani checks arithmetic overflow itself, on every operation
// in the code under proof, which is stronger than the lint.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic
)]

use super::*;
use alloc::string::String;

// ---------------------------------------------------------------------------
// Symbolic inputs
// ---------------------------------------------------------------------------

/// A symbolic byte string of at most `N` bytes: `N` arbitrary bytes, and an arbitrary
/// length that picks a prefix of them. Every byte string from the empty one up to `N`
/// bytes long is a possible value, and a proof covers all of them at once.
///
/// The length is what makes the harness need an `#[kani::unwind]` bound: a loop over a
/// slice this long has no bound CBMC can work out for itself.
fn any_bytes<const N: usize>(buffer: &[u8; N]) -> &[u8] {
    let len: usize = kani::any();
    kani::assume(len <= N);
    &buffer[..len]
}

// ---------------------------------------------------------------------------
// A second, simple reading of a raw request
// ---------------------------------------------------------------------------
//
// The no-merge proof must not ask the canonicalizer what two requests said; that would
// compare the canonicalizer with itself. These read the raw bytes the plain way,
// mirroring `raw_key` in `crates/gate/tests/invariants.rs` — except that they are
// total, where the test's version may unwrap, since a proof sees inputs a generator
// never produces.

/// The host bytes and the port the raw authority names, the scheme's default when it
/// names none. `None` where this simple reading cannot split the authority at all.
fn raw_host_and_port<'a>(authority: &'a [u8], scheme: &[u8]) -> Option<(&'a [u8], u16)> {
    // Past an IPv6 literal's `]`, so the colons inside it are not read as a port.
    let from = match authority.iter().position(|&byte| byte == b']') {
        Some(close) => close.checked_add(1)?,
        None => 0,
    };
    let colon = authority
        .get(from..)?
        .iter()
        .position(|&byte| byte == b':')
        .and_then(|at| at.checked_add(from));
    match colon {
        Some(at) => {
            let host = authority.get(..at)?;
            let digits = authority.get(at.checked_add(1)?..)?;
            if digits.is_empty() || digits.len() > 5 || !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let mut value: u32 = 0;
            for &digit in digits {
                value = value
                    .checked_mul(10)?
                    .checked_add(u32::from(digit.checked_sub(b'0')?))?;
            }
            Some((host, u16::try_from(value).ok()?))
        }
        None => {
            let default = if scheme == b"https" { 443 } else { 80 };
            Some((authority, default))
        }
    }
}

/// The path bytes before any `?`: the part of the field that names a destination.
fn raw_path(path_and_query: &[u8]) -> &[u8] {
    path_and_query
        .split(|&byte| byte == b'?')
        .next()
        .unwrap_or_default()
}

/// Every denial the canonicalizer is allowed to give. A denial outside this set would
/// mean a request denial leaked a token-format case, or a new case appeared unnamed.
fn is_named_request_denial(denial: Denial) -> bool {
    matches!(
        denial,
        Denial::RequestTooLong
            | Denial::MalformedMethod
            | Denial::UnsupportedScheme
            | Denial::MalformedHost
            | Denial::MalformedPort
            | Denial::MalformedPath
    )
}

// ===========================================================================
// Group 1 — the three invariants, end to end
// ===========================================================================
//
// Bytes per field. Small on purpose: these are symbolic bytes, so the solver reasons
// about 256^(sum) inputs at once, and a single `canonicalize` call allocates three
// Strings on the way. `SCHEME_BYTES` is 5 so that both `http` and `https` are inside
// the bound; a smaller one would make every accepted request `http` and quietly halve
// what the proof says.

/// Method bytes for the end-to-end proofs. `GET` is inside this bound.
const METHOD_BYTES: usize = 3;
/// Scheme bytes. 5 so both `http` and `https` are reachable.
const SCHEME_BYTES: usize = 5;
/// Authority bytes. 4 fits a two-label name (`a.bc`), a one-label name with a port
/// (`a:81`), and the shortest IPv6 literal (`[::]`).
const AUTHORITY_BYTES: usize = 4;
/// Path bytes, including any query. 3 fits `/a`, `/a/`, `/a?`, `%41` and `/..`.
const PATH_BYTES: usize = 3;

// The no-merge proof canonicalizes two symbolic requests, so its cost is roughly the
// square of a one-request proof. Its bounds are cut to match.

/// Method bytes per request in the no-merge proof.
const MERGE_METHOD_BYTES: usize = 1;
/// Scheme bytes per request in the no-merge proof. Still 5, so a merge between an
/// `http` request and an `https` one stays inside the bound — exactly the merge worth
/// looking for, since the two schemes have different default ports.
const MERGE_SCHEME_BYTES: usize = 5;
/// Authority bytes per request in the no-merge proof.
const MERGE_AUTHORITY_BYTES: usize = 3;
/// Path bytes per request in the no-merge proof. 2 fits `/a` and `/?`, so the query
/// exception (two requests sharing a target because a query was dropped) is reachable.
const MERGE_PATH_BYTES: usize = 2;

/// A symbolic request inside the end-to-end bound.
macro_rules! symbolic_request {
    ($method:ident, $scheme:ident, $authority:ident, $path:ident,
     $m:expr, $s:expr, $a:expr, $p:expr) => {
        let $method: [u8; $m] = kani::any();
        let $scheme: [u8; $s] = kani::any();
        let $authority: [u8; $a] = kani::any();
        let $path: [u8; $p] = kani::any();
    };
}

/// **Totality.** For every request whose four fields are at most `METHOD_BYTES`,
/// `SCHEME_BYTES`, `AUTHORITY_BYTES` and `PATH_BYTES` long — every byte value, every
/// length, including empty — `canonicalize` returns a target or one of the six named
/// request denials. It never panics, never indexes out of bounds and never overflows:
/// Kani checks those on every operation it reaches, so they need no assertion here.
///
/// **What it does not cover.** Only short inputs. The `RequestTooLong` branch is never
/// taken inside this bound, and neither is any rule that needs a longer field: the
/// 253-byte host limit, the five-digit port, a long percent-encoded path. Those stay
/// the sampled tests' job.
#[kani::proof]
#[kani::unwind(16)]
fn totality_any_bytes_give_a_bounded_target_or_a_named_denial() {
    symbolic_request!(
        method,
        scheme,
        authority,
        path,
        METHOD_BYTES,
        SCHEME_BYTES,
        AUTHORITY_BYTES,
        PATH_BYTES
    );
    let request = RequestFacts {
        method: any_bytes(&method),
        scheme: any_bytes(&scheme),
        authority: any_bytes(&authority),
        path: any_bytes(&path),
        mcp: None,
    };

    match canonicalize(&request) {
        // The request above carries no MCP facts, so its target is an HTTP one. The
        // other arm is unreachable and is written out rather than wildcarded, so that
        // adding a kind makes this harness say something about it.
        Ok(Target::Mcp(_)) => panic!("a request with no MCP facts gives an HTTP target"),
        Ok(Target::Http(target)) => {
            // Not vacuous: the solver must find real bytes that reach this arm.
            kani::cover!(true, "a request inside this bound is accepted");
            assert!(
                target.method().len() <= MAX_METHOD_BYTES,
                "an accepted method is inside its limit"
            );
            assert!(
                target.scheme().len() <= MAX_SCHEME_BYTES,
                "an accepted scheme is inside its limit"
            );
            assert!(
                target.host().len() <= MAX_HOST_BYTES,
                "an accepted host is inside its limit"
            );
            assert!(
                target.path().len() <= MAX_PATH_BYTES,
                "an accepted path is inside its limit"
            );
        }
        Err(denial) => {
            kani::cover!(true, "a request inside this bound is denied");
            assert!(
                is_named_request_denial(denial),
                "a request is denied only by a named request denial"
            );
        }
    }
}

/// **Idempotence.** For every accepted request inside the same bound, writing its
/// target back as request facts (`method`, `scheme`, `HttpTarget::authority`, `path`)
/// and canonicalizing that gives the same target, and writing *that* one back gives the
/// same four byte strings. This is what makes a sealed caveat readable: the token
/// format stores the written-back form and requires it to read back byte for byte.
///
/// **What it does not cover.** The same short bound as totality, so no long host, no
/// five-digit port, no long path. The written-back form itself is not bounded, only the
/// request it came from.
#[kani::proof]
#[kani::unwind(16)]
fn idempotence_a_target_written_back_canonicalizes_to_itself() {
    symbolic_request!(
        method,
        scheme,
        authority,
        path,
        METHOD_BYTES,
        SCHEME_BYTES,
        AUTHORITY_BYTES,
        PATH_BYTES
    );
    let request = RequestFacts {
        method: any_bytes(&method),
        scheme: any_bytes(&scheme),
        authority: any_bytes(&authority),
        path: any_bytes(&path),
        mcp: None,
    };

    let Ok(target) = canonicalize(&request) else {
        return;
    };
    // Not vacuous: without this, a bound that accepted nothing would still "pass".
    kani::cover!(true, "the proof reaches an accepted request");
    let Some(first) = target.as_http() else {
        panic!("a request with no MCP facts gives an HTTP target");
    };

    let written_method = String::from(first.method());
    let written_scheme = String::from(first.scheme());
    let written_authority = first.authority();
    let written_path = String::from(first.path());
    let written = RequestFacts {
        method: written_method.as_bytes(),
        scheme: written_scheme.as_bytes(),
        authority: written_authority.as_bytes(),
        path: written_path.as_bytes(),
        mcp: None,
    };

    let Ok(Target::Http(second)) = canonicalize(&written) else {
        panic!("a target written back is denied");
    };

    assert!(
        second == *first,
        "a target written back canonicalizes to the same target"
    );
    assert!(
        second.method() == written_method
            && second.scheme() == written_scheme
            && second.authority() == written_authority
            && second.path() == written_path,
        "writing the second target back gives the same bytes"
    );
    assert!(
        written_authority.len() <= MAX_AUTHORITY_BYTES,
        "a written-back authority is inside the authority limit"
    );
}

/// **No merge.** For every pair of requests inside the merge bound that are both
/// accepted and get the *same* target, a second and simpler reading of their raw bytes
/// agrees: the method bytes are identical, the scheme bytes are identical, the host
/// bytes are identical, and the ports are equal (an absent port counting as the
/// scheme's default). The path is compared before any `?`, because dropping the query
/// is the one merge the canonicalizer makes on purpose.
///
/// This is the invariant that stops the allowlist failing open: a merge is the only way
/// an exact-match allowlist can let through a request nobody observed.
///
/// The last assertion is stronger than the invariants ask for, and follows from them:
/// because the scheme's default port written out is denied, an accepted authority
/// is the only spelling of its host and port, so the whole authority must match byte
/// for byte, not just the host.
///
/// **What it does not cover.** Three bytes of authority and two of path per request.
/// Two long hosts that merge, or two long paths that merge, are outside it.
#[kani::proof]
#[kani::unwind(16)]
fn no_merge_one_target_means_the_same_method_scheme_host_port_and_path() {
    symbolic_request!(
        left_method,
        left_scheme,
        left_authority,
        left_path,
        MERGE_METHOD_BYTES,
        MERGE_SCHEME_BYTES,
        MERGE_AUTHORITY_BYTES,
        MERGE_PATH_BYTES
    );
    let left = RequestFacts {
        method: any_bytes(&left_method),
        scheme: any_bytes(&left_scheme),
        authority: any_bytes(&left_authority),
        path: any_bytes(&left_path),
        mcp: None,
    };

    symbolic_request!(
        right_method,
        right_scheme,
        right_authority,
        right_path,
        MERGE_METHOD_BYTES,
        MERGE_SCHEME_BYTES,
        MERGE_AUTHORITY_BYTES,
        MERGE_PATH_BYTES
    );
    let right = RequestFacts {
        method: any_bytes(&right_method),
        scheme: any_bytes(&right_scheme),
        authority: any_bytes(&right_authority),
        path: any_bytes(&right_path),
        mcp: None,
    };

    let (Ok(left_target), Ok(right_target)) = (canonicalize(&left), canonicalize(&right)) else {
        return;
    };
    kani::assume(left_target == right_target);

    // Not vacuous, and not trivial: the solver must find two requests whose *bytes*
    // differ yet whose targets are the same. That pair exists on purpose (a dropped
    // query), so a bound where it did not would be a bound that proves nothing.
    kani::cover!(
        left.path != right.path,
        "two requests with different bytes share a target"
    );

    assert!(
        left.method == right.method,
        "one target means one method, byte for byte"
    );
    assert!(
        left.scheme == right.scheme,
        "one target means one scheme, byte for byte"
    );

    let left_split = raw_host_and_port(left.authority, left.scheme);
    let right_split = raw_host_and_port(right.authority, right.scheme);
    assert!(
        left_split.is_some() && right_split.is_some(),
        "an accepted authority splits into a host and a port"
    );
    assert!(
        left_split == right_split,
        "one target means one host, byte for byte, and one port"
    );
    assert!(
        raw_path(left.path) == raw_path(right.path),
        "one target means one path before the query, byte for byte"
    );
    assert!(
        left.authority == right.authority,
        "one target means one authority, byte for byte"
    );
}

// ===========================================================================
// Group 2 — the rule layer, over whole domains
// ===========================================================================

/// **Every byte value, through the MCP value rule, in one proof.**
///
/// The `mcp` caveat kind's two byte classes, and the difference between them is the
/// whole point. An `Mcp-Method` or `Mcp-Name` **value** may hold exactly the printable
/// ASCII bytes, the token's two separators included, because a conforming value may
/// carry either. A **caveat body** may not hold those two, so the value is stored
/// percent-encoded and the body holds only what is left. A sampled test can only show
/// the bytes somebody thought of; this covers all 256 at once, in both classes.
///
/// It is stated over a value with the symbolic byte *between* two plain ones, because
/// a leading or trailing space is MCP's own wrapping trigger and is a rule of its own —
/// and three bytes is still short enough that the sentinel rules cannot fire (a value
/// needs four bytes to carry both markers).
#[kani::proof]
#[kani::unwind(16)]
fn every_mcp_value_byte_is_classified_the_way_the_rule_says() {
    let byte: u8 = kani::any();
    let value = [b'a', byte, b'b'];
    let request = RequestFacts {
        method: b"POST",
        scheme: b"https",
        authority: b"mcp.example.com",
        path: b"/mcp",
        mcp: Some(crate::target::McpFacts {
            method: b"tools/call",
            name: &value,
        }),
    };
    let target = canonicalize(&request);
    let accepted = target.is_ok();

    assert!(
        accepted == matches!(byte, 0x20..=0x7E),
        "an MCP value holds exactly the printable ASCII bytes"
    );
    assert!(
        !accepted || !byte.is_ascii_control(),
        "a control byte is denied"
    );
    assert!(
        accepted || byte != b'a',
        "an ordinary name byte is accepted"
    );
    assert!(
        accepted || (byte != b' ' && byte != b';'),
        "a value carrying either separator is expressible, never denied"
    );
    // The separators are kept out of the caveat body by the *storage* rule, not by
    // denying the value: whatever the byte was, what is stored holds neither.
    if let Ok(Target::Mcp(mcp)) = target {
        for stored in mcp.name().as_bytes() {
            assert!(
                *stored != b' ' && *stored != b';',
                "neither of the token's separators can reach a caveat body"
            );
            assert!(
                matches!(stored, 0x21..=0x7E),
                "a caveat body is printable ASCII"
            );
        }
    }
    kani::cover!(accepted, "some byte is accepted");
}

/// **Every byte value, through the storage rule, in one proof.**
///
/// The second of the `mcp` kind's two byte classes, read from the other side: which
/// bytes a caveat body may hold as themselves, and which escapes it may hold at all.
/// This is the rule `format.rs` leans on when it promises a body holds no separator, and
/// the rule that keeps one value from having two stored spellings.
///
/// Both halves are stated over three bytes with one symbolic, which is the whole domain:
/// the rule classifies each position on its own.
#[kani::proof]
#[kani::unwind(16)]
fn every_stored_mcp_value_byte_is_classified_the_way_the_rule_says() {
    let byte: u8 = kani::any();

    // A byte standing for itself is held exactly when it is not one of the three that
    // had to be encoded.
    let plain = [b'a', byte, b'b'];
    assert!(
        stored_mcp_value(&plain).is_some()
            == (matches!(byte, 0x21..=0x7E) && byte != b'%' && byte != b';'),
        "a caveat body holds exactly the bytes that did not have to be encoded"
    );

    // And an escape is read exactly when it names one of those three, in uppercase hex.
    // `%41` for `A` would be a second stored spelling of one value; `%3b` a second
    // spelling of one escape.
    let escaped = [b'%', byte, b'0'];
    assert!(
        stored_mcp_value(&escaped).is_some() == (byte == b'2'),
        "only %20, %25 and %3B name a byte that had to be encoded"
    );
    kani::cover!(
        stored_mcp_value(&plain).is_some(),
        "some byte is held as itself"
    );
}

/// **The storage encoding is exactly invertible.**
///
/// A caveat body holds an MCP value percent-encoded, and the token format's write-back
/// check requires a stored caveat to produce the same bytes again. That holds only if
/// [`store_mcp_value`] and [`stored_mcp_value`] are inverses: what is written must read
/// back, unchanged.
///
/// **This one does not finish, and it is kept for the same reason the group-1 harnesses
/// are.** The cost is the one this file's header names: [`store_mcp_value`] builds a
/// `String` from bytes the solver does not know, so its length, capacity and growth are
/// all symbolic.
///
/// What it states is worth proving, so it stays. What actually pins it today is Rust:
/// `every_admitted_value_stores_and_reads_back_unchanged` in `canonical.rs` walks all 95
/// admitted bytes, and `crates/gate/tests/invariants.rs` seals every accepted target into
/// a token and reads it back, 200,000 hostile rounds per run. The classification either
/// side of the round trip is proved complete by the harness above; it is the join between
/// them that is sampled rather than proved.
#[kani::proof]
#[kani::unwind(16)]
fn a_written_mcp_value_reads_back_unchanged() {
    let byte: u8 = kani::any();
    kani::assume(byte == b' ' || byte == b'%' || byte == b';' || byte == b'a');

    let value = [b'a', byte, b'b'];
    let stored = store_mcp_value(&value);
    assert!(
        stored_mcp_value(stored.as_bytes()).as_deref() == Some(stored.as_str()),
        "a stored value reads back as itself"
    );
    kani::cover!(true, "the proof reaches an admitted value");
}

/// **Every byte value, all 256 of them, through every byte rule at once.** This is not
/// a bound: `u8` has 256 values and the proof covers all of them, so it is complete.
///
/// Each assertion states a canonicalizer rule in its own words,
/// rather than restating the code:
///
/// - A byte above ASCII can never appear in a path as itself, and is allowed to stay
///   percent-encoded (that is how a non-ASCII path arrives and stays comparable).
/// - A control byte is denied both ways: as itself and percent-encoded.
/// - An unreserved byte must appear as itself and is denied percent-encoded, so nobody
///   can spell `/a` as `/%61` and reach a different target.
/// - The bytes that change a path's structure — `/`, `\`, `%`, `;` — are denied
///   percent-encoded, so no amount of decoding can turn one target into another.
/// - A percent-encoding digit is uppercase only: `%c3` is denied, not folded to `%C3`.
/// - A method byte is an RFC 9110 token byte, which excludes the token format's two
///   separators, `;` and space, so a method can never forge a token's structure.
#[kani::proof]
fn every_byte_is_classified_the_way_the_rules_say() {
    let byte: u8 = kani::any();

    assert!(
        byte < 0x80 || (!is_plain_path_byte(byte) && may_stay_encoded(byte)),
        "a non-ASCII byte must be percent-encoded, and stays that way"
    );
    assert!(
        !byte.is_ascii_control() || (!is_plain_path_byte(byte) && !may_stay_encoded(byte)),
        "a control byte is denied as itself and denied encoded"
    );
    assert!(
        !is_unreserved(byte) || (is_plain_path_byte(byte) && !may_stay_encoded(byte)),
        "an unreserved byte must appear as itself, never encoded"
    );
    assert!(
        !matches!(byte, b'/' | b'\\' | b'%' | b';') || !may_stay_encoded(byte),
        "a byte that changes a path's structure is denied encoded"
    );
    assert!(
        !matches!(byte, b';' | b'\\' | b'%' | b'?' | b'#' | b' ') || !is_plain_path_byte(byte),
        "the bytes servers read differently are denied as themselves"
    );
    assert!(
        uppercase_hex_value(byte).is_some() == matches!(byte, b'0'..=b'9' | b'A'..=b'F'),
        "a percent-encoding digit is a digit or an uppercase hex letter, and nothing else"
    );
    assert!(
        !matches!(byte, b'a'..=b'f') || uppercase_hex_value(byte).is_none(),
        "lowercase hex is denied in a path, not folded to uppercase"
    );
    assert!(
        match uppercase_hex_value(byte) {
            Some(value) => value <= 15,
            None => true,
        },
        "a hex digit's value fits in four bits, so hex_byte cannot overflow"
    );
    assert!(
        !is_tchar(byte) || (byte >= 0x21 && byte < 0x7f && byte != b';'),
        "a method byte is a visible ASCII byte and never the token format's separator"
    );
    assert!(
        !is_tchar(b';') && !is_tchar(b' ') && !is_tchar(b'\t'),
        "a method can never carry the token format's separators"
    );
}

/// **Every spelling of a scheme, up to five bytes.** Complete for the rule, not just a
/// bound: `canonical_scheme` matches the whole slice against two literals, so a slice
/// of six bytes or more cannot equal either and is denied for the same reason a
/// five-byte one is.
///
/// What it proves: the only two accepted spellings are the exact lowercase bytes.
/// `HTTPS`, `Http` and every other casing is denied rather than folded — the merge this
/// rule exists to prevent.
#[kani::proof]
#[kani::unwind(8)]
fn a_scheme_is_accepted_only_as_exact_lowercase_bytes() {
    let buffer: [u8; SCHEME_BYTES] = kani::any();
    let scheme = any_bytes(&buffer);

    match canonical_scheme(scheme) {
        Ok(Scheme::Http) => {
            kani::cover!(true, "http is reachable");
            assert!(
                scheme == b"http",
                "only the exact bytes `http` read as http"
            );
        }
        Ok(Scheme::Https) => {
            kani::cover!(true, "https is reachable");
            assert!(
                scheme == b"https",
                "only the exact bytes `https` read as https"
            );
        }
        Err(denial) => {
            assert!(
                denial == Denial::UnsupportedScheme,
                "a scheme is denied only as UnsupportedScheme"
            );
            assert!(
                scheme != b"http" && scheme != b"https",
                "neither accepted spelling is ever denied"
            );
        }
    }
}

/// **Every authority up to six bytes, split.** The split must lose nothing and invent
/// nothing: host and port are adjacent pieces of the same bytes with one `:` between
/// them, so no byte of the authority can go unchecked by a later rule.
///
/// **What it does not cover.** Six bytes, so not a full-length host with a five-digit
/// port. It does cover `@`, `[`, `]` and `:` in every position inside that bound, which
/// is where the split can go wrong.
#[kani::proof]
#[kani::unwind(8)]
fn the_authority_split_loses_no_byte_and_denies_user_info() {
    let buffer: [u8; 6] = kani::any();
    let authority = any_bytes(&buffer);

    match split_authority(authority) {
        Ok((host, None)) => {
            kani::cover!(true, "an authority with no port is reachable");
            assert!(
                host == authority,
                "with no port the host is the whole authority"
            );
        }
        Ok((host, Some(port))) => {
            kani::cover!(true, "an authority with a port is reachable");
            assert!(
                host.len().saturating_add(port.len()).saturating_add(1) == authority.len(),
                "host, one colon and port account for every byte of the authority"
            );
            assert!(
                authority.get(host.len()) == Some(&b':'),
                "the byte between host and port is the colon"
            );
        }
        Err(denial) => {
            assert!(
                denial == Denial::MalformedHost,
                "a split failure is named MalformedHost"
            );
        }
    }
    assert!(
        !authority.contains(&b'@') || split_authority(authority).is_err(),
        "user info is denied outright, wherever the `@` is"
    );
}

/// **Every port spelling, over the whole domain the rule can see.** Complete rather
/// than bounded: a port of six bytes or more is denied by the length check without
/// being read, so five symbolic bytes is the entire input space that reaches the rule.
///
/// What it proves: an accepted port is plain digits with no leading zero, is never
/// zero, and is never the scheme's default written out — the three spellings that would
/// otherwise merge two authorities into one target.
#[kani::proof]
#[kani::unwind(8)]
fn a_port_is_accepted_only_in_its_one_canonical_spelling() {
    let buffer: [u8; 5] = kani::any();
    let digits = any_bytes(&buffer);
    let scheme = if kani::any::<bool>() {
        Scheme::Https
    } else {
        Scheme::Http
    };

    match canonical_port(digits, scheme) {
        Ok(port) => {
            kani::cover!(true, "an accepted port is reachable");
            assert!(port != 0, "port zero is denied");
            assert!(
                port != scheme.default_port(),
                "the scheme's default written out is denied, not merged with no port"
            );
            assert!(
                digits.iter().all(u8::is_ascii_digit) && digits.first() != Some(&b'0'),
                "an accepted port is plain digits with no leading zero"
            );
        }
        Err(denial) => assert!(
            denial == Denial::MalformedPort,
            "a port is denied only as MalformedPort"
        ),
    }
}

/// **Every accepted port is written back the way it was read.** For every byte string
/// of at most five bytes the port rule accepts, `write_authority` spells the port back
/// as exactly those bytes, and reading those bytes again gives the same port. So a
/// caveat's authority always reads back to the port it was sealed from, for every port,
/// and two different port spellings can never reach one port value.
///
/// Together with the rule above this is the port half of idempotence, over the port's
/// whole domain rather than a bound.
#[kani::proof]
#[kani::unwind(8)]
fn every_accepted_port_is_written_back_the_way_it_was_read() {
    let buffer: [u8; 5] = kani::any();
    let digits = any_bytes(&buffer);
    let scheme = if kani::any::<bool>() {
        Scheme::Https
    } else {
        Scheme::Http
    };

    let Ok(port) = canonical_port(digits, scheme) else {
        return;
    };
    kani::cover!(true, "the proof reaches an accepted port");

    // An accepted port is never the scheme's default, so `write_authority` spells it.
    let authority = write_authority(scheme, "a", port);
    let spelled = authority.as_bytes();
    assert!(
        spelled.len() >= 2 && spelled[0] == b'a' && spelled[1] == b':',
        "an accepted port is always written out"
    );
    let written_back = &spelled[2..];
    assert!(
        written_back == digits,
        "a port is written back as exactly the bytes it was read from"
    );
    assert!(
        canonical_port(written_back, scheme) == Ok(port),
        "a written-back port reads back to the same port"
    );
}

/// **Every host name up to six bytes.** What it proves about an accepted name: it is
/// not empty, has no uppercase byte, has no byte above ASCII, has no trailing dot and
/// no empty label. Uppercase and a trailing dot are the two spellings a router may keep
/// apart, so folding either would be a merge.
///
/// **What it does not cover.** Six bytes, so not the 253-byte limit, and not the whole
/// dotted-quad rule (`255.255.255.255` is fifteen bytes). It does cover the
/// "ends in a number" rule for short numeric names such as `1`, `0x`, `1.2` and `12.3`.
#[kani::proof]
#[kani::unwind(8)]
fn an_accepted_host_name_is_already_in_its_one_spelling() {
    let buffer: [u8; 6] = kani::any();
    let host = any_bytes(&buffer);

    let accepted = is_host_name(host) && (!ends_in_number(host) || is_dotted_quad(host));
    if !accepted {
        return;
    }
    kani::cover!(true, "an accepted host name is reachable");

    assert!(!host.is_empty(), "the empty host is denied");
    assert!(
        host.iter().all(|&byte| !byte.is_ascii_uppercase()),
        "an uppercase host is denied, not folded to lowercase"
    );
    assert!(
        host.iter().all(|&byte| byte < 0x80),
        "a non-ASCII host is denied; an international name must arrive as punycode"
    );
    assert!(
        host.last() != Some(&b'.'),
        "a trailing dot is denied: it can resolve differently"
    );
    assert!(
        !host.windows(2).any(|pair| pair == b".."),
        "an empty label is denied"
    );
}

/// **Every IPv6 address, all 2^128 of them.** For every address: the RFC 5952 text the
/// canonicalizer writes for it reads back to the same address, is accepted as canonical,
/// and is short enough to be a host. No sampled or exhaustive test can cover this space;
/// a model checker can, because it reasons about the 128 bits symbolically instead of
/// enumerating them.
///
/// Together with the host rule this is the IPv6 half of no merge: two different
/// addresses cannot share a spelling, because each spelling reads back to the address it
/// was written from.
///
/// **What it does not cover.** That every *non*-canonical text is denied. That follows
/// from `is_canonical_ipv6` comparing against `write_ipv6`, which is code, not a claim
/// proved here.
///
/// **The IPv4-mapped prefix is assumed away.** `::ffff:0:0/96` has two recommended text
/// forms (RFC 5952 §4 and §5), so the canonicalizer denies it in both rather than
/// picking one ([`is_ipv4_mapped`]). For those addresses `write_ipv6` still writes a
/// text, and that text still reads back to the same address, but it is no longer
/// *accepted*, so the second assertion below would be false for them. They are assumed
/// out rather than special-cased, because the claim this harness makes is about the
/// addresses the canonicalizer accepts at all.
///
/// **Status: does not finish.** [`write_ipv6`] calls `format!("{group:x}")` eight times and
/// joins the results through a `Vec<String>`, so this is roughly eight times the
/// `core::fmt` work of
/// [`every_accepted_port_is_written_back_the_way_it_was_read`], which does the same
/// shape of round trip for **one** symbolic integer. Reducing it to two symbolic groups
/// with the other six fixed would no longer be a statement about the whole address
/// space, which is the only reason to write it.
#[kani::proof]
#[kani::unwind(24)]
fn every_ipv6_address_has_exactly_one_accepted_spelling() {
    let groups: [u16; 8] = kani::any();
    kani::assume(!is_ipv4_mapped(&groups));
    let text = write_ipv6(&groups);

    assert!(
        parse_ipv6(text.as_bytes()) == Some(groups),
        "the text written for an address reads back to that address"
    );
    assert!(
        is_canonical_ipv6(text.as_bytes()),
        "the text written for an address is accepted as canonical"
    );
    assert!(
        text.len() <= 39,
        "an IPv6 literal is at most 39 bytes, so it fits inside the host limit"
    );
}
