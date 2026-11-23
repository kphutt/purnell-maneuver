//! The query is dropped from a target, but its bytes are read first: a raw CR or LF
//! there must not reach a host that forwards the request target.

// A test binary: panicking is how a test fails. clippy.toml already exempts `#[test]`
// functions from the panic lints; this extends that to the helpers they call.
#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use gate::{check, present, Denial, RequestFacts};

const TOKEN: &[u8] = b"v1;http GET https example.com /orders";

fn check_path(path: &[u8]) -> Result<(), Denial> {
    let caveats = present(TOKEN).unwrap().caveats();
    let request = RequestFacts {
        method: b"GET",
        scheme: b"https",
        authority: b"example.com",
        path,
        mcp: None,
    };
    check(caveats, &request).map(|_| ())
}

#[test]
fn a_query_byte_outside_printable_ascii_is_denied_through_check() {
    for byte in 0u8..=255 {
        let expected = if matches!(byte, 0x21..=0x7E) && byte != b'#' {
            Ok(())
        } else {
            Err(Denial::MalformedPath)
        };
        let paths = [
            [b"/orders?".as_slice(), &[byte]].concat(),
            [b"/orders?".as_slice(), &[byte], b"x"].concat(),
            [b"/orders?a=".as_slice(), &[byte], b"b"].concat(),
        ];
        for path in paths {
            assert_eq!(check_path(&path), expected, "{path:?}");
        }
    }
}

#[test]
fn a_crlf_in_the_query_cannot_carry_a_header() {
    assert_eq!(
        check_path(b"/orders?\r\nX-Injected: 1"),
        Err(Denial::MalformedPath)
    );
}

#[test]
fn a_valid_query_stays_allowed() {
    for path in [
        b"/orders?".as_slice(),
        b"/orders?page=2&sort=asc",
        b"/orders?a=%0D%0A",
        b"/orders?x=/../;%zz?y",
    ] {
        assert_eq!(check_path(path), Ok(()), "{path:?}");
    }
}
