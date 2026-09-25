//! A guard on the *text* of `compare_secrets`, because no behaviour test can see
//! what it guards.
//!
//! `compare_secrets` compares two secrets in constant time, which is a property of how
//! long it takes, not of what it answers. Replace `a.ct_eq(b)` with `a == b` and every
//! answer stays exactly the same: the unit tests in `src/lib.rs` pass, the
//! `compare_secrets.json` vectors pass, the fuzz loop passes. Nothing in the suite
//! goes red, and the library has quietly gained a timing side channel that leaks a
//! secret one byte at a time.
//!
//! So this test reads the source instead. Be clear about what that is worth:
//!
//! - **It checks the implementation's text, not its timing.** It asserts that the body
//!   of `compare_secrets` still calls `ct_eq` and that the file still imports
//!   `subtle::ConstantTimeEq`. That is all.
//! - **It is deliberately crude.** It cannot tell a constant-time rewrite
//!   from a variable-time one. Someone who replaces `subtle` with their own correct
//!   constant-time comparison will have to change this test, and someone who writes a
//!   variable-time one that happens to mention `ct_eq` will get away with it.
//! - **A statistical timing measurement is the real test, and it does not belong
//!   here.** Timing two branches apart needs many samples, an optimised build and a
//!   quiet machine; in a debug build on a shared runner it is flaky, and a flaky
//!   security test gets muted, which is worse than no test.
//!
//! It earns its place on one property alone: the failure it guards against is silent
//! in every other test in the repo. A crude check that fires beats a precise one that
//! is never trusted enough to run.

// A test binary: panicking is how a test fails. clippy.toml already exempts `#[test]`
// functions from the panic lints; this extends that to the helpers they call.
#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

/// The source of the crate under test, read at compile time. `include_str!` resolves
/// relative to this file, so this is `crates/gate/src/lib.rs`.
const GATE_SOURCE: &str = include_str!("../src/lib.rs");

/// The body of `compare_secrets`: everything from its signature to the first line that
/// is a lone `}` at column zero, which is how `rustfmt` closes a top-level function in
/// this repo.
fn compare_secrets_body() -> &'static str {
    let start = GATE_SOURCE
        .find("pub fn compare_secrets(")
        .expect("crates/gate/src/lib.rs must define `pub fn compare_secrets`");
    let body = &GATE_SOURCE[start..];
    let end = body
        .find("\n}\n")
        .expect("`compare_secrets` must end with a closing brace at column zero");
    &body[..end]
}

#[test]
fn compare_secrets_still_compares_in_constant_time() {
    let body = compare_secrets_body();
    assert!(
        body.contains("ct_eq"),
        "the body of `compare_secrets` no longer calls `ct_eq`. If this is a plain \
         `==`, it is a timing side channel: every behaviour test in this repo passes \
         either way, which is why this check reads the source. If it is a different \
         constant-time comparison, change this test in the same commit and say which \
         one it is.\n\n{body}"
    );
    assert!(
        GATE_SOURCE.contains("use subtle::ConstantTimeEq;"),
        "crates/gate/src/lib.rs no longer imports `subtle::ConstantTimeEq`, so \
         whatever `ct_eq` now resolves to is not subtle's constant-time comparison."
    );
}
