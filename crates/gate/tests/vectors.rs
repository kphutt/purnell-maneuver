//! Runs every case in `testdata/vectors/compare_secrets.json` against
//! `gate::compare_secrets`.
//!
//! This is a plain-Rust integration test (a file under `tests/`), which cargo always
//! compiles as its own, ordinary `std` binary — separate from the `no_std` `gate`
//! library it links against. That is what lets this test use a JSON-reading
//! dependency (`serde_json`) as a dev-dependency without the `gate` crate itself
//! gaining a `std` dependency: `cargo build` never compiles dev-dependencies, only
//! `cargo test` does.
//!
//! `unwrap`/`expect`/`panic!` are used freely below: this file lives under `tests/`, so
//! `cargo clippy` (run without `--tests`) never compiles it, and its panic lints from
//! `[workspace.lints.clippy]` never apply here.

use gate::{compare_secrets, Comparison, GateError};
use serde::Deserialize;

/// The `"format"` value this test reader knows how to read. Bump this, and the
/// `match` in `shared_vectors_pass` below, in the same change that changes the shape
/// of a case (adding/removing/renaming a field, changing what a value means) -- never
/// change the shape without bumping the number. A reader given a format it doesn't
/// know fails loudly instead of silently misreading the new shape.
const KNOWN_FORMAT: u32 = 1;

/// Mirrors the JSON `"expected"` string as a real enum instead of matching a string by
/// hand, so an unrecognized value is a deserialization error (naming the bad case)
/// rather than a `panic!` reached deep inside the test loop.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Expected {
    Equal,
    NotEqual,
    /// Mirrors `gate::GateError::InputTooLong`. Named after the Rust error variant
    /// (`error_` prefix, `snake_case` of the variant name) so a non-Rust binding can
    /// read this the same way without knowing Rust enum syntax.
    ErrorInputTooLong,
}

/// One input to a case: either a literal hex string (`"a_hex"`/`"b_hex"`), or a
/// compact description of a generated input (`"a_gen"`/`"b_gen"`) -- `{ "repeat_byte":
/// "<two hex digits>", "len": <n> }` means "`len` bytes, each equal to `repeat_byte`".
/// `a_gen`/`b_gen` exist so an over-the-limit case (thousands of bytes) doesn't have to
/// paste kilobytes of hex into this file; a case sets exactly one of the `_hex`/`_gen`
/// pair per side.
#[derive(Deserialize)]
struct Generated {
    repeat_byte: String,
    len: usize,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(default)]
    a_hex: Option<String>,
    #[serde(default)]
    a_gen: Option<Generated>,
    #[serde(default)]
    b_hex: Option<String>,
    #[serde(default)]
    b_gen: Option<Generated>,
    expected: Expected,
    /// Optional human-readable explanation of what the case means. Documentation for
    /// whoever edits the JSON; the test itself doesn't read it.
    #[allow(dead_code)]
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize)]
struct VectorFile {
    format: u32,
    cases: Vec<Case>,
}

/// Resolves one side (`a` or `b`) of a case to its raw bytes, from whichever of its
/// `_hex`/`_gen` fields is set.
fn resolve_side(
    hex_field: &Option<String>,
    gen_field: &Option<Generated>,
    side: &str,
    case_name: &str,
) -> Result<Vec<u8>, String> {
    match (hex_field, gen_field) {
        (Some(hex), None) => hex::decode(hex)
            .map_err(|e| format!("case {case_name:?}: {side}_hex is not valid hex: {e}")),
        (None, Some(gen)) => {
            let byte = hex::decode(&gen.repeat_byte).map_err(|e| {
                format!("case {case_name:?}: {side}_gen.repeat_byte is not valid hex: {e}")
            })?;
            let &[byte] = byte.as_slice() else {
                return Err(format!(
                    "case {case_name:?}: {side}_gen.repeat_byte must decode to exactly one byte, got {}",
                    byte.len()
                ));
            };
            Ok(vec![byte; gen.len])
        }
        (Some(_), Some(_)) => Err(format!(
            "case {case_name:?}: both {side}_hex and {side}_gen are set; a case must set exactly one"
        )),
        (None, None) => Err(format!(
            "case {case_name:?}: neither {side}_hex nor {side}_gen is set; a case must set exactly one"
        )),
    }
}

#[test]
fn shared_vectors_pass() {
    let file: VectorFile = serde_json::from_str(VECTORS_JSON)
        .expect("testdata/vectors/compare_secrets.json must be valid JSON");
    assert_eq!(
        file.format, KNOWN_FORMAT,
        "testdata/vectors/compare_secrets.json has \"format\": {}, but this test reader only \
         knows format {KNOWN_FORMAT}; update crates/gate/tests/vectors.rs to read the new \
         format (and bump KNOWN_FORMAT) before changing the file's format",
        file.format
    );
    assert!(
        !file.cases.is_empty(),
        "expected at least one shared test vector"
    );

    // Collect every failing case instead of stopping at the first, so one failed run
    // names everything that's broken rather than making the fix-run-fix loop
    // rediscover the next failure one at a time.
    let mut failures = Vec::new();
    for case in file.cases {
        let a = match resolve_side(&case.a_hex, &case.a_gen, "a", &case.name) {
            Ok(bytes) => bytes,
            Err(msg) => {
                failures.push(msg);
                continue;
            }
        };
        let b = match resolve_side(&case.b_hex, &case.b_gen, "b", &case.name) {
            Ok(bytes) => bytes,
            Err(msg) => {
                failures.push(msg);
                continue;
            }
        };

        let actual = compare_secrets(&a, &b);
        let matches = matches!(
            (case.expected, actual),
            (Expected::Equal, Ok(Comparison::Equal))
                | (Expected::NotEqual, Ok(Comparison::NotEqual))
                | (Expected::ErrorInputTooLong, Err(GateError::InputTooLong))
        );
        if !matches {
            failures.push(format!(
                "case {:?}: expected {:?}, got {actual:?}",
                case.name, case.expected
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of the shared vector cases failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

const VECTORS_JSON: &str = include_str!("../../../testdata/vectors/compare_secrets.json");
