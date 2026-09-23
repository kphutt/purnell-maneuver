//! Runs every case in `testdata/vectors/compare_secrets.json` against
//! `gate::compare_secrets`.
//!
//! This is a plain-Rust integration test (a file under `tests/`), which cargo always
//! compiles as its own, ordinary `std` binary — separate from the `no_std` `gate`
//! library it links against. That is what lets this test use a JSON-reading
//! dependency (`tinyjson`) as a dev-dependency without the `gate` crate itself
//! gaining a `std` dependency: `cargo build` never compiles dev-dependencies, only
//! `cargo test` does.
//!
//! JSON reading uses `tinyjson` (no build script, no proc-macro, no non-dev
//! dependencies of its own) rather than `serde`/`serde_json`, and hex decoding is a
//! few lines below rather than the `hex` crate, so this test-only dependency tree
//! stays free of build scripts and proc-macros too.
//!
//! `unwrap`/`expect`/`panic!` are used freely below: a test fails by panicking, so the
//! panic lints from `[workspace.lints.clippy]` are allowed at the top of this file
//! (`cargo clippy --all-targets` lints it like every other test). A
//! malformed *file* (bad JSON, an unknown "format", a case missing "name" or
//! "expected") panics immediately, since that means the shared test data itself is
//! broken. A malformed or mismatching *case value* (bad hex, a comparison that doesn't
//! match "expected") is collected into `failures` instead, so one run reports every
//! broken case at once rather than stopping at the first.

// A test binary: panicking is how a test fails. clippy.toml already exempts `#[test]`
// functions from the panic lints; this extends that to the helpers they call.
#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use gate::{compare_secrets, Comparison, GateError};
use std::collections::HashMap;
use tinyjson::JsonValue;

/// The `"format"` value this test reader knows how to read. Bump this, and
/// `Expected::parse` below, in the same change that changes the shape of a case
/// (adding/removing/renaming a field, changing what a value means) -- never change the
/// shape without bumping the number. A reader given a format it doesn't know fails
/// loudly instead of silently misreading the new shape.
const KNOWN_FORMAT: f64 = 1.0;

/// Mirrors the JSON `"expected"` string as a real enum instead of matching a string by
/// hand every time it's used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    Equal,
    NotEqual,
    /// Mirrors `gate::GateError::InputTooLong`. Named after the Rust error variant
    /// (`error_` prefix, `snake_case` of the variant name) so a non-Rust binding can
    /// read this the same way without knowing Rust enum syntax.
    ErrorInputTooLong,
}

impl Expected {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "equal" => Some(Expected::Equal),
            "not_equal" => Some(Expected::NotEqual),
            "error_input_too_long" => Some(Expected::ErrorInputTooLong),
            _ => None,
        }
    }
}

/// A generated input: `len` bytes, each equal to `repeat_byte`. Exists so an
/// over-the-limit case (thousands of bytes) doesn't have to paste kilobytes of hex
/// into the JSON file; a case sets exactly one of `{a,b}_hex`/`{a,b}_gen` per side.
struct Generated {
    repeat_byte: String,
    len: usize,
}

/// Decodes a hex string such as `"68656c6c6f"` into raw bytes. A hand-written decoder
/// instead of the `hex` crate: this file is test-only, but every dependency still
/// widens the supply-chain surface, so a few lines beat a crate for something this
/// small.
fn decode_hex(hex: &str, context: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("{context}: hex string {hex:?} has an odd length"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            let pair = hex
                .get(i..i + 2)
                .ok_or_else(|| format!("{context}: {hex:?} is not valid ASCII hex"))?;
            u8::from_str_radix(pair, 16)
                .map_err(|e| format!("{context}: {pair:?} in {hex:?} is not valid hex: {e}"))
        })
        .collect()
}

/// Reads a string field from a JSON object, or `None` if it's absent or not a string.
fn field_str(obj: &HashMap<String, JsonValue>, key: &str) -> Option<String> {
    obj.get(key).and_then(JsonValue::get::<String>).cloned()
}

/// Reads an object field from a JSON object, or `None` if it's absent or not an
/// object.
fn field_object<'a>(
    obj: &'a HashMap<String, JsonValue>,
    key: &str,
) -> Option<&'a HashMap<String, JsonValue>> {
    obj.get(key)
        .and_then(JsonValue::get::<HashMap<String, JsonValue>>)
}

fn parse_generated(obj: &HashMap<String, JsonValue>, context: &str) -> Result<Generated, String> {
    let repeat_byte = field_str(obj, "repeat_byte")
        .ok_or_else(|| format!("{context}: missing or non-string \"repeat_byte\""))?;
    let len = obj
        .get("len")
        .and_then(JsonValue::get::<f64>)
        .ok_or_else(|| format!("{context}: missing or non-number \"len\""))?;
    Ok(Generated {
        repeat_byte,
        len: *len as usize,
    })
}

/// Resolves one side (`a` or `b`) of a case to its raw bytes, from whichever of its
/// `_hex`/`_gen` fields is set.
fn resolve_side(
    case: &HashMap<String, JsonValue>,
    side: &str,
    case_name: &str,
) -> Result<Vec<u8>, String> {
    let hex_field = field_str(case, &format!("{side}_hex"));
    let gen_field = field_object(case, &format!("{side}_gen"));

    match (hex_field, gen_field) {
        (Some(hex), None) => decode_hex(&hex, &format!("case {case_name:?}: {side}_hex")),
        (None, Some(gen_obj)) => {
            let context = format!("case {case_name:?}: {side}_gen");
            let gen = parse_generated(gen_obj, &context)?;
            let byte = decode_hex(&gen.repeat_byte, &format!("{context}.repeat_byte"))?;
            let &[byte] = byte.as_slice() else {
                return Err(format!(
                    "{context}.repeat_byte must decode to exactly one byte, got {}",
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
    let value: JsonValue = VECTORS_JSON
        .parse()
        .expect("testdata/vectors/compare_secrets.json must be valid JSON");
    let root: &HashMap<String, JsonValue> = value
        .get()
        .expect("testdata/vectors/compare_secrets.json must be a JSON object");

    let format = root
        .get("format")
        .and_then(JsonValue::get::<f64>)
        .expect("testdata/vectors/compare_secrets.json must have a numeric \"format\" field");
    assert_eq!(
        *format, KNOWN_FORMAT,
        "testdata/vectors/compare_secrets.json has \"format\": {format}, but this test reader \
         only knows format {KNOWN_FORMAT}; update crates/gate/tests/vectors.rs to read the new \
         format (and bump KNOWN_FORMAT) before changing the file's format",
    );

    let cases = root
        .get("cases")
        .and_then(JsonValue::get::<Vec<JsonValue>>)
        .expect("testdata/vectors/compare_secrets.json must have an array \"cases\" field");
    assert!(
        !cases.is_empty(),
        "expected at least one shared test vector"
    );

    // Collect every failing case instead of stopping at the first, so one failed run
    // names everything that's broken rather than making the fix-run-fix loop
    // rediscover the next failure one at a time.
    let mut failures = Vec::new();
    for case_value in cases {
        let case: &HashMap<String, JsonValue> = case_value
            .get()
            .expect("every entry in \"cases\" must be a JSON object");
        let name = field_str(case, "name")
            .unwrap_or_else(|| panic!("a case in \"cases\" is missing a string \"name\" field"));
        let expected_raw = field_str(case, "expected")
            .unwrap_or_else(|| panic!("case {name:?}: missing or non-string \"expected\" field"));
        let expected = Expected::parse(&expected_raw).unwrap_or_else(|| {
            panic!("case {name:?}: unrecognized \"expected\" value {expected_raw:?}")
        });

        let a = match resolve_side(case, "a", &name) {
            Ok(bytes) => bytes,
            Err(msg) => {
                failures.push(msg);
                continue;
            }
        };
        let b = match resolve_side(case, "b", &name) {
            Ok(bytes) => bytes,
            Err(msg) => {
                failures.push(msg);
                continue;
            }
        };

        let actual = compare_secrets(&a, &b);
        let matches = matches!(
            (expected, actual),
            (Expected::Equal, Ok(Comparison::Equal))
                | (Expected::NotEqual, Ok(Comparison::NotEqual))
                | (Expected::ErrorInputTooLong, Err(GateError::InputTooLong))
        );
        if !matches {
            failures.push(format!(
                "case {name:?}: expected {expected:?}, got {actual:?}"
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
