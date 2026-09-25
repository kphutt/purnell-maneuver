//! Runs the shared request vectors against `gate` and `seal`:
//!
//! - `testdata/vectors/canonical_target.json`: raw request facts in, canonical target
//!   or named denial out, through `gate::observe`.
//! - `testdata/vectors/flow.json`: observe some requests, learn, seal, then check more
//!   requests against the sealed token. Also a list of hand-written malformed tokens,
//!   none of which may ever be allowed.
//!
//! Fields this reader doesn't use are ignored, so a vector file can gain a field per
//! case (for example the raw request bytes) without breaking it. Changing what an
//! existing field means bumps `"format"`.
//!
//! Like `vectors.rs`, this is an ordinary `std` test binary, so it can use `tinyjson`
//! without the `no_std` libraries gaining a dependency. A broken vector *file* panics
//! at once; a case that gives the wrong answer is collected, so one run names every
//! failing case.

// A test binary: panicking is how a test fails. clippy.toml already exempts `#[test]`
// functions from the panic lints; this extends that to the helpers they call.
#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use std::collections::HashMap;

use gate::{check, observe, Denial, McpFacts, RequestFacts};
use tinyjson::JsonValue;

type Object = HashMap<String, JsonValue>;

/// Format 1: a request is method, scheme, authority and path, plus an optional "mcp"
/// object holding the two mirrored MCP header values. A request without "mcp" has an
/// HTTP target; one with it has an MCP target, and its expected target then also
/// carries "mcp_method" and "mcp_name". Both are fields a reader may not know, which
/// the file's own rule says does not bump the format -- an adapter that ignores them
/// simply fails the `mcp_*` cases, which is the right answer for an adapter that has
/// not implemented the kind.
const KNOWN_FORMAT: f64 = 1.0;

const CANONICAL_JSON: &str = include_str!("../../../testdata/vectors/canonical_target.json");
const FLOW_JSON: &str = include_str!("../../../testdata/vectors/flow.json");

/// The snake_case name a vector file uses for each denial. `Denial::name` is the one
/// source of truth for this mapping; kept as a thin local alias so the call sites
/// below read as "the vector's name for this denial" rather than the method name.
fn denial_name(denial: Denial) -> &'static str {
    denial.name()
}

/// Parses a vector file and checks its `"format"`.
fn load(json: &str, file: &str) -> Object {
    let value: JsonValue = json
        .parse()
        .unwrap_or_else(|e| panic!("{file}: not valid JSON: {e}"));
    let root: Object = value
        .get::<Object>()
        .unwrap_or_else(|| panic!("{file}: must be a JSON object"))
        .clone();
    let format = root
        .get("format")
        .and_then(JsonValue::get::<f64>)
        .unwrap_or_else(|| panic!("{file}: missing numeric \"format\""));
    assert_eq!(
        *format, KNOWN_FORMAT,
        "{file}: unknown format; update this reader first"
    );
    root
}

fn array<'a>(object: &'a Object, key: &str) -> &'a Vec<JsonValue> {
    object
        .get(key)
        .and_then(JsonValue::get::<Vec<JsonValue>>)
        .unwrap_or_else(|| panic!("missing array {key:?}"))
}

fn object(value: &JsonValue) -> &Object {
    value
        .get::<Object>()
        .unwrap_or_else(|| panic!("expected a JSON object, got {value:?}"))
}

fn string<'a>(object: &'a Object, key: &str) -> &'a str {
    object
        .get(key)
        .and_then(JsonValue::get::<String>)
        .unwrap_or_else(|| panic!("missing string {key:?} in {object:?}"))
}

/// The raw request facts of a vector, with the byte fields owned.
struct RawRequest {
    method: Vec<u8>,
    scheme: Vec<u8>,
    authority: Vec<u8>,
    path: Vec<u8>,
    /// The two mirrored MCP header values, when the case gives them.
    mcp: Option<(Vec<u8>, Vec<u8>)>,
}

impl RawRequest {
    fn from_json(value: &JsonValue) -> RawRequest {
        let fields = object(value);
        let bytes = |key: &str| string(fields, key).as_bytes().to_vec();
        let mcp = fields.get("mcp").map(|mcp| {
            let mcp = object(mcp);
            (
                string(mcp, "method").as_bytes().to_vec(),
                string(mcp, "name").as_bytes().to_vec(),
            )
        });
        RawRequest {
            method: bytes("method"),
            scheme: bytes("scheme"),
            authority: bytes("authority"),
            path: bytes("path"),
            mcp,
        }
    }

    fn facts(&self) -> RequestFacts<'_> {
        RequestFacts {
            method: &self.method,
            scheme: &self.scheme,
            authority: &self.authority,
            path: &self.path,
            mcp: self
                .mcp
                .as_ref()
                .map(|(method, name)| McpFacts { method, name }),
        }
    }
}

#[test]
fn canonical_target_vectors_pass() {
    let root = load(CANONICAL_JSON, "canonical_target.json");
    let cases = array(&root, "cases");
    assert!(!cases.is_empty());

    let mut failures = Vec::new();
    for case in cases {
        let case = object(case);
        let name = string(case, "name");
        let request = RawRequest::from_json(&case["request"]);
        let expected = object(&case["expected"]);
        let actual = observe(&request.facts());

        let matches = match (expected.get("target"), expected.get("denial"), &actual) {
            (Some(target), None, Ok(actual)) => {
                let target = object(target);
                // The kind is decided by the request, so the expected target is read
                // the same way: with "mcp" it must be an MCP target, without it an
                // HTTP one. A case can never pass by getting the kind wrong.
                let (actual, mcp_matches) = match (&request.mcp, actual.as_mcp()) {
                    (Some(_), Some(mcp)) => (
                        mcp.http(),
                        mcp.method() == string(target, "mcp_method")
                            && mcp.name() == string(target, "mcp_name"),
                    ),
                    (None, None) => (
                        actual
                            .as_http()
                            .unwrap_or_else(|| panic!("case {name:?}: not an HTTP target")),
                        true,
                    ),
                    _ => panic!("case {name:?}: the target's kind is not the request's kind"),
                };
                let port = target
                    .get("port")
                    .and_then(JsonValue::get::<f64>)
                    .unwrap_or_else(|| panic!("case {name:?}: missing numeric port"));
                mcp_matches
                    && actual.method() == string(target, "method")
                    && actual.scheme() == string(target, "scheme")
                    && actual.host() == string(target, "host")
                    && f64::from(actual.port()) == *port
                    && actual.path() == string(target, "path")
                    // Optional, so older cases need not carry it.
                    && target
                        .get("authority")
                        .and_then(JsonValue::get::<String>)
                        .is_none_or(|authority| actual.authority() == *authority)
            }
            (None, Some(denial), Err(actual)) => {
                denial.get::<String>().map(String::as_str) == Some(denial_name(*actual))
            }
            (Some(_), Some(_), _) | (None, None, _) => {
                panic!("case {name:?}: \"expected\" needs exactly one of \"target\" or \"denial\"")
            }
            _ => false,
        };
        if !matches {
            failures.push(format!(
                "case {name:?}: expected {expected:?}, got {actual:?}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failing cases:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Checks `request` against `token` and names the outcome the way the vectors do.
fn outcome(token: &[u8], request: &RawRequest) -> &'static str {
    match check(token, &request.facts()) {
        Ok(_) => "allowed",
        Err(denial) => denial_name(denial),
    }
}

#[test]
fn flow_vectors_pass() {
    let root = load(FLOW_JSON, "flow.json");
    let cases = array(&root, "cases");
    assert!(!cases.is_empty());

    let mut failures = Vec::new();
    for case in cases {
        let case = object(case);
        let name = string(case, "name");

        // Observe -> learn -> seal: the only way this test gets a valid token.
        let observed: Vec<gate::Target> = array(case, "observed")
            .iter()
            .filter_map(|request| observe(&RawRequest::from_json(request).facts()).ok())
            .collect();
        let token = seal::seal(&seal::learn(&observed)).expect("a small caveat set seals");

        for (i, check_case) in array(case, "checks").iter().enumerate() {
            let check_case = object(check_case);
            let request = RawRequest::from_json(&check_case["request"]);
            let expected = string(check_case, "expected");
            let actual = outcome(token.as_bytes(), &request);
            if actual != expected {
                failures.push(format!(
                    "case {name:?} check {i}: expected {expected}, got {actual}"
                ));
            }
        }
    }

    let request = RawRequest {
        method: b"GET".to_vec(),
        scheme: b"https".to_vec(),
        authority: b"api.example.com".to_vec(),
        path: b"/orders".to_vec(),
        mcp: None,
    };
    for bad in array(&root, "bad_tokens") {
        let bad = object(bad);
        let name = string(bad, "name");
        let expected = string(bad, "expected");
        assert_ne!(
            expected, "allowed",
            "bad token {name:?}: a hand-written token may never be expected to allow"
        );
        let actual = outcome(string(bad, "token").as_bytes(), &request);
        if actual != expected {
            failures.push(format!(
                "bad token {name:?}: expected {expected}, got {actual}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} failing cases:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
