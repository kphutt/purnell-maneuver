//! The WHATWG URL Standard as a test oracle, through the web-platform-tests data.
//!
//! `testdata/wpt/urltestdata.json` is vendored, unchanged, from web-platform-tests (see
//! `testdata/wpt/README.md` for the commit and the license). WHATWG is not the
//! canonicalizer's standard: it merges spellings that real servers keep apart, so the
//! canonicalizer is stricter. But it is a careful, widely tested description of what a
//! browser sends, which makes it a good referee for three claims. For every absolute
//! `http` or `https` input in the file:
//!
//! 1. If WHATWG says the input is not a URL, the canonicalizer denies it.
//! 2. If the canonicalizer accepts it, its host, port (with the scheme's default when
//!    none is given) and path are exactly WHATWG's `hostname`, `port` and `pathname`.
//! 3. No two accepted inputs share a target unless WHATWG also gives them the same
//!    protocol, hostname, port and pathname. The query is not compared: dropping it is
//!    the one merge the canonicalizer makes on purpose.
//!
//! The input is split into raw request facts the way a server would receive them:
//! scheme before `://`, authority up to the first `/`, `?` or `#`, and the rest as the
//! path. Nothing is decoded or cleaned up first.
//!
//! WHATWG lowercases the scheme and host; the canonicalizer denies them instead, since a
//! router may keep the cases apart. An input WHATWG parses that is denied for its
//! scheme or host, and that lowercasing its scheme and authority gets past that denial
//! (to a target, or to a denial of a later field), is recorded as an intentional case
//! denial and listed, apart from the other false denials. In today's data all such
//! inputs have no path at all (an empty raw path, which the canonicalizer always
//! denies), so lowercasing never actually reaches a target for them; the list shows
//! only that the *scheme or host* denial fired before the path did, not that case was
//! the only thing standing between the input and acceptance.

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

use gate::{observe, Denial, RequestFacts, Target};
use tinyjson::JsonValue;

const WPT_JSON: &str = include_str!("../../../testdata/wpt/urltestdata.json");

/// Splits `scheme://authority/path?query#fragment` into raw request facts, byte for
/// byte. `None` for anything that is not an absolute URL with `://`.
fn split(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some((scheme, &rest[..end], &rest[end..]))
}

/// (scheme, host, port, path): what a target and WHATWG are compared on.
type View = (String, String, u16, String);

/// A target's view, for comparing with WHATWG's.
fn view(target: &Target) -> View {
    let http = target
        .as_http()
        .expect("every target is an HTTP target today");
    (
        http.scheme().to_string(),
        http.host().to_string(),
        http.port(),
        http.path().to_string(),
    )
}

/// The request a server would see for these raw pieces.
fn observe_raw(scheme: &str, authority: &str, path: &str) -> Result<Target, Denial> {
    observe(&RequestFacts {
        method: b"GET",
        scheme: scheme.as_bytes(),
        authority: authority.as_bytes(),
        path: path.as_bytes(),
    })
}

fn field(case: &HashMap<String, JsonValue>, key: &str) -> String {
    match case.get(key) {
        Some(JsonValue::String(value)) => value.clone(),
        _ => String::new(),
    }
}

#[test]
fn whatwg_url_test_data_agrees_where_the_canonicalizer_accepts() {
    let json: JsonValue = WPT_JSON.parse().expect("urltestdata.json is valid JSON");
    let JsonValue::Array(items) = json else {
        panic!("urltestdata.json must be a JSON array")
    };

    let (mut applicable, mut accepted, mut denied_where_wpt_fails, mut denied_where_wpt_parses) =
        (0, 0, 0, 0);
    let mut case_denials = Vec::new();
    let mut accepted_but_wpt_fails = Vec::new();
    let mut differs = Vec::new();
    // Target -> every (input, WHATWG's protocol/hostname/port/pathname) that gave it.
    let mut by_target: HashMap<View, Vec<(String, String)>> = HashMap::new();

    for item in &items {
        let JsonValue::Object(case) = item else {
            continue; // comment strings
        };
        let Some(JsonValue::String(input)) = case.get("input") else {
            continue;
        };
        let Some((scheme, authority, path)) = split(input) else {
            continue;
        };
        let scheme_lower = scheme.to_ascii_lowercase();
        if scheme_lower != "http" && scheme_lower != "https" {
            continue;
        }
        applicable += 1;
        let wpt_fails = matches!(case.get("failure"), Some(JsonValue::Boolean(true)));
        let result = observe_raw(scheme, authority, path);
        match (result, wpt_fails) {
            (Err(_), true) => denied_where_wpt_fails += 1,
            (Err(denial), false) => {
                denied_where_wpt_parses += 1;
                let lowercased = observe_raw(
                    &scheme.to_ascii_lowercase(),
                    &authority.to_ascii_lowercase(),
                    path,
                );
                let for_case = matches!(denial, Denial::UnsupportedScheme | Denial::MalformedHost)
                    && lowercased != Err(denial);
                if for_case {
                    case_denials.push(format!("{input:?} (lowercased: {lowercased:?})"));
                }
            }
            (Ok(target), true) => accepted_but_wpt_fails.push(format!("{input:?} -> {target:?}")),
            (Ok(target), false) => {
                accepted += 1;
                let default_port = if scheme_lower == "https" { 443 } else { 80 };
                let wpt_port = field(case, "port").parse().unwrap_or(default_port);
                let ours = view(&target);
                let whatwg = (
                    field(case, "protocol").trim_end_matches(':').to_string(),
                    field(case, "hostname"),
                    wpt_port,
                    field(case, "pathname"),
                );
                if ours != whatwg {
                    differs.push(format!("{input:?}: ours {ours:?}, WHATWG {whatwg:?}"));
                }
                by_target
                    .entry(ours)
                    .or_default()
                    .push((input.clone(), format!("{whatwg:?}")));
            }
        }
    }

    let merges: Vec<String> = by_target
        .values()
        .filter(|inputs| inputs.iter().any(|(_, whatwg)| *whatwg != inputs[0].1))
        .map(|inputs| format!("{inputs:?}"))
        .collect();

    println!(
        "WPT oracle: applicable={applicable} accepted={accepted} \
         denied_where_wpt_fails={denied_where_wpt_fails} \
         denied_where_wpt_parses={denied_where_wpt_parses} \
         (of which intentional_case_denials={}) \
         accepted_but_wpt_fails={} accepted_but_differs={} merges_wpt_keeps_apart={}",
        case_denials.len(),
        accepted_but_wpt_fails.len(),
        differs.len(),
        merges.len()
    );
    for input in &case_denials {
        println!("  intentional case denial (WHATWG lowercases, we deny): {input}");
    }
    assert!(applicable > 0, "no http(s) cases found; is the file right?");
    // Claims 2 and 3 range over the accepted inputs; if a future tightening denied
    // them all, both would pass with no signal. This floor catches that.
    assert!(
        accepted >= 22,
        "the WPT oracle accepted {accepted} inputs; claims 2 and 3 are now vacuous"
    );
    // Every broken claim is reported at once, so one run names every failing input.
    let mut problems = String::new();
    for (claim, list) in [
        ("accepted, but WHATWG rejects", &accepted_but_wpt_fails),
        ("accepted, but the target differs from WHATWG", &differs),
        ("one target for inputs WHATWG keeps apart", &merges),
    ] {
        for line in list {
            problems.push_str(&format!("{claim}: {line}\n"));
        }
    }
    assert!(problems.is_empty(), "{problems}");
}
