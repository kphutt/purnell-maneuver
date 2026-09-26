//! Keeps `docs/what-it-does.md` accurate.
//!
//! That page claims to list everything this library does, and a page like that goes
//! stale without anyone noticing. Four of its claims can be derived from the source
//! instead of trusted, so they are:
//!
//! 1. the refusal names it lists are exactly the names the code can produce;
//! 2. the kinds of destination it lists are exactly the kinds the token format knows;
//! 3. the public surface it lists is exactly the public functions the crates define;
//! 4. every function the page names by name exists.
//!
//! Check 4 is deliberately one-directional. A function the page names that the code no
//! longer has is a false claim on a page people quote, so this fails. A function the
//! page does not mention is not a false claim, so this does not fail — adding a test or
//! a proof must not break somebody else's change.
//!
//! Everything else on that page is prose. In particular, whether a limit belongs on the
//! "never" list or the "not yet" list is a judgement, and no test can make it.

// A test binary: panicking is how a test fails. clippy.toml already exempts `#[test]`
// functions from the panic lints; this extends that to the helpers they call.
#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The workspace root: this crate's directory, two levels up.
fn workspace_root() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|why| panic!("cannot read {}: {why}", path.display()))
}

fn page() -> String {
    read("docs/what-it-does.md")
}

/// The lines of the first fenced block after `heading`, with blanks dropped.
fn block_after(page: &str, heading: &str) -> Vec<String> {
    let mut lines = page.lines().skip_while(|line| line.trim() != heading);
    assert!(
        lines.next().is_some(),
        "docs/what-it-does.md has no {heading}"
    );
    let mut lines = lines.skip_while(|line| !line.starts_with("```"));
    assert!(
        lines.next().is_some(),
        "no fenced block follows {heading} in docs/what-it-does.md"
    );
    lines
        .take_while(|line| !line.starts_with("```"))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Every `.rs` file under `crates/*/src`, plus the integration tests, so a function the
/// page names is looked for everywhere it could live.
fn source_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    let crates = workspace_root().join("crates");
    for entry in fs::read_dir(&crates).expect("crates/ is readable") {
        let krate = entry.expect("a readable entry").path();
        for directory in ["src", "tests", "examples"] {
            collect_rs(&krate.join(directory), &mut files);
        }
    }
    assert!(!files.is_empty(), "found no Rust sources under crates/");
    files
}

fn collect_rs(directory: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("a readable entry").path();
        if path.is_dir() {
            collect_rs(&path, into);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            into.push(path);
        }
    }
}

/// The name in `pub fn <name>(`, for a line that starts one at column zero. Indented
/// `pub fn`s are methods inside an `impl`, which this check does not cover: the page
/// lists free functions.
fn free_function(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("pub fn ")?;
    let end = rest.find(['(', '<'])?;
    rest.get(..end)
}

#[test]
fn the_page_lists_exactly_the_refusals_the_code_can_name() {
    // `Denial::name` is the one place a variant gets its outside-facing name, and its
    // match has no catch-all arm, so this reads the whole set.
    let listed: BTreeSet<String> = read("crates/token/src/denial.rs")
        .lines()
        .filter(|line| line.contains("Denial::") && line.contains("=> \""))
        .filter_map(|line| {
            let after = line.split("=> \"").nth(1)?;
            Some(after.split('"').next()?.to_owned())
        })
        .collect();
    assert_eq!(listed.len(), 15, "found {listed:?}");

    let documented: BTreeSet<String> = block_after(&page(), "### Every refusal it can name")
        .into_iter()
        .collect();
    assert_eq!(
        documented, listed,
        "docs/what-it-does.md and Denial::name disagree about the refusal names"
    );
}

#[test]
fn the_page_lists_exactly_the_kinds_of_destination_the_token_format_knows() {
    let known: BTreeSet<String> = read("crates/token/src/format.rs")
        .lines()
        .filter(|line| line.starts_with("const ") && line.contains("_KIND: &[u8] = b\""))
        .filter_map(|line| {
            let after = line.split("b\"").nth(1)?;
            Some(after.split('"').next()?.to_owned())
        })
        .collect();
    assert!(known.contains("http"), "found {known:?}");

    let documented: BTreeSet<String> =
        block_after(&page(), "### Every kind of destination it can express")
            .into_iter()
            .collect();
    assert_eq!(
        documented, known,
        "docs/what-it-does.md and format.rs disagree about the caveat kinds"
    );
}

#[test]
fn the_page_lists_exactly_the_public_functions_the_crates_define() {
    let mut defined: BTreeSet<String> = BTreeSet::new();
    for path in source_files() {
        // Only `src/` holds public surface, and the proof harnesses are behind
        // `#[cfg(kani)]`, so nothing in them is reachable from an ordinary build.
        let in_src = path.components().any(|part| part.as_os_str() == "src");
        let is_kani = path
            .file_name()
            .is_some_and(|name| name == "canonical_kani.rs");
        if !in_src || is_kani {
            continue;
        }
        let krate = path
            .ancestors()
            .nth(2)
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .expect("every source file sits under crates/<name>/src")
            .to_owned();
        for line in read_relative(&path).lines() {
            if let Some(name) = free_function(line) {
                defined.insert(format!("{krate}::{name}"));
            }
        }
    }

    let documented: BTreeSet<String> = block_after(&page(), "## The whole public surface")
        .into_iter()
        .collect();
    assert_eq!(
        documented, defined,
        "docs/what-it-does.md and the crates disagree about the public functions"
    );
}

#[test]
fn every_function_the_page_names_still_exists() {
    let sources: Vec<String> = source_files()
        .iter()
        .map(|path| read_relative(path))
        .collect();
    let page = page();
    let mut missing: Vec<String> = Vec::new();

    for (index, piece) in page.split('`').enumerate() {
        // Odd pieces are the ones between backticks.
        if index % 2 == 0 || !looks_like_a_function_name(piece) {
            continue;
        }
        // The `(` is what stops a truncated name matching: `fn foo` is a prefix of
        // `fn foobar`, and a page naming a function that no longer exists under that
        // exact spelling is exactly what this test is for.
        let needle = format!("fn {piece}(");
        if !sources.iter().any(|source| source.contains(&needle)) {
            missing.push(piece.to_owned());
        }
    }

    missing.sort_unstable();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "docs/what-it-does.md names functions that no longer exist: {missing:?}"
    );
}

/// A snake_case Rust identifier long enough that it cannot be an ordinary word in code
/// font. Short names and anything carrying `:`, `/`, `.` or a space are left alone.
fn looks_like_a_function_name(piece: &str) -> bool {
    piece.len() >= 12
        && piece.contains('_')
        && piece.starts_with(|first: char| first.is_ascii_lowercase())
        && piece
            .chars()
            .all(|letter| letter.is_ascii_lowercase() || letter.is_ascii_digit() || letter == '_')
}

fn read_relative(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|why| panic!("cannot read {}: {why}", path.display()))
}
