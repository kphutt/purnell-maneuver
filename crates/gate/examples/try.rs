//! A small command-line walkthrough of purnell-maneuver's observe -> learn -> seal -> check
//! flow, for trying it by hand.
//!
//! ```sh
//! cargo run --example try -- observe GET https example.com /orders
//! cargo run --example try -- seal GET https example.com /orders
//! cargo run --example try -- check <token> GET https example.com /orders
//! ```
//!
//! A request is four raw fields, one per [`gate::RequestFacts`] field, given as four
//! separate arguments -- never a URL string this CLI would have to split or tidy:
//!
//!     METHOD SCHEME AUTHORITY PATH
//!
//! for example `GET https example.com /orders?x=1`. Every byte is passed to
//! `gate::observe` exactly as typed: nothing here lowercases, decodes or otherwise
//! tidies it. That is the canonicalizer's job, not this CLI's.
//!
//! This CLI seals only what the canonicalizer accepted, and has no way to type a caveat and
//! have it sealed. The request itself is whatever you pass, and `check` takes any token
//! string, including one typed by hand.
//!
//! Pass `--explain` (anywhere in the arguments) to narrate each step instead of just
//! the final answer. The core crates print nothing themselves -- they only ever return
//! structured results -- so every word of the narration below is built by this CLI from
//! those results.

use gate::{check, observe, Denial, RequestFacts, Target};

const USAGE: &str = "\
try -- a small observe -> learn -> seal -> check walkthrough

USAGE:
    cargo run --example try -- observe [--explain] METHOD SCHEME AUTHORITY PATH
    cargo run --example try -- seal [--explain] (METHOD SCHEME AUTHORITY PATH)...
    cargo run --example try -- check [--explain] TOKEN METHOD SCHEME AUTHORITY PATH

A request is four raw fields, one per RequestFacts field -- never a URL string:

    METHOD SCHEME AUTHORITY PATH

for example: GET https example.com /orders?x=1

    observe   prints the request's canonical target, or the denial that rejects it.
    seal      observes each given request, learns a caveat set, seals it into a
              token, and prints the token plus the caveats that were learned (for
              review before you trust it).
    check     prints \"Allowed\" if TOKEN allows the request, or the denial that
              rejects it.

--explain prints each step instead of just the final answer: the raw request facts
as given, the canonical target (or which rule denied it and why), and for `seal` the
full learned caveat set before it is sealed. For `check`, it says whether the request
canonicalized, whether the token decoded, and the final verdict -- but it never prints
a checked token's caveats, because the library never lets them leave it; use `seal --explain` to review a
caveat set before you trust it, not `check --explain` on someone else's token.

Exit code 0 means Allowed or success; any other code means a denial or a usage error.\
";

/// Exit code for a denial (the request or token was well formed but refused).
const EXIT_DENIED: i32 = 1;
/// Exit code for a usage error (bad arguments), distinct from a denial.
const EXIT_USAGE: i32 = 2;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (output, code) = run(&args);
    if code == EXIT_USAGE {
        eprintln!("{output}");
    } else {
        println!("{output}");
    }
    std::process::exit(code);
}

/// The CLI's core logic: arguments in, output text and an exit code out. Kept separate
/// from `main` so it can be unit tested without touching the process's real args, exit
/// code or stdio.
fn run(args: &[String]) -> (String, i32) {
    let explain = args.iter().any(|arg| arg == "--explain");
    let filtered: Vec<String> = args
        .iter()
        .filter(|arg| arg.as_str() != "--explain")
        .cloned()
        .collect();
    let args = &filtered[..];

    match args.first().map(String::as_str) {
        Some("observe") => run_observe(args.get(1..).unwrap_or(&[]), explain),
        Some("seal") => run_seal(args.get(1..).unwrap_or(&[]), explain),
        Some("check") => run_check(args.get(1..).unwrap_or(&[]), explain),
        Some("-h") | Some("--help") | Some("help") => (USAGE.to_string(), 0),
        Some(other) => (
            format!("unknown subcommand '{other}'\n\n{USAGE}"),
            EXIT_USAGE,
        ),
        None => (USAGE.to_string(), EXIT_USAGE),
    }
}

/// Parses exactly one request's four raw fields. Never indexes or slices: a slice
/// pattern either matches four elements or it does not.
fn parse_request(fields: &[String]) -> Result<RequestFacts<'_>, String> {
    match fields {
        [method, scheme, authority, path] => Ok(RequestFacts {
            method: method.as_bytes(),
            scheme: scheme.as_bytes(),
            authority: authority.as_bytes(),
            path: path.as_bytes(),
        }),
        _ => Err(format!(
            "a request needs exactly 4 fields (METHOD SCHEME AUTHORITY PATH), got {}",
            fields.len()
        )),
    }
}

/// The raw facts of one request, formatted for `--explain`, exactly as given -- no
/// lowercasing, decoding or tidying; only lossy UTF-8 display of the same bytes
/// `gate::observe` is about to read.
fn describe_request(request: &RequestFacts<'_>) -> String {
    format!(
        "request:\n  method:    {}\n  scheme:    {}\n  authority: {}\n  path:      {}",
        String::from_utf8_lossy(request.method),
        String::from_utf8_lossy(request.scheme),
        String::from_utf8_lossy(request.authority),
        String::from_utf8_lossy(request.path),
    )
}

/// A canonical target, formatted the same way a token's `http` caveat body is written,
/// so it can be copied straight into another `try` command.
fn target_line(target: &Target) -> String {
    match target.as_http() {
        Some(http) => format!(
            "{} {} {} {}",
            http.method(),
            http.scheme(),
            http.authority(),
            http.path()
        ),
        None => "(a target kind this example does not know how to print)".to_string(),
    }
}

/// A short, human reason for a [`Denial`], for `--explain`. Mirrors the doc comments on
/// `Denial` and the canonicalizer's rules; kept here because the core crates
/// return only the named case, never a text message, so any prose has to live in the CLI
/// that prints it.
fn denial_reason(denial: Denial) -> String {
    match denial {
        Denial::EmptyToken => "the token was zero bytes long".to_string(),
        Denial::TokenTooLong => "the token was longer than the maximum token length".to_string(),
        Denial::UnknownVersion => {
            "the token's version is not one this build knows (only v1 today)".to_string()
        }
        Denial::MalformedToken => {
            "the token said v1 but its body is not exactly what seal would have written".to_string()
        }
        Denial::UnknownCaveatKind => {
            "the token holds a caveat kind this build does not know (only http today)".to_string()
        }
        Denial::RequestTooLong => "a request field was longer than its limit".to_string(),
        Denial::MalformedMethod => "the method is empty or is not a valid HTTP token".to_string(),
        Denial::UnsupportedScheme => "the scheme is not http or https".to_string(),
        Denial::MalformedHost => {
            "the host is empty, has an empty label or a trailing dot, an unsupported \
             byte, or a non-canonical numeric or IPv6 form"
                .to_string()
        }
        Denial::MalformedPort => {
            "the port is empty, zero, has a leading zero, is not all digits, is above \
             65535, or spells out the scheme's default"
                .to_string()
        }
        Denial::MalformedPath => {
            "the path does not start with \"/\", or has a \".\", \"..\" or empty \
             segment, or a byte the canonicalizer will not pass through unchanged"
                .to_string()
        }
        Denial::NotListed => {
            "the request and the token are both well formed, but the token does not \
             list this exact target"
                .to_string()
        }
        // `Denial` is `#[non_exhaustive]`: a later version of `token` may add a case
        // this build has never heard of. It still has a stable name -- `Denial::name`
        // has no catch-all of its own (see `crates/token/src/denial.rs`) -- so the
        // fallback narrates that name instead of going fully generic.
        _ => format!(
            "denied for a reason newer than this example knows about ({})",
            denial.name()
        ),
    }
}

/// Whether a [`Denial`] means the *token* failed to decode, as opposed to the request
/// itself, or the request simply not being listed. Used only to narrate `check
/// --explain` in the same order `gate::check` actually works: it canonicalizes the
/// request first, and only then reads the token.
fn is_token_format_denial(denial: Denial) -> bool {
    matches!(
        denial,
        Denial::EmptyToken
            | Denial::TokenTooLong
            | Denial::UnknownVersion
            | Denial::MalformedToken
            | Denial::UnknownCaveatKind
    )
}

/// A short, human reason for a [`seal::SealError`], for `--explain`. See
/// [`denial_reason`] for why this prose lives here rather than in the core.
fn seal_error_reason(error: seal::SealError) -> &'static str {
    match error {
        seal::SealError::TokenTooLong => {
            "the sealed token would be longer than the maximum token length"
        }
        _ => "sealing failed for a reason newer than this example knows about",
    }
}

fn run_observe(args: &[String], explain: bool) -> (String, i32) {
    let request = match parse_request(args) {
        Ok(request) => request,
        Err(message) => return (format!("{message}\n\n{USAGE}"), EXIT_USAGE),
    };
    let result = observe(&request);
    if !explain {
        return match result {
            Ok(target) => (target_line(&target), 0),
            Err(denial) => (format!("Denied: {denial:?}"), EXIT_DENIED),
        };
    }

    let mut out = describe_request(&request);
    out.push('\n');
    match result {
        Ok(target) => {
            out.push_str("-> canonicalized to: ");
            out.push_str(&target_line(&target));
            (out, 0)
        }
        Err(denial) => {
            out.push_str("-> denied: ");
            out.push_str(&format!("{denial:?}"));
            out.push_str(" \u{2014} ");
            out.push_str(&denial_reason(denial));
            (out, EXIT_DENIED)
        }
    }
}

fn run_check(args: &[String], explain: bool) -> (String, i32) {
    let (token, request_fields) = match args.split_first() {
        Some((token, rest)) => (token, rest),
        None => {
            return (
                format!("check needs a TOKEN and a request\n\n{USAGE}"),
                EXIT_USAGE,
            )
        }
    };
    let request = match parse_request(request_fields) {
        Ok(request) => request,
        Err(message) => return (format!("{message}\n\n{USAGE}"), EXIT_USAGE),
    };

    if !explain {
        return match check(token.as_bytes(), &request) {
            Ok(_allowed) => ("Allowed".to_string(), 0),
            Err(denial) => (format!("Denied: {denial:?}"), EXIT_DENIED),
        };
    }

    // Explain mode narrates the same two steps `gate::check` takes internally:
    // canonicalize the request, then decode the token and consult it. It calls
    // `observe` (the same canonicalizer) separately only to describe that first step;
    // `check` itself still makes the real decision. It never reaches into the token's
    // decoded caveats -- there is no public way to, on purpose.
    let mut out = describe_request(&request);
    out.push('\n');
    match observe(&request) {
        Err(denial) => {
            out.push_str("-> the request itself is denied, so the token is never read: ");
            out.push_str(&format!("{denial:?}"));
            out.push_str(" \u{2014} ");
            out.push_str(&denial_reason(denial));
            (out, EXIT_DENIED)
        }
        Ok(target) => {
            out.push_str("-> canonical target: ");
            out.push_str(&target_line(&target));
            out.push('\n');
            match check(token.as_bytes(), &request) {
                Ok(_allowed) => {
                    out.push_str("-> the token decoded, and lists this exact target -> Allowed");
                    (out, 0)
                }
                Err(denial) if is_token_format_denial(denial) => {
                    out.push_str("-> the token did not decode: ");
                    out.push_str(&format!("{denial:?}"));
                    out.push_str(" \u{2014} ");
                    out.push_str(&denial_reason(denial));
                    (out, EXIT_DENIED)
                }
                Err(denial) => {
                    out.push_str(
                        "-> the token decoded, but its caveats are never shown outside \
                         the library; it \
                         does not list this exact target -> Denied: ",
                    );
                    out.push_str(&format!("{denial:?}"));
                    (out, EXIT_DENIED)
                }
            }
        }
    }
}

fn run_seal(args: &[String], explain: bool) -> (String, i32) {
    if args.is_empty() || !args.len().is_multiple_of(4) {
        return (
            format!(
                "seal needs one or more requests, each 4 fields (METHOD SCHEME \
                 AUTHORITY PATH); got {} field(s)\n\n{USAGE}",
                args.len()
            ),
            EXIT_USAGE,
        );
    }

    let mut narration = String::new();
    let mut targets = Vec::new();
    for (index, fields) in args.chunks(4).enumerate() {
        let request = match parse_request(fields) {
            Ok(request) => request,
            Err(message) => {
                return (
                    format!("request {}: {message}", index.saturating_add(1)),
                    EXIT_USAGE,
                )
            }
        };
        if explain {
            narration.push_str(&format!("request {}:\n", index.saturating_add(1)));
            narration.push_str(&describe_request(&request));
            narration.push('\n');
        }
        match observe(&request) {
            Ok(target) => {
                if explain {
                    narration.push_str("  -> observed: ");
                    narration.push_str(&target_line(&target));
                    narration.push_str("\n\n");
                }
                targets.push(target);
            }
            Err(denial) => {
                if explain {
                    narration.push_str("  -> denied, so learning stops here: ");
                    narration.push_str(&format!("{denial:?}"));
                    narration.push_str(" \u{2014} ");
                    narration.push_str(&denial_reason(denial));
                    return (narration, EXIT_DENIED);
                }
                return (
                    format!("request {} denied: {denial:?}", index.saturating_add(1)),
                    EXIT_DENIED,
                );
            }
        }
    }

    let caveat_set = seal::learn(&targets);
    if explain {
        narration.push_str(&format!(
            "learned {} caveat(s):\n",
            caveat_set.caveats().count()
        ));
        for caveat in caveat_set.caveats() {
            narration.push_str("  ");
            narration.push_str(&target_line(caveat.target()));
            narration.push('\n');
        }
        narration.push('\n');
    }

    match seal::seal(&caveat_set) {
        Ok(token) => {
            if explain {
                narration.push_str(&format!("sealed token: {token}"));
                (narration, 0)
            } else {
                let mut output = format!("token: {token}\n");
                output.push_str("learned caveats:\n");
                let mut any = false;
                for caveat in caveat_set.caveats() {
                    any = true;
                    output.push_str("  ");
                    output.push_str(&target_line(caveat.target()));
                    output.push('\n');
                }
                if !any {
                    output.push_str("  (none)\n");
                }
                (output.trim_end().to_string(), 0)
            }
        }
        Err(error) => {
            if explain {
                narration.push_str("sealing denied: ");
                narration.push_str(&format!("{error:?}"));
                narration.push_str(" \u{2014} ");
                narration.push_str(seal_error_reason(error));
                (narration, EXIT_DENIED)
            } else {
                (format!("could not seal: {error:?}"), EXIT_DENIED)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strings: &[&str]) -> Vec<String> {
        strings.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn observe_prints_the_canonical_target() {
        let (output, code) = run(&args(&[
            "observe",
            "GET",
            "https",
            "example.com",
            "/orders?x=1",
        ]));
        assert_eq!(code, 0);
        assert_eq!(output, "GET https example.com /orders");
    }

    #[test]
    fn observe_names_the_denial_for_a_tricky_path() {
        let (output, code) = run(&args(&[
            "observe",
            "GET",
            "https",
            "example.com",
            "/a/../b",
        ]));
        assert_eq!(code, EXIT_DENIED);
        assert_eq!(output, "Denied: MalformedPath");
    }

    #[test]
    fn observe_denies_an_explicit_default_port() {
        let (output, code) = run(&args(&["observe", "GET", "https", "example.com:443", "/"]));
        assert_eq!(code, EXIT_DENIED);
        assert_eq!(output, "Denied: MalformedPort");
    }

    #[test]
    fn observe_rejects_the_wrong_number_of_fields() {
        let (_output, code) = run(&args(&["observe", "GET", "https", "example.com"]));
        assert_eq!(code, EXIT_USAGE);
    }

    #[test]
    fn no_subcommand_prints_usage_and_exits_nonzero() {
        let (output, code) = run(&args(&[]));
        assert_eq!(code, EXIT_USAGE);
        assert!(output.contains("USAGE"));
    }

    #[test]
    fn unknown_subcommand_is_a_usage_error() {
        let (_output, code) = run(&args(&["nope"]));
        assert_eq!(code, EXIT_USAGE);
    }

    #[test]
    fn help_flag_prints_usage_and_succeeds() {
        let (output, code) = run(&args(&["--help"]));
        assert_eq!(code, 0);
        assert!(output.contains("USAGE"));
    }

    #[test]
    fn seal_then_check_allows_the_learned_request_and_denies_a_different_one() {
        let (seal_output, seal_code) =
            run(&args(&["seal", "GET", "https", "example.com", "/orders"]));
        assert_eq!(seal_code, 0);
        let token = seal_output
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("token: "))
            .expect("seal always prints a token line first");
        assert!(seal_output.contains("GET https example.com /orders"));

        let (allowed_output, allowed_code) = run(&args(&[
            "check",
            token,
            "GET",
            "https",
            "example.com",
            "/orders?page=2",
        ]));
        assert_eq!(allowed_code, 0);
        assert_eq!(allowed_output, "Allowed");

        let (denied_output, denied_code) = run(&args(&[
            "check",
            token,
            "GET",
            "https",
            "example.com",
            "/other",
        ]));
        assert_eq!(denied_code, EXIT_DENIED);
        assert_eq!(denied_output, "Denied: NotListed");
    }

    #[test]
    fn sealing_nothing_is_a_usage_error() {
        let (_output, code) = run(&args(&["seal"]));
        assert_eq!(code, EXIT_USAGE);
    }

    #[test]
    fn check_denies_a_bad_token() {
        let (output, code) = run(&args(&[
            "check",
            "not-a-real-token",
            "GET",
            "https",
            "example.com",
            "/",
        ]));
        assert_eq!(code, EXIT_DENIED);
        assert_eq!(output, "Denied: UnknownVersion");
    }

    #[test]
    fn observe_explain_narrates_the_request_and_the_canonical_target() {
        let (output, code) = run(&args(&[
            "observe",
            "--explain",
            "GET",
            "https",
            "example.com",
            "/orders?x=1",
        ]));
        assert_eq!(code, 0);
        assert!(output.contains("method:    GET"));
        assert!(output.contains("scheme:    https"));
        assert!(output.contains("authority: example.com"));
        assert!(output.contains("path:      /orders?x=1"));
        assert!(output.ends_with("GET https example.com /orders"));
    }

    #[test]
    fn observe_explain_names_the_rule_and_the_reason_for_a_tricky_path() {
        let (output, code) = run(&args(&[
            "observe",
            "--explain",
            "GET",
            "https",
            "example.com",
            "/a/../b",
        ]));
        assert_eq!(code, EXIT_DENIED);
        assert!(output.contains("MalformedPath"));
        assert!(output.contains("does not start with"));
    }

    #[test]
    fn seal_explain_lists_the_learned_caveats_and_the_token() {
        let (output, code) = run(&args(&[
            "seal",
            "--explain",
            "GET",
            "https",
            "example.com",
            "/a",
            "GET",
            "https",
            "example.com",
            "/b",
        ]));
        assert_eq!(code, 0);
        assert!(output.contains("learned 2 caveat(s)"));
        assert!(output.contains("GET https example.com /a"));
        assert!(output.contains("GET https example.com /b"));
        assert!(output.contains("sealed token: v1;"));
    }

    #[test]
    fn seal_explain_stops_at_the_first_denied_request() {
        let (output, code) = run(&args(&[
            "seal",
            "--explain",
            "GET",
            "https",
            "example.com",
            "/a/../b",
        ]));
        assert_eq!(code, EXIT_DENIED);
        assert!(output.contains("denied, so learning stops here"));
        assert!(output.contains("MalformedPath"));
    }

    #[test]
    fn check_explain_reports_each_step_for_an_allowed_request() {
        let (seal_output, _) = run(&args(&["seal", "GET", "https", "example.com", "/orders"]));
        let token = seal_output
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("token: "))
            .expect("seal always prints a token line first");

        let (output, code) = run(&args(&[
            "check",
            "--explain",
            token,
            "GET",
            "https",
            "example.com",
            "/orders?page=2",
        ]));
        assert_eq!(code, 0);
        assert!(output.contains("canonical target: GET https example.com /orders"));
        assert!(output.contains("the token decoded"));
        assert!(output.ends_with("Allowed"));
    }

    #[test]
    fn check_explain_reports_not_listed_without_exposing_the_tokens_caveats() {
        let (seal_output, _) = run(&args(&["seal", "GET", "https", "example.com", "/orders"]));
        let token = seal_output
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("token: "))
            .expect("seal always prints a token line first");

        let (output, code) = run(&args(&[
            "check",
            "--explain",
            token,
            "GET",
            "https",
            "example.com",
            "/other",
        ]));
        assert_eq!(code, EXIT_DENIED);
        assert!(output.contains("NotListed"));
        assert!(output.contains("never shown outside"));
        // The learned caveat's own path ("/orders") must never appear: only the
        // checked request's target ("/other") may.
        assert!(!output.contains("/orders"));
    }

    #[test]
    fn check_explain_stops_at_the_request_when_the_request_itself_is_denied() {
        let (output, code) = run(&args(&[
            "check",
            "--explain",
            "v1",
            "GET",
            "https",
            "example.com",
            "/a/../b",
        ]));
        assert_eq!(code, EXIT_DENIED);
        assert!(output.contains("the token is never read"));
        assert!(output.contains("MalformedPath"));
    }

    #[test]
    fn check_explain_reports_when_the_token_itself_does_not_decode() {
        let (output, code) = run(&args(&[
            "check",
            "--explain",
            "not-a-real-token",
            "GET",
            "https",
            "example.com",
            "/",
        ]));
        assert_eq!(code, EXIT_DENIED);
        assert!(output.contains("canonical target: GET https example.com /"));
        assert!(output.contains("the token did not decode"));
        assert!(output.contains("UnknownVersion"));
    }
}
