# purnell-maneuver

Can you limit an AI agent to the endpoints it needs for a task? This Rust library lets you test an allowlist built from a trusted run.

An agent's credential often opens far more than its task needs. You pass the library the requests from a run you
trust. It writes their HTTP and Model Context Protocol (MCP) destinations into a token. For each later request, it
answers allowed or denied, and your server or proxy acts on that answer.

> Use this for research only. Tokens are not signed yet, so anyone who can edit a token can add a destination to it.
> Until signing exists, this does not stop a client that controls its own token. See [Known limits](#known-limits).

## Try it

With Rust installed, run these from the root of a clone. In Git Bash on Windows, first run
`export MSYS_NO_PATHCONV=1` so the shell leaves the paths alone.

```console
$ cargo run --quiet --example try -- seal GET https example.com /orders
token: v1;http GET https example.com /orders
learned caveats:
  GET https example.com /orders

$ cargo run --quiet --example try -- check 'v1;http GET https example.com /orders' GET https example.com /orders
Allowed

$ cargo run --quiet --example try -- check 'v1;http GET https example.com /orders' GET https example.com /admin
Denied: NotListed
```

The token lists `/orders`, so that request is allowed. It does not list `/admin`, so that one is denied.
Run it with `--help` to see the other commands and options. The example does not send MCP headers, so
it only shows HTTP checks.

## How it works

```text
observe a request -> learn a set of destinations -> seal it into a token -> check later requests against it
```

Each token entry is called a caveat. An HTTP caveat matches the method, scheme, host, port and path. The default port for the scheme is never written out, in a token or a request, so `example.com:443` is denied. Two MCP tools can
share one HTTP endpoint, so an MCP caveat also matches the `Mcp-Method` and `Mcp-Name` header values.

Learning and checking share one set of rules for reading a request. Those rules deny a non-canonical spelling instead of
tidying it:

```text
EXAMPLE.com    denied: uppercase host
/a/../b        denied: dot segment
/%2e           denied: encoded dot
```

| Crate | What it contains |
|---|---|
| `token` | The request rules and token format |
| `seal` | Learning and sealing |
| `gate` | Observing and checking |

## Known limits

- Tokens are not signed, so anyone who can set the token header can add a destination.
- Learning trusts what it observes. Learn only from a run you trust, and have a person approve each destination before enforcing it.
- No request reader is included. Your code must extract each request field and pass its original bytes.
- The query is dropped, so one entry covers every action an API selects by query string.
- MCP checks read headers and never the body. On MCP routes, your code must require both headers, and the destination
  must reject calls whose headers and body disagree.

The [full list](docs/what-it-does.md#known-limits) has the rest.

## Design rules

These apply to all three crates:

- No I/O: no files, network, clock or threads.
- `no_std` with `alloc`.
- Clippy denies panic-prone constructs in library code, with tests exempt.
- No `unsafe` code in these three crates, enforced by a workspace lint.
- Plain data in and out. A failed call returns one of a fixed list of named cases.
- The secret-comparison helper compares equal-length raw bytes, up to 4,096, in constant time. It does not hide lengths.
- Every core dependency must build for `wasm32v1-none`.
- No build scripts anywhere in the dependency graph. Proc-macros are kept out by review.

## Build and test

Install Rust with [rustup](https://rustup.rs), then run `rustup toolchain install` in the repo. It installs
the version pinned in `rust-toolchain.toml`. Then install `cargo-deny`:

```sh
cargo install --locked cargo-deny --version 0.20.2
```

The checks:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo deny --locked check
cargo test --locked
```

## Docs

- [What it does](docs/what-it-does.md): every capability, every gap, and what it will never do.
- [Canonicalizer rules](docs/canonicalizer.md): how each part of a request is checked.
- [Backlog](purnell-maneuver-backlog.md): what comes next, starting with signed tokens.

## License

Apache-2.0, in [LICENSE](LICENSE). The WHATWG URL test data in `testdata/wpt/` keeps its own license, in
[testdata/wpt/LICENSE.md](testdata/wpt/LICENSE.md).
