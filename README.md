# purnell-maneuver

An AI agent can hold a credential that opens more endpoints than its task needs. `purnell-maneuver` is a small Rust
library that limits which HTTP and MCP destinations such a client may call. Your code shows it the requests from a
run you trust, and it writes them into a token. A later request is allowed only if its method, scheme, host, port
and path match an entry in that token byte for byte. For an MCP call, the MCP method and name must match too.

Tokens are not signed yet. Anyone who can edit a token can add a destination to it. Until signing exists, this is
not a security boundary against a client that controls its own token. See [Known limits](#known-limits).

## Try it

From a clone of this repo, with Rust installed:

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

The first command builds a token that lists one request. The second command checks the same request against that
token, and it is allowed. The third checks a request for `/admin`, which the token does not list, so it is denied.

In Git Bash on Windows, first run `export MSYS_NO_PATHCONV=1` so the shell leaves the paths alone.

## How it works

```text
observe a request -> learn a set of destinations -> seal it into a token -> check later requests against it
```

The library uses three terms:

| Term | Meaning |
|---|---|
| Caveat | The method, scheme, host, port and path of one allowed destination, plus the MCP method and name for an MCP call. |
| Seal | To write a set of caveats into a plain-text token. There is no cryptography yet. |
| Run id | An optional label the caller puts in a token. It has no effect on whether a request is allowed. |

The code is in three crates:

| Crate | What it contains |
|---|---|
| `crates/token` | The canonicalizer, the caveat types and the token format |
| `crates/seal` | `seal`, `seal_for`, and `learn` (re-exported from `token`) |
| `crates/gate` | `observe`, `check`, `present` (re-exported from `token`), and `compare_secrets`, a separate constant-time helper that `check` does not use |

### One canonicalizer

Learning and checking both use `token::canonicalize` to turn a request into a destination. It denies any input that
is not already in canonical form:

```text
EXAMPLE.com    denied: uppercase host
/a/../b        denied: dot segment
/%2e           denied: encoded dot
```

Its only changes are filling in a default port, unwrapping and percent-encoding MCP values for storage, and
dropping the query. The full rule table is in [docs/canonicalizer.md](docs/canonicalizer.md).

### MCP calls

The Model Context Protocol has a [Streamable HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#standard-request-headers).
On it, calls to different tools are POST requests to the same endpoint, so an HTTP destination alone cannot separate
them. An MCP caveat also records two request headers, the MCP method and name:

```text
mcp POST https mcp.example.com /mcp tools/call get_document
```

### Destinations in a token

The destination types have no public constructor, so every destination the library seals has passed the
canonicalizer. That does not prove a real request happened, because a caller can describe any request it likes.

## Known limits

- Tokens are not signed. Anyone who can set the token header can write a canonical destination, and it is allowed.
  The test `known_gap_until_signing_a_hand_written_canonical_token_is_allowed` records this.
- Learning trusts what it observes. Run it only in a window you trust, and have a person approve each learned
  destination before enforcing the set.
- MCP checks trust the mirrored headers and do not read the body. The destination must reject a request whose
  headers and body disagree, [as MCP requires](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#server-validation).
  Without that check, an allowed header can front a different call.
- The library does not read the MCP protocol version. The layer in front of it must refuse a missing version, or one
  that does not require the header check.
- MCP calls with no name have no caveat. A method such as `tools/list` has no name to mirror, so a request reader must
  refuse it. Passing it as plain HTTP would learn the bare POST, which then allows other requests read the same way.
- The query is dropped after a check for raw control, space and non-ASCII bytes. Requests that differ only in
  their query share a destination, so this library cannot limit an API that picks its action from the query string.
- The query is not validated beyond its raw bytes. Dot segments and encoded CRLF in it pass, so every hop behind the
  gate must split the query off first and must not decode it into a header.
- No request reader is included. Something in front of the core has to copy the raw request bytes into
  `RequestFacts` unchanged.
- Learning and checking must see the same request. If a proxy rewrites paths, take both views from the same side of
  that proxy.
- The gate must be on every path to the destination. A destination does not record which socket or listener a request
  arrived on.
- Some spellings open more than they appear to. A server behind the gate can send two paths the gate keeps apart to
  one resource. IIS can ignore a trailing dot, and some character mappings turn the encoded full-width slash
  `%EF%BC%8F` into a real slash.

[docs/what-it-does.md](docs/what-it-does.md) lists what the library does, what it does not do yet, and what it will
never do.

## Design rules

These apply to all three crates:

- No I/O: no files, network, clock or threads.
- `no_std` with `alloc`.
- No panics in library code. Clippy's panic lints are errors, with tests exempt.
- No `unsafe` code, enforced by a workspace lint.
- Plain data in and out. A failed call returns one of a fixed list of named cases.
- Secrets are compared as raw bytes in constant time, never case-folded or normalized first.
- Every core dependency must build for `wasm32v1-none`.
- No build scripts anywhere in the dependency graph. Proc-macros are kept out by review.

## Build and test

You need `cargo-deny` and the Rust version pinned in the toolchain file.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo deny --locked check
cargo test --locked
```

The test command runs the unit tests and the integration tests in `crates/gate/tests/`. Those tests read the shared
vectors and the WHATWG URL test data, both under `testdata/`.

The Kani proofs for the canonicalizer run separately. Eight of the 13 finish, some over small bounded inputs. The
other five are listed in [docs/what-it-does.md](docs/what-it-does.md).

To run these checks through git hooks, along with a secret scan and three wasm builds, install pre-commit and
gitleaks, then run:

```sh
pre-commit install --hook-type pre-commit --hook-type pre-push
```

## License

Apache-2.0, in [LICENSE](LICENSE). The WHATWG URL test data in `testdata/wpt/` keeps its own license, in
[testdata/wpt/LICENSE.md](testdata/wpt/LICENSE.md).
