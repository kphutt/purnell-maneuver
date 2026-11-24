# AGENTS.md

This is a Rust workspace with three core crates: `token` (shared: the canonicalizer, the
caveat set and the token format), `gate` (observe, check) and `seal` (learn, seal).
Before changing anything under `crates/`, read README.md's "Design rules", which hold
for every core crate here, and `docs/canonicalizer.md`. The local checks
(`.pre-commit-config.yaml`) enforce the rules a tool can actually check (formatting,
the panic lints, `unsafe_code = "forbid"`, the wasm builds, the shared test vectors);
the rest (no I/O, and plain data in and out) are reviewed by hand. The rules are not
repeated here so there is only one copy to keep current.

Run once, right after cloning:

```sh
pre-commit install --hook-type pre-commit --hook-type pre-push
```

Without that step this clone runs no checks before a push, and nothing will warn you.
GitHub runs the same commands on every pull request (`.github/workflows/ci.yml`), so
keep that file and the hooks in step.

## No build scripts, no proc-macros

Cargo has no `--ignore-scripts` switch: any dependency with a `build.rs` (or any
transitive dependency of one) runs arbitrary code on every `cargo build` or `cargo test`,
with the full privileges of whoever runs the command. **The core crates (`token`, `seal`,
`gate`) and their tests allow zero build scripts and zero proc-macros.** The build-script
half is enforced by `deny.toml`'s `[bans.build]` table: `allow-build-scripts = []` (an
empty allow-list — no crate anywhere in the graph may have a build script) and
`executables = "deny"`. `cargo deny --locked check` (part of the pre-push hook) fails the
moment a build-script dependency, or one that pulls one in transitively, is added.
Proc-macros are not blocked by this check, so look for new ones with `cargo metadata`.

This is why the shared test vectors are read with `tinyjson` (a JSON parser chosen
because it has no build script, is not a proc-macro, and pulls in no non-dev
dependencies of its own) instead of `serde`/`serde_json` + `serde_derive`, and why hex
decoding in `crates/gate/tests/vectors.rs` is a few hand-written lines instead of the
`hex` crate.

**Bindings added later will need this.** `pyo3` (Python) and `wasm-bindgen`
(TypeScript/wasm) both use proc-macros, and native-module bindings commonly pull in a
build script. When a binding needs a build script, add that crate to `deny.toml`'s
`allow-build-scripts` by name, as its own reviewed change. Proc-macros have no allow-list,
so check `cargo metadata` for new ones in the same change. Never widen the check to "warn"
or remove it. Bindings live outside `crates/` and are not held to the rest of this rule
(no I/O, `no_std`, etc.); only the build-script/proc-macro ban is meant to extend to them.

## The canonicalizer and the token format

These hold by the shape of the code; keep it that way:

- **One canonicalizer.** `token::canonicalize` is the only place a request becomes a
  target. `observe`, `check` and every future server adapter go through it; nothing
  compares raw request strings. Every rule lives in `crates/token/src/canonical.rs`
  and nowhere else, so the rule set can be swapped without touching the format or the
  flow. A rule change goes in the table in `docs/canonicalizer.md` and in
  `testdata/vectors/canonical_target.json` in the same change.
- **Never merge.** Apart from the deliberate query drop, the canonicalizer folds nothing:
  any input that is not already canonical is denied, never folded onto another spelling,
  including uppercase in the scheme, host or IPv6 hex. It does *rewrite* in exactly two
  places, and both rewrites are injective, which is what the no-merge rule actually needs:
  the port rule fills in the scheme's default when none is given (and denies that default
  written out), and an MCP value is decoded from its base64 wrapper if it has one, then
  percent-encoded for storage in a caveat body. Every fact comes from the request, and
  every field is checked on its own, with one exception: the port rule reads the scheme.
  `testdata/wpt/` is vendored data: replace it, never edit it.
- **Tighten freely, never widen in place.** A stored caveat must read back through the
  current rules, so tightening a rule only makes old caveats deny. Widening a rule (a new
  fold, a newly accepted spelling) silently widens every existing token, so it needs a
  new caveat kind, and it must keep the no-merge invariant test
  (`crates/gate/tests/invariants.rs`) and the WHATWG oracle (`crates/gate/tests/wpt.rs`)
  passing. **A new token version cannot do that job**: `present` hands `check` the caveat
  region with the version cut away, so `decode` has no version to branch on, and the kind
  is the only thing that pins a caveat's rules. So once tokens are in use, a change
  to what stored caveat bytes *mean* retires the old kind and adds a new one, and an old
  token then denies as a whole rather than being read under rules it was not written for.
  No tokens are in use yet, so a rule change is still just a rule change.
- **One format module.** Only `crates/token/src/format.rs` knows the token bytes. Library
  code elsewhere reads tokens through `token::present` + `token::lists`, or
  `gate::check`. The `try` example's tests check its printed tokens, and the fuzz test
  re-parses tokens on purpose as an independent check.
- **`check` never gets the token, only its caveats.** `present` splits a token into the
  run it names and an opaque `Caveats` handle, and only the handle goes to `gate::check`.
  `Caveats` keeps one private field and no public accessor, so `check` cannot reach the
  run id from another crate (`E0616`), and `present` cuts after the id so those bytes do
  not contain it either. Keep both halves: adding an accessor, or handing `check` the
  token bytes again, silently undoes that type-level guarantee. The `E0616` check to run
  by hand is recorded in `format.rs`, beside the `Target` `E0603` one in `target.rs`.
- **Caveats come only from the canonicalizer, in code.** `Target`, `Caveat` and
  `CaveatSet` get no public constructor, and nothing public turns text into a caveat, so
  every sealed destination passed the canonicalizer. That does not prove a real request
  happened: a caller can build `RequestFacts` for any request. It is a type-level
  property: tokens are not signed yet, so anyone who can write the token header can list
  any canonical target by hand, and `check` allows it (a known limit in the README). Don't
  describe it as more than that. In the library's tests, valid tokens come from
  `seal(learn(observe(...)))`. Hand-written tokens are for cases that must be denied, for
  the `try` example's `v1` check, for a bare `v1` or `v2;<run>` header (a valid empty set)
  where a test needs one, and for the test that pins the unsigned-token gap
  (`known_gap_until_signing_a_hand_written_canonical_token_is_allowed`), which signing
  flips.
- **Allowed is built in one place**, `gate::check`. Every other outcome is a named
  `Denial`.
- **When `canonical.rs` changes, run the Kani proofs**
  (`crates/token/src/canonical_kani.rs`). Passing sampled tests do not show that a bug in
  a rule would be caught. The proofs need Linux (`cargo kani --harness <name>`, two or
  three at a time), so this is a manual check, not a pre-commit gate.
- Integration tests under `crates/gate/tests/` allow the panic lints at the top of each
  file, because a test fails by panicking. Library code never does.
- **`docs/what-it-does.md` is the one exhaustive list** of what this library does, what it
  does not do yet, and what it will never do. Adding or removing a capability, a refusal
  name or a caveat kind means editing that page in the same change.
  `crates/gate/tests/what_it_does.rs` fails on the parts a test can check: the refusal
  names, the caveat kinds, the public functions, and whether a function the page names
  still exists. That last check reads only snake_case names of 12 or more characters, so
  it skips short names and paths such as `Denial::name`. Which list a limit belongs on is
  a judgement, and no test makes it.

## cargo-deny

Installed with a pinned version, not whatever `cargo install cargo-deny` happens to
resolve to today:

```sh
cargo install --locked cargo-deny --version 0.20.2
```

Config is `deny.toml` at the repo root. Run it directly with `cargo deny --locked
check` (the pre-push hook runs this first, before the slower checks, since it doesn't
compile anything and is the check most likely to reject a change outright). `--locked`
must come *before* `check` (`cargo deny --locked check`, not `cargo deny check
--locked`) -- `cargo-deny`'s top-level flags aren't accepted after the subcommand.
