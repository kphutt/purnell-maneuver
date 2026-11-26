# Token signing

Status: requirements and decisions drafted, and the signature library is chosen (D-5). The design
section is not written yet. Backlog item: [B-8](../../purnell-maneuver-backlog.md).

## Problem

Anyone who can set the token header can write a valid token today. The grammar is public, so a
client that controls its own token can list any destination it likes, and the gate allows it.

The attacker is whoever holds or relays a token. After signing, only the sealing side can make a
token that the gate accepts.

## Background

- **A token** lists the destinations a run may reach, in plain text. `seal` makes one from what a
  trusted run requested.
- **A caveat** is one entry in that list. "Canonical" means it is written in the one spelling the
  [canonicalizer](../canonicalizer.md) accepts.
- **A run id** is an optional label in a `v2` token, naming the run the token came from.
- **A gate** is the process that receives a request and a token. It calls `token::present` to split
  the token, then `gate::check` to decide. `check` only gets an opaque `Caveats` handle, never the
  token bytes or the run id.

## Decisions

- **D-1. Public-key signatures.** The sealing side signs with a private key. A gate gets only the
  public key, so it can check tokens but cannot make them. A shared secret would let anyone who
  breaks into one gate write new tokens.
- **D-2. Tokens expire.** The sealing side writes a latest-valid time into the signed bytes. The
  caller passes the current time into verification, so the library still never reads a clock.
- **D-3. Verification happens in `token::present`.** It is the only place that sees the whole
  token. `check` keeps getting only the `Caveats` handle.
- **D-4. Narrowing is out of scope.** In this version, nobody can add restrictions to a sealed
  token. A later design may let a holder narrow a token without a signing key.
- **D-5. Use `ed25519-compact`, pinned to an exact version, with `default-features = false`.**
  The crate is [ed25519-compact](https://crates.io/crates/ed25519-compact), at 2.6.1 today.
  - **Why this one.** It is the only candidate that meets the build rules with no exception. It has
    zero build scripts, zero proc-macros and zero dependencies, so `cargo deny --locked check` passes
    with the empty `allow-build-scripts` list. It builds `no_std` with `alloc` on all three wasm
    targets. Its checks on non-canonical signatures pass (see the evidence under Q-1). It is
    maintained: 2.6.1 was released on 2026-11-07.
  - **Prior use.** [pasetors](https://github.com/brycx/pasetors), a `no_std` PASETO token library,
    switched from `ed25519-dalek` to it for fewer dependencies
    ([changelog](https://github.com/brycx/pasetors/blob/master/CHANGELOG.md),
    [issue 48](https://github.com/brycx/pasetors/issues/48)). Google's
    [OpenSK](https://github.com/google/OpenSK/blob/develop/libraries/opensk/Cargo.toml) uses it as
    an optional software backend.
  - **Accepted risks.** The crate has one owner on crates.io. We found no public audit of it.
  - **What covers them.** The committed `Cargo.lock` with `--locked`, Dependabot's 7-day cooldown,
    reading the diff of each version bump (one crate, so the diff is small), and our own test
    vectors (SIG-15).
  - **What would make us switch.** We would move to `ed25519-dalek` and add a reviewed
    build-script exception to `deny.toml` if any of these happens: a Wycheproof or speccheck vector
    fails on a properly made key, a security advisory is filed against the crate, or the crate
    goes unmaintained.

## Requirements

Each requirement has an ID, so tests and the design can point at it.

### What signing must do

- **SIG-1. An edited token is denied.** Changing, adding or removing any byte of a signed token,
  the signature included, makes it deny.
- **SIG-2. A hand-written token is denied.** A token the sealing side did not sign is denied, even
  when every caveat in it is canonical. The test
  `known_gap_until_signing_a_hand_written_canonical_token_is_allowed` changes to expect a denial,
  and gets a new name.
- **SIG-3. An expired token is denied.** A token whose latest-valid time is before the time the
  caller passes in is denied. A token with no latest-valid time cannot be sealed.
- **SIG-4. Only a verified token can reach a decision.** The only way to get a `Caveats` handle is a
  token whose signature and expiry passed. No public function can return `Allowed`, or answer
  `token::lists`, from an unverified token.
- **SIG-5. Each failure has its own named denial.** New `Denial` cases cover at least an unsigned
  old token, an unknown key, a bad signature and an expired token. Nothing panics or returns a text
  message.
- **SIG-6. A fixed order of checks.** Before verification, `present` may read only these, each with
  a fixed format and a size limit: the length, the version, the key choice and the signature. No
  caveat or run id is read until the signature passes. The order of denials is: empty, too long,
  unknown version, unknown key, bad signature, expired. After that, `check` reads the request, then
  the caveats, as it does today.
- **SIG-7. The token never chooses how it is checked.** The version fixes the algorithm. A key
  choice in the token, if there is one, only picks among keys the caller supplied, and the
  signature covers it. A key of the wrong type or length is denied before any signature work. A
  public key must be a properly made key of prime order, and the caller supplies only such keys. A
  small-order or mixed-order key is outside the contract. The reason: the verify in
  `ed25519-compact` is cofactored, so speccheck vectors 4 and 5 (mixed-order keys) verify, and
  only the trusted sealing side, which can sign anyway, could supply such a key.
- **SIG-8. One valid spelling per signed token.** The scheme must reject a second spelling of a
  valid signature. The signature is written in a fixed-length encoding that is read strictly. It
  uses printable ASCII, contains no `;` or space, and fits in an HTTP header. Each sealed set still
  has exactly one token.
- **SIG-9. A signature cannot be reused elsewhere.** The signed bytes start with a fixed label
  naming this library and the token version, so a signature made for anything else does not verify.

### What it must keep

- **SIG-10. No I/O, no randomness.** Neither signing nor verifying reads a file, a network, a clock
  or a random source, or starts a thread. Keys and the current time come in from the caller.
  Signing is deterministic, so the same key and set always give the same token.
- **SIG-11. The same build rules.** Every core crate, including any new signing crate, follows the
  README's "Design rules". That means `no_std` with `alloc`, no panics in library code, no `unsafe`
  code, plain data in and out, and the three wasm builds in `.github/workflows/ci.yml`. Nothing in
  the dependency graph has a build script or a proc-macro.
- **SIG-12. Bounded cost.** Before any signature work, `present` checks the token length, each key's
  length and the number of keys. A signed token, signature included, stays within `MAX_TOKEN_BYTES`
  (8,192). `seal` counts the signature when it checks that limit, so it never makes a token that
  `present` would deny.
- **SIG-13. Tokens stay plain text.** A signed token is still printable ASCII that fits in an HTTP
  header. It is not encrypted, so the existing limit still applies: do not learn paths that contain
  secrets.

### What it must allow

- **SIG-14. Key replacement without an outage.** A gate can accept a new key and an old key at the
  same time, up to a small fixed number of keys. That lets the sealing side switch keys, then
  retire the old one.
- **SIG-15. Shared test vectors.** Signed tokens get vectors in `testdata/vectors/`, made with test
  keys that are marked as test-only. They include bad cases, such as an edited signature and a
  second spelling of one. The vectors include the Wycheproof Ed25519 set. A binding in another
  language can then check that it gives the same answers.

### What changes with it

- **SIG-16. Unsigned tokens are retired.** `v1` and `v2` tokens deny with a named case, and signed
  tokens use a new version. No tokens are in use yet, so there is no period where both are
  accepted. The same change updates the README, the `try` example, AGENTS.md, the page of what
  the library does, and the tests that use hand-written tokens.

## Non-goals

- **Revocation lists.** They need a list fetched from outside the library. Expiry (D-2) and key
  retirement are the only ways to stop a token.
- **Narrowing a sealed token.** See D-4.
- **Key generation, storage and distribution.** Making keys needs randomness, and where keys live
  is the deployment's job.
- **Encrypting tokens.** See SIG-13.

## Open questions

1. **Q-1. Which signature library?** Answered by D-5. The evidence follows.

   The nine tests a library had to pass, and the SIG items they come from:

   1. No build script or proc-macro in the dependency graph (SIG-11).
   2. `cargo deny --locked check` passes (SIG-11).
   3. `no_std` with `alloc` builds on the three wasm targets (SIG-11).
   4. A second spelling of a valid signature is rejected, checked with the
      [ed25519-speccheck](https://github.com/novifinancial/ed25519-speccheck) vectors (SIG-8).
   5. Deterministic, with no randomness crate (SIG-10).
   6. A key of the wrong length gives a typed error (SIG-7).
   7. Signs and verifies raw bytes, so the label of SIG-9 can lead the signed bytes (SIG-9).
   8. A supply chain we can trust (the README's design rules and `deny.toml`).
   9. Actively maintained (D-5).

   Results, measured on 2026-11-26 with `default-features = false`:

   | Library | Passed | Why the rest failed |
   |---|---|---|
   | `ed25519-compact` 2.6.1 | 9 of 9 | |
   | `ed25519-dalek` 3.0.0 | 7 of 9 | Build script in `curve25519-dalek`, plus proc-macro and build-script crates on x86_64, so tests 1 and 2 fail. |
   | `ed25519-zebra` 5.0.0 | 5 of 9 | The same build scripts, so tests 1 and 2 fail. Test 4 fails because it follows ZIP215, which accepts non-canonical R and A. Test 5 fails because `rand_core` is a required dependency. |
   | `biscuit-auth` 6.0.0 | 1 of 9 | 14 build scripts and 7 proc-macros in its graph. It needs `std`, an open advisory is in its graph, its last release was 2025-07-16, and its public API cannot verify a bare signature. |

   `ed25519-dalek` is used by [libsignal](https://github.com/signalapp/libsignal/blob/main/Cargo.toml),
   [Arti](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/crates/tor-llcrypto/Cargo.toml),
   [vodozemac](https://github.com/matrix-org/vodozemac/blob/main/Cargo.toml) and
   [ssh-key](https://github.com/RustCrypto/SSH/blob/master/ssh-key/Cargo.toml). We would take it
   only with a reviewed build-script exception.

   Wycheproof: all 210 vectors in `ed25519_test.json` (the C2SP/wycheproof file, at commit
   `65ca494`) were run through `PublicKey::from_slice` and `verify`. All 117 valid vectors verify
   and all 64 invalid ones are rejected. The 29 marked acceptable are all small-order or
   mixed-order public keys: 8 small-order keys are rejected and 21 mixed-order keys verify, which
   matches the SIG-7 contract.
2. **Q-2. Where does the crypto dependency go?** `token` has no dependencies on purpose, and only
   `token::format` knows the token bytes. Verifying in `present` gives `token` its first dependency.
   Signing could stay out of `seal`, with `seal` building the bytes to sign and a separate signer
   signing them.
3. **Q-3. How does a gate pick a key?** One way: the gate tries each of its keys, up to the cap in
   SIG-14. The other: the token names one key, and the signature covers that name. Trying each key keeps the token from
   choosing anything (SIG-7). Naming one key costs less work per request.

## Risks

These are accepted for this version:

- **A copied token works until it expires.** Signing proves who made a token, not who holds it.
  Anyone who copies one from a log or a hop can use it until its latest-valid time.
- **Retiring a key stops every token signed with it.** It is the only way to stop a token early.
- **A token works at any gate that trusts the same key.** Nothing ties a token to one deployment.
- **Post-quantum signatures are much larger.** If one is added later, the 8,192-byte limit may need
  to grow.

## Design

Not written yet. It starts once the open questions above are settled. It will include the
alternatives considered.
