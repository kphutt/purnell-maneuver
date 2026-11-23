# What purnell-maneuver does, and what it does not

This library is small. Small enough that this page can list everything, so it does: if a capability
is not on the first list, `purnell-maneuver` does not have it.

It has three lists.

1. **What it does.** Everything it does today, one line per capability, each naming what stands
   behind it. Where nothing stands behind one, the page says so.
2. **What it does not do yet.** Known gaps.
3. **What it will never do.** Limits that come from the design, not from unfinished work. Closing one would cost more than it bought.

Nothing here is a schedule. This page says what is true of the code, not when anything lands.

## The whole public surface

Eleven free functions, in three crates. There are no others.

```text
gate::observe
gate::check
gate::compare_secrets
seal::seal
seal::seal_for
token::canonicalize
token::learn
token::encode
token::encode_for
token::present
token::lists
```

`gate` and `seal` are the two sides most callers use. `token` holds what they share: the
canonicalizer, the caveat types and the token format. `seal` re-exports `token::learn`, and `gate`
re-exports `token::present`, so an ordinary caller touches `token` only for the types.

Everything else the crates export is a type, a method on a type, a named error case or a byte limit.

## 1. What it does

| What it does | The call | What stands behind it |
|---|---|---|
| Turns one request into one canonical destination. The request is four fields — method, scheme, authority and path — and optionally two MCP header values. The answer is one target or one named refusal, never anything in between. | `gate::observe`, which is `token::canonicalize` | The shared vector file `testdata/vectors/canonical_target.json`, read by `canonical_target_vectors_pass` |
| Refuses any spelling that is not already canonical, instead of tidying it. Uppercase in the scheme, the host or an IPv6 literal is denied, not folded. The one thing it fills in is the scheme's default port, and only when the authority names none. | same | The `disagree_*` cases in the vector file; the machine-checked proofs `a_scheme_is_accepted_only_as_exact_lowercase_bytes`, `the_authority_split_loses_no_byte_and_denies_user_info`, `a_port_is_accepted_only_in_its_one_canonical_spelling`, `every_accepted_port_is_written_back_the_way_it_was_read`, `an_accepted_host_name_is_already_in_its_one_spelling`, `every_byte_is_classified_the_way_the_rules_say` |
| Gives two requests the same destination only if they differ in the query, which it drops on purpose, or in a fact a destination does not record, such as the listener or another header. | same | `no_merge_one_target_means_the_same_method_scheme_host_port_and_path` (a sampled test; the Kani proof of the same name does not finish); the WHATWG oracle `whatwg_url_test_data_agrees_where_the_canonicalizer_accepts`, over vendored web-platform-tests data |
| Reads the query only to refuse `#` or a raw control byte, space, DEL or non-ASCII byte, then drops it. Other printable ASCII is not parsed. | `gate::observe`, `gate::check` | The `query_*` cases in the vector file; `a_query_byte_outside_printable_ascii_is_denied_through_check`, over all 256 byte values |
| Writes an HTTP destination back into request fields that canonicalize to the same destination again, so a stored caveat can be read back and checked byte for byte. The MCP accessors return the stored spelling instead: `us west 1` comes back as `us%20west%201`, which is a different value if sent again. | `HttpTarget::authority` and the field accessors | `idempotence_a_target_written_back_canonicalizes_to_itself` (a sampled test; the Kani proof of the same name does not finish) |
| Tells an MCP call apart from the plain POST that carries it, by making the two mirrored header values part of the destination. A token allowing one tool does not allow a request whose headers name another, and does not allow the bare POST. The body is not read, so this relies on the destination rejecting a request whose headers and body disagree, as MCP requires. | the `mcp` field on `RequestFacts` | The `mcp_*` cases in the vector file; `one_value_one_spelling_no_two_accepted_mcp_values_stand_for_the_same_thing`; the proof `every_mcp_value_byte_is_classified_the_way_the_rule_says` |
| Learns a set of destinations from observed ones. Duplicates collapse, the set is ordered, and it believes everything it is given. | `token::learn`, re-exported as `seal::learn` | Unit tests in `crates/token/src/caveat.rs`; the flow vectors `testdata/vectors/flow.json` |
| Hands a learned set back for a person to read before it is enforced. | `CaveatSet::caveats` | Nothing. It is an accessor with no rule to test. Reviewing the set is a step a deployment performs, not something the library can check. |
| Seals a learned set into a token. One set has exactly one token: caveats are sorted, with no repeats, and every byte is printable ASCII that fits in an HTTP header. | `seal::seal` | Unit tests in `crates/seal/src/lib.rs`; the flow vectors |
| Seals the same set with a run id: an opaque label the caller supplies. | `seal::seal_for` | `a_sealed_token_carries_the_run_it_was_sealed_for`; `sealing_for_a_run_lists_exactly_what_sealing_without_one_does` |
| Splits a presented token into the run id and the destinations, and keeps the id out of the check. The bytes the check is handed do not contain the id or the version tag, and the handle's field is private to another crate, so no expression inside the check can reach it. | `token::present`, re-exported as `gate::present` | `the_run_is_read_beside_the_check_and_never_inside_it`; the compiler. The exact compile error is written out in `crates/token/src/format.rs` to be run by hand, because automating it would need a dependency the workspace bans |
| Decides one request against a set of destinations: one lookup, exact bytes, no prefixes, no wildcards, no options. An empty set allows nothing. | `gate::check` | `an_empty_caveat_set_allows_nothing`; `every_observed_subset_allows_exactly_what_the_oracle_says`, which checks every subset of a small set of tricky requests against a separate hand-written oracle |
| Refuses a token that is not in the exact form sealing writes, byte for byte, including a caveat of a kind this build does not know. A caveat is never skipped. One harmless exception: a stored MCP value whose required wire form is over its byte limit reads back, but no request can match it. | `token::present` and `token::lists` | `malformed_v1_bodies_are_denied`; the hand-written malformed tokens in the flow vectors |
| Names every refusal. Fifteen cases, each with a stable lowercase name an adapter can log. | `Denial::name` | `every_variant_has_a_unique_name`, backed by a match with no catch-all, so a new case cannot be added without being named |
| Checks every input against a byte limit before reading it, and never counts characters. | every entry point | `each_field_over_its_limit_is_denied_before_any_field_is_read`; `over_long_token_is_denied_before_reading` |
| Always answers. Random bytes as the token and as the four HTTP request fields give a destination or a named refusal, with no panic in the tested paths, and a random token never allows anything. The loop does not set the two MCP values: random MCP bytes are tested through `gate::observe` only. Allocation failure is left to the host. | `gate::check` | `random_input_never_panics_and_always_gets_a_named_answer`, a fixed-seed random-input loop; `totality_and_bounded_cost_any_bytes_give_a_bounded_target_or_a_named_denial` |
| Compares two secrets as raw bytes in constant time, up to 4096 bytes, and answers with a named case rather than a bare yes or no. It does not hide the lengths of its inputs. | `gate::compare_secrets` | `testdata/vectors/compare_secrets.json`, read by `shared_vectors_pass`. The constant-time property itself has **no behaviour test** — swapping the constant-time comparison for `==` changes no answer. `compare_secrets_still_compares_in_constant_time` is a guard on the source text, which is weaker than a measurement and is written down as such |
| Builds without the standard library. No `unsafe`, no panics, no files, no network, no clock, no threads, and one runtime dependency. It builds for three wasm targets, including one with no standard library at all. | — | The compiler enforces `unsafe_code = "forbid"`. Clippy enforces the panic lints. The wasm builds and `cargo deny` run in the optional pre-push hook |

### Every refusal it can name

```text
empty_token
token_too_long
unknown_version
malformed_run_id
malformed_token
unknown_caveat_kind
request_too_long
malformed_method
unsupported_scheme
malformed_host
malformed_port
malformed_path
malformed_mcp_method
malformed_mcp_name
not_listed
```

### Every kind of destination it can express

```text
http
mcp
```

An `http` caveat is a method, a scheme, a host, a port and a path. An `mcp` caveat is those five
plus the two MCP header values. A caveat of any other kind denies the whole token.

## 2. What it does not do yet

Known gaps.

| Gap | What it costs today |
|---|---|
| **Tokens are not signed.** | The token proves nothing about who wrote it. The grammar is published, so anyone who can set the token header can write a canonical destination by hand and it is allowed. The test `known_gap_until_signing_a_hand_written_canonical_token_is_allowed` pins today's behaviour so the gap cannot be forgotten; signing flips it to a refusal. This is the single largest thing on this page. |
| **Nothing lists the request facts an adapter can see and a caveat cannot express.** | A server adapter holds the whole request head. An HTTP destination is five fields, and an MCP destination is seven. Anything in that gap is a fact the destination may act on and the allowlist never checked. The sharp case is a method-override header: the check approves a `POST`, and a destination that honours the header performs a `DELETE`. The fix is an adapter rule refusing any request carrying a fact in the gap — which needs the facts enumerated by name first, and that list does not exist. |
| **The gate cannot confirm a run id.** | A run id is whatever the token says, and anyone who can edit the token can change it, so it is not proof of which client sent a request. Confirming it would need an identity the gate gets some other way, which belongs in the layer that deploys the library. |
| **One gate in front of two listeners can allow a destination learned on the wrong one.** | A destination is built only from what the request says. Nothing in it says which socket the request arrived on, so a process serving a public listener and an admin listener that report the same host cannot tell them apart. A fix would record the socket's local port as its own observed fact, separate from the authority's port. None of it is built. |
| **Five of the machine-checked proofs do not finish.** | `totality_any_bytes_give_a_bounded_target_or_a_named_denial`, `idempotence_a_target_written_back_canonicalizes_to_itself` and `no_merge_one_target_means_the_same_method_scheme_host_port_and_path` state the three invariants over a whole request, and none of them finishes. Neither do `every_ipv6_address_has_exactly_one_accepted_spelling` or `a_written_mcp_value_reads_back_unchanged`. They are kept in the tree. Until they finish, sampled tests are what pin those invariants. |
| **Nothing here turns a real platform's request into request facts.** | That layer must never normalize, must prefer the rawest thing the platform offers, and must refuse when two copies of one fact disagree. No code implements it yet. Until it exists, the library cannot be put in front of a real server without somebody writing that layer by hand. |
| **An MCP call with no name has no safe representation.** | `Mcp-Name` is required and may not be empty, so a method with no `params.name` or `params.uri`, such as `initialize` or `tools/list`, cannot have an `mcp` caveat. A request reader must refuse these calls. If it passes `mcp: None` instead, learning records a plain HTTP caveat for the POST, and that caveat allows any later request also read as `None`. |
| **There are no language bindings.** | The library is Rust only today. Python and TypeScript bindings are planned and not built. |
| **Destinations with an id in the path each need their own caveat.** | There are no path templates anywhere in the crates, so `/orders/7` and `/orders/8` are two destinations. A template kind would let them be one, and it has to be proven to be a tightening before it can be added. |
| **An API that picks its action from the query string cannot be limited per action.** | The query is dropped, so every action behind one path is one destination. Such an API needs query facts that a deployment opts into, by name, for that API only. That is a planned extension and does not exist. |
| **A large set of destinations has no way to travel except in full.** | A token carries the whole list and must stay under its byte limit. A token that carries a reference instead, with the set fetched another way, is planned and unbuilt. |
| **An API specification cannot be used as a source of destinations.** | Importing the operations a specification declares, running them through the same canonicalizer and reviewing them like a learned set, is planned and unbuilt. |
| **Whether filling in the default port should survive at all is undecided.** | It is one of the two rewrites the canonicalizer makes: an absent port becomes the scheme's default, and a written default is denied. The standard says the two are equal. Dropping it has its own cost in false refusals. The decision is open and the cost is not known. |

## 3. What it will never do

Each of these is a limit the design chose.

| It will never | Why that is deliberate |
|---|---|
| **See inside one allowed call.** | One call is one destination. A batch endpoint's sub-requests, an MCP tool's arguments and everything inside an opened session are all invisible, and a check takes one destination and will not take a set. Taking a set would mean the library endorsing some other format's rules about which of those sub-requests depend on which. As a result, allowing a batch endpoint means allowing anything that endpoint can reach, so an allowlist should exclude such an endpoint rather than learn it. |
| **Read a request body.** | The MCP facts come from two mirrored headers and nothing else. A body is large, it can disagree with the headers, and parsing it in two places is two chances to disagree. A later kind of destination that reads one would be a new caveat kind with its own rules, never a change to these. |
| **See a response.** | There is no response anywhere in the library. A destination the server itself refused is therefore learned exactly like one it served: three refused probes during a learning window become three allowed destinations. Confirming a learned destination against the answer belongs in the layer that sits in the response path. Putting it here would give the check a second source of truth and break the one thing the design rests on — that learning and checking see the same facts. |
| **Remember anything between requests.** | The check is a pure function. Request one and request ten thousand get the same answer. There is no clock and no counter, so "only once", "the second time" and "after five minutes" are not expressible and must not become expressible. A retry cap belongs in the caller. |
| **Know who is calling.** | There is no client identity, no source address, no process and no session. Two clients look the same to it. |
| **Know why a request happened.** | Nothing links a request to what provoked it. A destination's fields say where a request goes, and none of them says where it came from. |
| **Have a monitor-only mode.** | The same request gives the same verdict either way. Which gate is in which mode is a deployment's decision, made with the verdict, not inside it. |
| **Produce a response.** | A check answers `Allowed` or a named refusal. What a caller sends back to the client — the status, the body, whether it is distinguishable from the destination's own refusal — is the host's design, and this library has no opinion it can enforce. |
| **Do any input or output.** | No files, no network, no clock, no threads. A caller passes in everything the library needs. This is what lets one copy of the code run in wasm, in a proxy filter and in a server process, and it is why the core can be reasoned about at all. |
| **Know anything about authentication or authorization.** | It reads no policy, no role and no session, and it never learns what a credential could already do. A destination list can only ever *remove* reach; it never grants any. A forged token, a widened allowlist or a destination learned by mistake gives a caller no access its credential did not already have, because the destination's own authorization never saw the token. It does remove the limit this library exists to apply. |
| **Control what a destination does once it is reached.** | If an allowed call makes the destination act somewhere else, that second hop does not cross this library at all. It limits where a client can go, not what it does there. |
| **Fold two spellings into one destination.** | A merge is the main way an exact-match list fails open inside the canonicalizer. Every rule here refuses rather than tidies, and the cost — refusing requests a real client really sends — is accepted on purpose. |
| **Parse raw HTTP itself.** | Every platform this library sits behind hands over a request it already parsed. Parsing the wire bytes here would be request-smuggling territory, and the quirks of the host's own parser are part of what a deployment trusts either way. |

## What holds only because a deployment holds up its side

Everything in list 1 is a guarantee about the code; none of it is a guarantee about a running
system, because a running system is more than the code. Each guarantee below is conditioned on
something no crate here can check, covered in the README's "Known limits" and in
`docs/canonicalizer.md`.

| The guarantee holds only if | Otherwise |
|---|---|
| **`learn` runs only in a window the deployment trusts, and a person reads the learned set before it is enforced.** `learn` believes every request it is shown; nothing in the library tells a trusted request from an attacker's. | A request observed during learning becomes an allowed destination whether or not it should be one. See "Known limits" in the README. |
| **Learning and checking sit at the same point in the request chain**, and every hop in front of the gate that can rewrite a path -- a merging or normalizing proxy included -- is named as part of what the deployment trusts. | The two sides describe one request differently, which either denies traffic that should pass or lets two different requests share one caveat -- the same shape of bug as Istio's repeated-slash bypass (CVE-2021-31920) and Envoy's escaped-slash bypass (CVE-2021-29492). See "Known limits" in the README. |
| **The gate sits on every path a request can reach the destination by**, not only the one it was learned or tested against. A target carries no fact about which socket or listener a request arrived on. | One process serving two listeners that report the same host can allow, on the listener nobody meant to open up, whatever was learned on the other one. This is the deployment-facing edge of the listener gap above; until that gap closes, avoiding this shape is the deployment's job, not the library's. See "Known limits" in the README. |
| **The reader in front of the core hands it raw bytes, never a framework's tidied version, and denies wherever two sources of the same fact disagree.** The canonicalizer only ever sees what the reader hands it. | A reader that normalizes, or silently picks one of two disagreeing sources, hides from the canonicalizer exactly the spelling its no-merge rule exists to catch. See "Reading a request" in `docs/canonicalizer.md`. |

## What on this page is checked, and what is not

A page like this goes stale silently, so the facts that can be derived from the source are derived
from it. `crates/gate/tests/what_it_does.rs` runs with the ordinary test suite and fails if:

- the list of refusal names above is not exactly the names the code can produce;
- the list of destination kinds above is not exactly the kinds the token format knows;
- the public surface above is not exactly the public functions the three crates define;
- a function this page names does not exist anywhere in the crates' sources. This reads only snake_case names of 12 or more characters, so it skips short names and paths such as `Denial::name`.

The last one is deliberately one-directional. A function this page names and the code no longer has is
a false claim, so the test catches it. A new proof this page does not mention is not a false claim,
so the test lets it through rather than failing somebody else's work for adding one.

Everything else on this page is prose, and prose is what a reader has to trust. A judgement — that
a limit belongs in the third list rather than the second — cannot be derived from the source,
because the source cannot tell a deliberate limit from an unfinished one. Those sentences are
reviewed like any other change.
