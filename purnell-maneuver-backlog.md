# purnell-maneuver backlog

The next planned work for this repo. Closed work is in [purnell-maneuver-archive.md](purnell-maneuver-archive.md). The reasoning
behind it is in [purnell-maneuver-notes.md](purnell-maneuver-notes.md).

## Links

- **Repo:** https://github.com/kphutt/purnell-maneuver
- **Live site:** none, this is a library
- **Board:** this file
- **Archive:** [purnell-maneuver-archive.md](purnell-maneuver-archive.md)
- **Notes:** [purnell-maneuver-notes.md](purnell-maneuver-notes.md)

## Overview

**Goal:** a small, well-tested library that limits which HTTP and MCP destinations an AI agent or other automated client can reach.

**Next:** sign tokens, so a token proves who wrote it (B-8).

## How this file works

- **Order:** a row's position is its order. The top row goes first.
- **#:** a permanent ID such as `B-12`. It never changes or gets reused, even when rows move. The `B-` keeps
  GitHub from reading it as an issue or pull request number.
- **P:** priority. P0 comes first, P1 should follow, P2 can wait.
- **Effort:** S is under an hour, M is a few hours, L is a day or more.
- **Done when:** the check that proves an item is finished.
- **When an item closes:** move it to the archive, with what wrapped up and a link to the commit that shipped it.
  A commit cannot contain its own hash, so the row it adds says `The commit that adds this row` until a later commit
  adds the link.

## Commit format

Commits made before these tracking files existed have a title, a one-line summary and bullets, with no tracker
lines. Every commit since, starting with the one that adds these files, uses this full shape. `B-NN` stands for the
real item ID:

```text
feat(gate): carry an opaque run id the check cannot read

Let a token carry a caller-supplied label, without letting the check see it.

- Add the `v2` token format, which puts a run id before the caveats
- Change `gate::check` to take an opaque handle instead of token bytes

Closes: B-NN
Board: https://github.com/kphutt/purnell-maneuver/blob/main/purnell-maneuver-archive.md#b-nn
Follow up: Sign tokens, so a token proves who wrote it.
```

- **Title:** `type(scope): summary` in the present tense.
- **One line:** what this is, in plain English.
- **Bullets:** what the commit does.
- **Closes:** the backlog item it closes, or `none`.
- **Board:** a link to that item in the archive. Leave it out when `Closes` is `none`.
- **Follow up:** the next step. Leave it out when there is none.

This repo has no tagged releases. To point at an exact state, link to its commit.

## In progress

| # | Item | Effort | Description | Next step |
|---|---|---|---|---|
| | Nothing in progress | | | |

## 1. Ready to build

| # | Item | P | Effort | Description | Next step | Done when |
|---|---|---|---|---|---|---|
| B-8 | Sign tokens | P1 | L | A token proves nothing about who wrote it today | Choose the signature scheme | The test that pins the unsigned-token gap flips to a refusal |
| B-9 | A request reader | P1 | M | Turn one real platform's request into `RequestFacts` without tidying it | Pick the first platform | The reader denies when two copies of a fact disagree |
| B-10 | Add a check service | P2 | M | Add a service that runs the gate behind an external authorization check | Design it as its own crate | It builds and passes the workspace checks |
| B-11 | Language bindings | P2 | L | The library is Rust only | Start with Python | One binding passes the shared vectors |
| B-12 | Mutation tests | P2 | M | Check that the tests catch a deliberately broken rule | Run `cargo mutants --workspace` | Each survivor is fixed or recorded as equivalent |
| B-13 | Finish the Kani proofs | P2 | M | Some proofs do not finish | Stub `ascii_to_string` | Each proof verifies or lists why it cannot |
| B-17 | Make `try --explain` check the token first | P2 | S | `try --explain` and plain `try` can report different denials for the same bad token | Run the token check before the explanation | `try --explain` reports the same denial as plain `try` for every bad token in the flow vectors |
| B-18 | Add a Rust usage example to the docs | P2 | S | The docs have no short Rust example and no dependency line | Write a short learn, seal and check example, and the dependency line | The example compiles and its output matches the docs |

## 2. Research

Ideas to try. Each one ends in tests or a written result, not a feature.

| # | Item | P | Effort | Description | Next step | Done when |
|---|---|---|---|---|---|---|
| B-19 | Search for a way past the check | P2 | M | The tests and fuzzing try inputs without learning from a near-miss | Run agents that start from a token listing one path, share what they find on one board, and try to get any other request allowed | Each way past the check becomes a failing test and a fix, or the run records every spelling it tried |

## What I'd do next

1. Sign tokens (B-8).
2. Add the first request reader (B-9).
3. Add a check service (B-10).
