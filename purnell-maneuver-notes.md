# purnell-maneuver notes

What git can't show.

- **Tokens are unsigned because signing is not built yet (B-8).** A test pins the gap, so signing has to flip that test.
- **cargo-deny is pinned to 0.20.2 on every machine and on GitHub.** The local hook and the workflow then give the same answer. Move both pins in one change, and only to a release at least 7 days old.
- **Pull requests are squash-merged.** The squash commit takes the pull request's title and body, so those follow the commit format in the backlog file.
- **Settle which library a project uses by reading its own manifest or lockfile, never from memory or a summary.** Checked 2026-11-26: the current Solana validator ([anza-xyz/agave](https://github.com/anza-xyz/agave/blob/master/Cargo.toml)) uses `solana-ed25519`, while the older [solana-labs/solana](https://github.com/solana-labs/solana/blob/master/Cargo.toml) repo still pins `ed25519-dalek = "=1.0.1"`. The `minisign` Rust crate carries its own Ed25519 code. [pasetors](https://github.com/brycx/pasetors/issues/48) and Google OpenSK (1.x) use `ed25519-compact`.
- **Imported cargo-vet audits did not cover the newest dalek releases.** On 2026-11-26 I read the published audit files of [Google](https://github.com/google/rust-crate-audits), [Mozilla](https://github.com/mozilla/supply-chain), the [Bytecode Alliance](https://github.com/bytecodealliance/wasmtime/tree/main/supply-chain) and [Zcash](https://github.com/zcash/rust-ecosystem). Google's coverage stops at `curve25519-dalek` 4.0.0 and Zcash's at 4.1.3. None covers `ed25519-dalek` 3.0.0 or `curve25519-dalek` 5.0.0. Check again before relying on imported audits.
- **A pull request here cannot be merged with the safe-merge command until B-23 is done.** That command needs the reviewer's review to be posted, and no routine or trigger exists yet. A pull request with no review comments reads as clean but has not been reviewed.
