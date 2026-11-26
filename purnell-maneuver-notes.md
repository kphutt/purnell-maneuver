# purnell-maneuver notes

What git can't show.

- **Tokens are unsigned because signing is not built yet (B-8).** A test pins the gap, so signing has to flip that test.
- **cargo-deny is pinned to 0.20.2 on every machine and on GitHub.** The local hook and the workflow then give the same answer. Move both pins in one change, and only to a release at least 7 days old.
- **Pull requests are squash-merged.** The squash commit takes the pull request's title and body, so those follow the commit format in the backlog file.
- **Check what another project depends on in its own manifest or lockfile, never from memory or a summary.** Three claims were wrong on 2026-11-26: Solana does not use `ed25519-dalek`, the minisign Rust port does not use `ed25519-compact`, and "no major project uses `ed25519-compact`" missed pasetors and OpenSK.
- **Imported cargo-vet audits did not cover the newest dalek releases.** On 2026-11-26 none of the published audits (Google, Mozilla, Bytecode Alliance, Zcash) covered `ed25519-dalek` 3.0.0 or `curve25519-dalek` 5.0.0. Google's stops at `curve25519-dalek` 4.0.0 and Zcash's at 4.1.3. Check again before relying on them.
