# purnell-maneuver notes

What git can't show.

- **Tokens are unsigned because signing is not built yet (B-8).** A test pins the gap, so signing has to flip that test.
- **cargo-deny is pinned to 0.20.2 on every machine and on GitHub.** The local hook and the workflow then give the same answer. Move both pins in one change, and only to a release at least 7 days old.
- **Pull requests are squash-merged.** The squash commit takes the pull request's title and body, so those follow the commit format in the backlog file.
