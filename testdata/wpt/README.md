# web-platform-tests URL data

`urltestdata.json` is the WHATWG URL Standard's shared test data, copied byte for byte from
[web-platform-tests](https://github.com/web-platform-tests/wpt). Do not edit it; replace it with a
newer copy instead, and update this file.

| | |
|---|---|
| Source | [`url/resources/urltestdata.json`](https://github.com/web-platform-tests/wpt/blob/c48d58747e1f211527fb695fd60548a997fae617/url/resources/urltestdata.json) |
| Commit | `c48d58747e1f211527fb695fd60548a997fae617` (2026-09-19) |
| SHA-256 | `81e85fd3c199c08ef9c34cf651b3580eeedd080316493bfaf277a6b5ff8cf652` |
| License | 3-Clause BSD, copyright web-platform-tests contributors: [`LICENSE.md`](LICENSE.md), copied from the same commit |

It is test data only. `crates/gate/tests/wpt.rs` reads it with `tinyjson` and uses WHATWG as an
oracle, not as the canonicalizer's standard: `crates/gate/tests/wpt.rs` explains how.
