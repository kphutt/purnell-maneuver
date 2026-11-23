# The canonicalizer

`token::canonicalize` is the one place a request becomes a target. Within it, the main way an exact-match list
fails open is a merge: two requests that a server keeps apart getting the same target. So anything not already in
canonical form is denied rather than tidied. The README's "Known limits" lists failures outside the canonicalizer.

| Field | Changed how | Denied when |
|---|---|---|
| Limits | Not changed | Method over 32 bytes, scheme over 16, authority over 259, path with query over 4096, MCP method over 64, MCP name over 1024, token over 8192. Checked before anything is read |
| Method | Not changed | Empty, or not an RFC 9110 token |
| Scheme | Not changed | Not exactly `http` or `https` |
| Host name | Not changed | Uppercase, an empty label, a byte other than lowercase ASCII letters, digits, `-`, `_` and `.`, or over 253 bytes |
| Numeric host | Not changed | The last label is a number and the host is not exactly a dotted quad, so `127.1` and `2130706433` deny |
| IPv6 host | Not changed | Not bracketed, not in RFC 5952 form, a zone id, or an IPv4-mapped address |
| User info | Not applicable | Any `@` in the authority |
| Port | If absent, filled in from the scheme (80 or 443) | The scheme's default written out, empty, a leading zero, not all digits, or above 65535 |
| Query | Dropped | A `#` in it still denies |
| Fragment | Not applicable | A `#` anywhere |
| Path shape | Not changed | Not starting with `/`, a `.` or `..` segment, or an empty segment other than a trailing `/` |
| Path bytes | Not changed | A byte outside letters, digits and `- . _ ~ ! $ & ' ( ) * + , = : @ /`, unless percent-encoded |
| Percent-encoding | Never decoded or re-cased | A malformed escape, lowercase hex, an encoded `/`, `\`, `%`, `;` or control byte, or an encoded letter, digit or `- . _ ~` |
| Decoded bytes | Never decoded | The bytes the path stands for are not well-formed UTF-8 |
| `Mcp-Method`, `Mcp-Name` | Read through MCP's `=?base64?…?=` wrapper when present, then stored percent-encoded | Empty; over 64 or 1024 bytes on the wire or once stored; a byte outside `0x20..=0x7E`; a value that needed the wrapper and arrived plain; a wrapper that was not needed; base64 that is not canonical |

## The query exception

The query is dropped, so requests that differ only in the query share a target. This is the one merge the
canonicalizer makes on purpose. An API that picks its action from the query string gets one target for every action
behind that path, so this library cannot limit such an API per action today.

## Changing a rule

A stored caveat must read back through the current rules. Tightening a rule is safe: an old caveat stops reading
back and its token denies. Widening a rule would silently widen existing tokens, so it needs a new caveat kind. A
new token version cannot do that job, because `check` is handed the caveats with the version cut away.

## Reading a request

The core takes `RequestFacts`: raw bytes for each field. Something in front of it has to copy those bytes out of the
platform's request. That reader must never tidy anything, and must deny when two copies of one fact disagree, such
as a `Host` header and `:authority`. No such reader is included yet.
