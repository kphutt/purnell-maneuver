//! `token` is the part of `purnell-maneuver` that `seal` and `gate` share.
//!
//! It holds the words both sides must agree on, and nothing else:
//!
//! - [`RequestFacts`]: what a server reports about one request, as plain bytes.
//! - [`canonicalize`]: the **one** canonicalizer. It turns request facts into a
//!   [`Target`] — an [`HttpTarget`], or an [`McpTarget`] when the request carries MCP's
//!   mirrored headers — or denies. `gate` uses it both to observe requests and to check them,
//!   and every server adapter must use it too, never its own string comparison. All of
//!   its rules live in one module, so the rule set can be replaced without touching the
//!   token format or the flow.
//! - [`Caveat`] and [`CaveatSet`]: the destinations a token allows. The only public way
//!   to get a caveat set is [`learn`], from targets that came out of [`canonicalize`],
//!   and no public function turns text into a caveat. That holds for code; it does not
//!   stop a person from writing a token by hand, which `gate` honors until tokens
//!   are signed.
//! - [`encode`] and [`token_lists`]: the token's byte format. They live in one small
//!   private module, and nothing else in the workspace knows the format.
//! - [`Denial`]: every way a check can say no, by name.
//!
//! Most callers use `gate` (observe, check) and `seal` (learn, seal) instead of this
//! crate directly.
//!
//! `no_std` + `alloc`, no `unsafe`, no panics, and no dependencies.
#![no_std]

extern crate alloc;

mod canonical;
mod caveat;
mod denial;
mod format;
mod target;

pub use canonical::{
    canonicalize, MAX_AUTHORITY_BYTES, MAX_MCP_METHOD_BYTES, MAX_MCP_NAME_BYTES, MAX_METHOD_BYTES,
    MAX_PATH_BYTES, MAX_SCHEME_BYTES,
};
pub use caveat::{learn, Caveat, CaveatSet};
pub use denial::Denial;
pub use format::{encode, token_lists, SealError, MAX_TOKEN_BYTES};
pub use target::{HttpTarget, McpFacts, McpTarget, RequestFacts, Target};
