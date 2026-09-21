//! `seal` is the signing side of `purnell-maneuver`: the future home of sealing (signing)
//! tokens.
//!
//! This crate is intentionally empty. Nothing is implemented yet: there is no signing API
//! and no connection to any outside system.
//!
//! `no_std` so the same code can run on every target this repo builds for, including
//! wasm and Envoy.
#![no_std]
