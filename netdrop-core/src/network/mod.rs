//! Сетевой слой netdrop.
//!
//! `protocol`  — формат кадров wire-протокола.
//! `transport` — iroh QUIC endpoint, hole punching, n0+n1 реле.

pub mod protocol;
pub mod transport;
