// ============================================================
//  netdrop-core // lib.rs
//
//  Ядро netdrop — zero-knowledge P2P-передача файлов:
//    • crypto            — эфемерный X25519 (PFS) + HKDF + ChaCha20-Poly1305,
//                          тикеты `nd1…` (Base58).
//    • network::protocol — wire-фрейминг (тип/длина/nonce/payload+tag).
//    • network::transport — iroh QUIC endpoint (итерация 2).
//    • pipeline          — AsyncRead → ZSTD → шифратор → QUIC (итерация 2).
//
//  Author: SmartNet
// ============================================================
#![deny(clippy::unwrap_used)]

pub mod crypto;
pub mod network;
pub mod pipeline;

pub use crypto::{ChunkCipher, EphemeralKeyPair, Role, SessionKeys, Ticket};

/// ALPN-идентификатор протокола для iroh QUIC-соединений.
pub const ALPN: &[u8] = b"netdrop/1";

/// Собственные n1-реле SmartHoldem (дополняют дефолтные n0-реле iroh).
pub const RELAYS_N1: &[&str] = &["https://relay-fsn7.sth.cx", "https://relay-ru1.sth.cx"];
