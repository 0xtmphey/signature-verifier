//! # signature-verifier
//!
//! Convenience crate for verifying crypto-signed messages.
//!
//! Currently supports Ethereum- and Solana-signed messages.

mod signature_verifier;
pub use signature_verifier::SignatureVerifier;

pub mod error;

#[cfg(feature = "ethereum")]
pub mod ethereum;

#[cfg(feature = "solana")]
pub mod solana;
