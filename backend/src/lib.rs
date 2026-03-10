//! Lightning Onion Builder
//!
//! A Rust implementation of the Sphinx packet format for Lightning Network
//! onion routing with visualization capabilities.
//!
//! # Modules
//!
//! - `types`: Data structures for onion packets and hops
//! - `utils`: Utility functions for cryptographic operations
//! - `crypto`: Core cryptographic primitives (ECDH, ChaCha20, HMAC)
//! - `api`: Web API endpoints for the web UI

pub mod api;
pub mod crypto;
pub mod types;
pub mod utils;

pub use api::{create_api_router, BuildOnionRequest, BuildOnionResponse};
pub use types::{Hops, InputData, OnionPacket};
