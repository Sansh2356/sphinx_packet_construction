use serde::{Deserialize, Serialize};

/// Represents a single hop in the onion route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hops {
    pub pubkey: String,
    pub payload: String,
}

/// Input data structure for onion packet construction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputData {
    pub session_key: String,
    pub associated_data: String,
    pub hops: Vec<Hops>,
}

/// Represents a constructed onion packet with all its components
#[derive(Debug, Clone)]
pub struct OnionPacket {
    pub version: u8,
    pub ephemeral_pubkey: [u8; 33],
    pub mix_header: [u8; 1300],
    pub hmac: [u8; 32],
}

impl OnionPacket {
    pub fn new(version: u8, ephemeral_pubkey: [u8; 33], mix_header: [u8; 1300], hmac: [u8; 32]) -> Self {
        Self {
            version,
            ephemeral_pubkey,
            mix_header,
            hmac,
        }
    }

    /// Serialize the onion packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + 33 + 1300 + 32);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.ephemeral_pubkey);
        bytes.extend_from_slice(&self.mix_header);
        bytes.extend_from_slice(&self.hmac);
        bytes
    }

    /// Serialize the onion packet to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

/// Represents intermediate state during onion construction (for visualization)
#[derive(Debug, Clone)]
pub struct OnionLayerState {
    pub hop_index: usize,
    pub hop_pubkey: String,
    pub shared_secret: [u8; 32],
    pub rho_key: [u8; 32],
    pub mu_key: [u8; 32],
    pub payload_size: usize,
    pub mix_header_before_shift: Option<Vec<u8>>,
    pub mix_header_after_shift: Option<Vec<u8>>,
    pub mix_header_after_payload: Option<Vec<u8>>,
    pub mix_header_after_xor: Option<Vec<u8>>,
    pub mix_header_after_filler: Option<Vec<u8>>,
    pub computed_hmac: [u8; 32],
}

impl OnionLayerState {
    pub fn new(hop_index: usize, hop_pubkey: String) -> Self {
        Self {
            hop_index,
            hop_pubkey,
            shared_secret: [0u8; 32],
            rho_key: [0u8; 32],
            mu_key: [0u8; 32],
            payload_size: 0,
            mix_header_before_shift: None,
            mix_header_after_shift: None,
            mix_header_after_payload: None,
            mix_header_after_xor: None,
            mix_header_after_filler: None,
            computed_hmac: [0u8; 32],
        }
    }
}
