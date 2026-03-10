//! Web API module for onion packet construction
//! 
//! Provides REST API endpoints for the web UI to interact with
//! the Sphinx packet construction backend.

use axum::{
    extract::Json,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use secp256k1::{Secp256k1, SecretKey};

use crate::crypto::{
    compute_next_hmac, compute_shared_secrets, generate_cipher_stream,
    generate_filler, generate_initial_header,
};
use crate::types::{Hops, OnionPacket};
use crate::utils::{key_generation, right_shift, xor_bytes, MIX_HEADER_SIZE};

/// API request for building an onion packet
#[derive(Debug, Deserialize)]
pub struct BuildOnionRequest {
    pub session_key: String,
    pub associated_data: String,
    pub hops: Vec<HopRequest>,
}

#[derive(Debug, Deserialize)]
pub struct HopRequest {
    pub pubkey: String,
    pub payload: String,
}

/// Shared secret info for a single hop
#[derive(Debug, Serialize)]
pub struct SharedSecretInfo {
    pub hop_index: usize,
    pub hop_pubkey: String,
    pub shared_secret: String,
    pub rho_key: String,
    pub mu_key: String,
}

/// Layer construction step info
#[derive(Debug, Serialize)]
pub struct LayerStep {
    pub hop_index: usize,
    pub hop_pubkey: String,
    pub payload_size: usize,
    pub payload_hex: String,
    pub shared_secret: String,
    pub rho_key: String,
    pub mu_key: String,
    pub mix_header_before_shift: String,
    pub mix_header_after_shift: String,
    pub mix_header_after_payload: String,
    pub mix_header_after_xor: String,
    pub mix_header_final: String,
    pub computed_hmac: String,
    pub is_innermost: bool,
}

/// Complete response with all construction details
#[derive(Debug, Serialize)]
pub struct BuildOnionResponse {
    pub success: bool,
    pub error: Option<String>,
    
    // Input summary
    pub session_key: String,
    pub ephemeral_pubkey: String,
    pub associated_data: String,
    pub num_hops: usize,
    
    // Initial header
    pub padding_key: String,
    pub initial_header: String,
    
    // Shared secrets
    pub shared_secrets: Vec<SharedSecretInfo>,
    
    // Filler
    pub filler_size: usize,
    pub filler_hex: String,
    
    // Layer construction steps
    pub layers: Vec<LayerStep>,
    
    // Final packet
    pub final_packet: FinalPacketInfo,
}

#[derive(Debug, Serialize)]
pub struct FinalPacketInfo {
    pub version: String,
    pub ephemeral_pubkey: String,
    pub mix_header: String,
    pub hmac: String,
    pub full_packet_hex: String,
    pub total_size: usize,
}

/// Build onion packet with full visualization data
pub fn build_onion_with_details(request: &BuildOnionRequest) -> BuildOnionResponse {
    // Parse session key
    let mut private_key_bytes = [0u8; 32];
    if hex::decode_to_slice(&request.session_key, &mut private_key_bytes).is_err() {
        return error_response("Invalid session key hex");
    }
    
    let session_key = match SecretKey::from_byte_array(private_key_bytes) {
        Ok(sk) => sk,
        Err(_) => return error_response("Invalid session key"),
    };
    
    let associated_data = match hex::decode(&request.associated_data) {
        Ok(ad) => ad,
        Err(_) => return error_response("Invalid associated data hex"),
    };
    
    // Convert hops
    let hops: Vec<Hops> = request.hops.iter().map(|h| Hops {
        pubkey: h.pubkey.clone(),
        payload: h.payload.clone(),
    }).collect();
    
    let secp = Secp256k1::new();
    let ephemeral_pubkey = session_key.public_key(&secp);
    
    // Generate padding key and initial header
    let padding_key = key_generation("pad", &session_key.secret_bytes());
    let initial_header = generate_initial_header(&padding_key);
    
    // Compute shared secrets
    let hop_secrets = compute_shared_secrets(session_key, &hops);
    
    let shared_secrets: Vec<SharedSecretInfo> = hops.iter().zip(hop_secrets.iter()).enumerate()
        .map(|(i, (hop, secret))| SharedSecretInfo {
            hop_index: i,
            hop_pubkey: hop.pubkey.clone(),
            shared_secret: hex::encode(secret),
            rho_key: hex::encode(key_generation("rho", secret)),
            mu_key: hex::encode(key_generation("mu", secret)),
        }).collect();
    
    // Generate filler
    let filler = generate_filler(&hops, &hop_secrets);
    
    // Build layers with detailed tracking
    let mut mix_header = initial_header.clone();
    let mut next_hmac = [0u8; 32];
    let mut layers: Vec<LayerStep> = Vec::new();
    
    for (hop_num, hop) in hops.iter().rev().enumerate() {
        let actual_index = hops.len() - 1 - hop_num;
        let is_innermost = hop_num == 0;
        
        let mix_header_before_shift = hex::encode(&mix_header);
        
        let curr_shared_secret = &hop_secrets[actual_index];
        let curr_hop_rho_key = key_generation("rho", curr_shared_secret);
        let curr_hop_mu_key = key_generation("mu", curr_shared_secret);
        
        let payload_bytes = match hex::decode(&hop.payload) {
            Ok(p) => p,
            Err(_) => return error_response(&format!("Invalid payload hex at hop {}", actual_index)),
        };
        let payload_bytes_len = payload_bytes.len();
        let shift_key = 32 + payload_bytes_len;
        
        // Right shift
        right_shift(&mut mix_header, shift_key);
        for i in 0..shift_key {
            mix_header[i] = 0u8;
        }
        let mix_header_after_shift = hex::encode(&mix_header);
        
        // Insert payload and HMAC
        let mut serialized_field = Vec::new();
        serialized_field.extend_from_slice(&payload_bytes);
        serialized_field.extend_from_slice(&next_hmac);
        mix_header[..serialized_field.len()].copy_from_slice(&serialized_field);
        let mix_header_after_payload = hex::encode(&mix_header);
        
        // XOR with cipher stream
        let cipher_stream = generate_cipher_stream(&curr_hop_rho_key, MIX_HEADER_SIZE);
        mix_header = xor_bytes(&mix_header, &cipher_stream).try_into().unwrap();
        let mix_header_after_xor = hex::encode(&mix_header);
        
        // Add filler for innermost layer
        if is_innermost {
            let start = mix_header.len() - filler.len();
            mix_header[start..].copy_from_slice(&filler);
        }
        let mix_header_final = hex::encode(&mix_header);
        
        // Compute HMAC
        next_hmac = compute_next_hmac(&curr_hop_mu_key, &mix_header, &associated_data);
        
        layers.push(LayerStep {
            hop_index: actual_index,
            hop_pubkey: hop.pubkey.clone(),
            payload_size: payload_bytes_len,
            payload_hex: hop.payload.clone(),
            shared_secret: hex::encode(curr_shared_secret),
            rho_key: hex::encode(curr_hop_rho_key),
            mu_key: hex::encode(curr_hop_mu_key),
            mix_header_before_shift,
            mix_header_after_shift,
            mix_header_after_payload,
            mix_header_after_xor,
            mix_header_final,
            computed_hmac: hex::encode(next_hmac),
            is_innermost,
        });
    }
    
    // Create final packet
    let packet = OnionPacket::new(0x00, ephemeral_pubkey.serialize(), mix_header, next_hmac);
    
    BuildOnionResponse {
        success: true,
        error: None,
        session_key: request.session_key.clone(),
        ephemeral_pubkey: hex::encode(ephemeral_pubkey.serialize()),
        associated_data: request.associated_data.clone(),
        num_hops: hops.len(),
        padding_key: hex::encode(padding_key),
        initial_header: hex::encode(initial_header),
        shared_secrets,
        filler_size: filler.len(),
        filler_hex: hex::encode(&filler),
        layers,
        final_packet: FinalPacketInfo {
            version: "00".to_string(),
            ephemeral_pubkey: hex::encode(packet.ephemeral_pubkey),
            mix_header: hex::encode(packet.mix_header),
            hmac: hex::encode(packet.hmac),
            full_packet_hex: packet.to_hex(),
            total_size: 1366,
        },
    }
}

fn error_response(msg: &str) -> BuildOnionResponse {
    BuildOnionResponse {
        success: false,
        error: Some(msg.to_string()),
        session_key: String::new(),
        ephemeral_pubkey: String::new(),
        associated_data: String::new(),
        num_hops: 0,
        padding_key: String::new(),
        initial_header: String::new(),
        shared_secrets: vec![],
        filler_size: 0,
        filler_hex: String::new(),
        layers: vec![],
        final_packet: FinalPacketInfo {
            version: String::new(),
            ephemeral_pubkey: String::new(),
            mix_header: String::new(),
            hmac: String::new(),
            full_packet_hex: String::new(),
            total_size: 0,
        },
    }
}

/// API handler: Build onion packet
async fn api_build_onion(Json(request): Json<BuildOnionRequest>) -> impl IntoResponse {
    let response = build_onion_with_details(&request);
    Json(response)
}

/// API handler: Health check
async fn api_health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "lightning-onion-builder"
    }))
}

/// API handler: Get example input
async fn api_example() -> impl IntoResponse {
    Json(serde_json::json!({
        "session_key": "4141414141414141414141414141414141414141414141414141414141414141",
        "associated_data": "4242424242424242424242424242424242424242424242424242424242424242",
        "hops": [
            {
                "pubkey": "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
                "payload": "1202023a98040205dc06080000000000000001"
            },
            {
                "pubkey": "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
                "payload": "52020236b00402057806080000000000000002fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f"
            },
            {
                "pubkey": "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007",
                "payload": "12020230d4040204e206080000000000000003"
            },
            {
                "pubkey": "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
                "payload": "1202022710040203e806080000000000000004"
            },
            {
                "pubkey": "02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145",
                "payload": "fd011002022710040203e8082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
            }
        ]
    }))
}

/// Create the API router
pub fn create_api_router() -> Router {
    Router::new()
        .route("/api/health", get(api_health))
        .route("/api/example", get(api_example))
        .route("/api/build", post(api_build_onion))
}
