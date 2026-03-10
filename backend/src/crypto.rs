use std::collections::HashMap;

use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha256;

use crate::types::Hops;
use crate::utils::{compute_sha256, key_generation, xor_bytes, GENERATION_NONCE, MIX_HEADER_SIZE};

type HmacSha256 = Hmac<Sha256>;

/// Compute shared secrets for all hops using ECDH
///
/// For each hop:
/// 1. SS_hop = H(ephemeral_private_key * Public_key_hop)
/// 2. blinding_factor = H(Public_key || SS_hop)
/// 3. next_ephemeral_private_key = ephemeral_private_key * blinding_factor
pub fn compute_shared_secrets(
    session_ephemeral_private_key: SecretKey,
    hops: &Vec<Hops>,
) -> Vec<[u8; 32]> {
    let secp = Secp256k1::new();
    let mut intermediate_ephemeral_pubkey = session_ephemeral_private_key.public_key(&secp);
    let mut intermediate_priv_key = session_ephemeral_private_key;
    let mut shared_secrets = Vec::with_capacity(hops.len());

    for hop in hops.iter() {
        // Parse hop's public key
        let mut intermediate_hop_pubkey_bytes = [0u8; 33];
        hex::decode_to_slice(&hop.pubkey, &mut intermediate_hop_pubkey_bytes)
            .expect("Failed to decode hop pubkey hex");
        let intermediate_pub_key =
            PublicKey::from_byte_array_compressed(intermediate_hop_pubkey_bytes)
                .expect("Failed to parse compressed public key");

        // Compute shared secret using ECDH
        let shared_secret_uncompressed =
            secp256k1::ecdh::shared_secret_point(&intermediate_pub_key, &intermediate_priv_key);

        // Compress the shared secret point
        let y_bytes = &shared_secret_uncompressed[33..64];
        let y_is_odd = (y_bytes[30] & 1) == 1;
        let mut compressed_public_key = [0u8; 33];
        compressed_public_key[0] = if y_is_odd { 0x03 } else { 0x02 };
        compressed_public_key[1..33].copy_from_slice(&shared_secret_uncompressed[0..32]);

        // Hash the compressed point to get the shared secret
        let shared_secret = compute_sha256(&compressed_public_key);
        shared_secrets.push(shared_secret);

        // Compute blinding factor: H(ephemeral_pubkey || shared_secret)
        let mut intermediate_bytes = Vec::with_capacity(33 + 32);
        intermediate_bytes.extend_from_slice(&intermediate_ephemeral_pubkey.serialize());
        intermediate_bytes.extend_from_slice(&shared_secret);
        let blinding_factor: [u8; 32] = compute_sha256(&intermediate_bytes);

        // Compute next ephemeral private key
        intermediate_priv_key = intermediate_priv_key
            .mul_tweak(&Scalar::from_be_bytes(blinding_factor).unwrap())
            .unwrap();

        // Compute next ephemeral public key
        intermediate_ephemeral_pubkey = intermediate_priv_key.public_key(&secp);
    }

    shared_secrets
}

/// Generate the initial mix header with pseudo-random padding
pub fn generate_initial_header(padding_key: &[u8; 32]) -> [u8; MIX_HEADER_SIZE] {
    let mut header = [0u8; MIX_HEADER_SIZE];
    let mut cipher = ChaCha20::new_from_slices(padding_key, &GENERATION_NONCE)
        .expect("Failed to create ChaCha20 cipher");
    cipher.apply_keystream(&mut header);
    header
}

/// Generate filler bytes to maintain constant packet size
///
/// The filler ensures that when intermediate nodes peel off their layer,
/// the packet maintains its structure and no information leaks about
/// the packet's position in the route.
pub fn generate_filler(hops: &Vec<Hops>, secrets: &Vec<[u8; 32]>) -> Vec<u8> {
    // Calculate total payload size and per-hop payload sizes
    let mut total_payload_size = 0u32;
    let mut hop_payload_map = HashMap::new();

    for (index, hop) in hops.iter().enumerate() {
        let hop_size = 32u32 + (hop.payload.len() / 2) as u32; // HMAC (32) + payload bytes
        total_payload_size += hop_size;
        hop_payload_map.insert(index, hop_size);
    }

    // Filler size excludes the last hop's payload
    let filler_size = total_payload_size - hop_payload_map.get(&(hops.len() - 1)).unwrap();
    let mut filler_array = vec![0u8; filler_size as usize];

    // Process all hops except the last one
    let mut stream_slice_start = MIX_HEADER_SIZE as u32;

    for (hop_num, _hop) in hops[0..hops.len() - 1].iter().enumerate() {
        let curr_hop_payload_size = hop_payload_map.get(&hop_num).unwrap().clone();
        let curr_hop_secret = secrets.get(hop_num).expect("Missing hop secret").clone();

        // Generate rho key for this hop
        let curr_hop_rho_key = key_generation("rho", &curr_hop_secret);

        // Generate the full cipher stream
        let mut full_cipher_stream = [0u8; 2600];
        let mut current_hop_stream =
            ChaCha20::new_from_slices(&curr_hop_rho_key, &GENERATION_NONCE)
                .expect("Failed to create ChaCha20 cipher");
        current_hop_stream.apply_keystream(&mut full_cipher_stream);

        // XOR the filler with the appropriate slice of the cipher stream
        let full_cipher_stream_xor_slice = &full_cipher_stream[stream_slice_start as usize
            ..(MIX_HEADER_SIZE as u32 + curr_hop_payload_size) as usize];
        filler_array = xor_bytes(&filler_array, full_cipher_stream_xor_slice);

        stream_slice_start -= curr_hop_payload_size;
    }

    filler_array
}

/// Compute HMAC for packet validation
pub fn compute_next_hmac(
    mu_key: &[u8; 32],
    curr_state_header: &[u8; MIX_HEADER_SIZE],
    associated_data: &[u8],
) -> [u8; 32] {
    let mut serialized_input = Vec::with_capacity(MIX_HEADER_SIZE + associated_data.len());
    serialized_input.extend_from_slice(curr_state_header);
    serialized_input.extend_from_slice(associated_data);

    let mut mac = HmacSha256::new_from_slice(mu_key).expect("Failed to create HMAC");
    mac.update(&serialized_input);

    mac.finalize()
        .into_bytes()
        .try_into()
        .expect("Failed to convert HMAC to array")
}

/// Generate ChaCha20 cipher stream for a given rho key
pub fn generate_cipher_stream(rho_key: &[u8; 32], size: usize) -> Vec<u8> {
    let mut stream = vec![0u8; size];
    let mut cipher = ChaCha20::new_from_slices(rho_key, &GENERATION_NONCE)
        .expect("Failed to create ChaCha20 cipher");
    cipher.apply_keystream(&mut stream);
    stream
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_initial_header() {
        let padding_key = [0x41u8; 32];
        let header = generate_initial_header(&padding_key);
        assert_eq!(header.len(), MIX_HEADER_SIZE);
        // Should not be all zeros after encryption
        assert!(header.iter().any(|&b| b != 0));
    }
}
