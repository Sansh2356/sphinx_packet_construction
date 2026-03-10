//! Lightning Onion Packet Builder
//! 
//! Implementation of Sphinx onion routing for Lightning Network payments.
//! Supports both standard packet construction and visual step-by-step construction.
//!
//! ## Usage
//! 
//! Standard mode (quiet):
//! ```bash
//! cargo run -- <output_dir> <input.json>
//! ```
//!
//! Visualization mode:
//! ```bash
//! cargo run -- <output_dir> <input.json> --visualize
//! ```
//!
//! Web UI mode:
//! ```bash
//! cargo run -- --web [--port 3000]
//! ```

#![allow(unused)]

mod types;
mod utils;
mod crypto;
mod visualizer;
mod api;

use std::{
    env,
    error::Error,
    fs::{self, File},
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use axum::Router;
use chacha20::{ChaCha20, cipher::{KeyIvInit, StreamCipher}};
use secp256k1::{Secp256k1, SecretKey};
use tower_http::services::ServeDir;
use tower_http::cors::{Any, CorsLayer};

use types::{Hops, InputData, OnionPacket};
use crypto::{compute_shared_secrets, generate_filler, generate_initial_header, compute_next_hmac};
use utils::{key_generation, right_shift, xor_bytes, MIX_HEADER_SIZE, GENERATION_NONCE};
use visualizer::{OnionVisualizer, VisualizerConfig};
use api::create_api_router;

/// Read input JSON from file
fn read_json_from_file<P: AsRef<Path>>(path: P) -> Result<InputData, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let input_data = serde_json::from_reader(reader)?;
    Ok(input_data)
}

/// Build onion packet silently (original behavior)
fn build_onion_packet_quiet(
    session_key: &SecretKey,
    input_data: &InputData,
) -> OnionPacket {
    let associated_data = hex::decode(&input_data.associated_data).unwrap();
    let padding_key = key_generation("pad", &session_key.secret_bytes());
    let mut mix_header = generate_initial_header(&padding_key);
    
    let hop_secrets = compute_shared_secrets(*session_key, &input_data.hops);
    let filler = generate_filler(&input_data.hops, &hop_secrets);
    
    let mut next_hmac = [0u8; 32];
    
    for (hop_num, hop) in input_data.hops.iter().rev().enumerate() {
        let actual_index = input_data.hops.len() - 1 - hop_num;
        let curr_shared_secret = hop_secrets.get(actual_index).unwrap();
        
        let curr_hop_rho_key = key_generation("rho", curr_shared_secret);
        let curr_hop_mu_key = key_generation("mu", curr_shared_secret);
        
        let payload_bytes_len = hop.payload.len() / 2;
        let shift_key = 32 + payload_bytes_len;
        
        // Right shift to make room for payload + HMAC
        right_shift(&mut mix_header, shift_key);
        for i in 0..shift_key {
            mix_header[i] = 0u8;
        }
        
        // Insert payload and previous HMAC
        let mut serialized_field = Vec::new();
        serialized_field.extend_from_slice(&hex::decode(&hop.payload).unwrap());
        serialized_field.extend_from_slice(&next_hmac);
        mix_header[..serialized_field.len()].copy_from_slice(&serialized_field);
        
        // Encrypt with ChaCha20
        let mut cipher_stream = [0u8; MIX_HEADER_SIZE];
        let mut current_hop_stream = ChaCha20::new_from_slices(&curr_hop_rho_key, &GENERATION_NONCE)
            .expect("Failed to create cipher");
        current_hop_stream.apply_keystream(&mut cipher_stream);
        
        mix_header = xor_bytes(&mix_header, &cipher_stream).try_into().unwrap();
        
        // Add filler for innermost layer (last hop, which we process first)
        if hop_num == 0 {
            let start = mix_header.len() - filler.len();
            mix_header[start..].copy_from_slice(&filler);
        }
        
        // Compute HMAC for next iteration
        next_hmac = compute_next_hmac(&curr_hop_mu_key, &mix_header, &associated_data);
    }
    
    let ephemeral_pubkey = session_key.public_key(&Secp256k1::new()).serialize();
    OnionPacket::new(0x00, ephemeral_pubkey, mix_header, next_hmac)
}

/// Print help message
fn print_help() {
    println!("Lightning Onion Packet Builder");
    println!();
    println!("USAGE:");
    println!("    submissions <output_dir> <input.json> [OPTIONS]");
    println!("    submissions --web [--port PORT]");
    println!();
    println!("MODES:");
    println!("    CLI Mode:     Build onion packet from JSON input file");
    println!("    Web Mode:     Start web server with visual UI");
    println!();
    println!("OPTIONS:");
    println!("    --web           Start web server with visual UI (default port: 3000)");
    println!("    --port PORT     Port for web server (default: 3000)");
    println!("    --visualize     Show step-by-step visualization in terminal");
    println!("    --verbose       Show detailed intermediate values");
    println!("    --no-color      Disable colored output");
    println!("    --help, -h      Show this help message");
    println!();
    println!("EXAMPLES:");
    println!("    submissions ./output ./input.json");
    println!("    submissions ./output ./input.json --visualize");
    println!("    submissions --web");
    println!("    submissions --web --port 8080");
}

/// Start the web server
async fn start_web_server(port: u16) {
    // Get the static files directory
    let static_dir = get_static_dir();
    
    // Build CORS layer
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    
    // Build the router
    let app = Router::new()
        .merge(create_api_router())
        .nest_service("/", ServeDir::new(&static_dir))
        .layer(cors);
    
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    
    println!("🧅 Lightning Onion Packet Visualizer");
    println!("════════════════════════════════════");
    println!();
    println!("🌐 Web UI available at:");
    println!("   http://localhost:{}", port);
    println!("   http://127.0.0.1:{}", port);
    println!();
    println!("📡 API endpoints:");
    println!("   GET  /api/health   - Health check");
    println!("   GET  /api/example  - Get example input");
    println!("   POST /api/build    - Build onion packet");
    println!();
    println!("Press Ctrl+C to stop the server");
    println!();
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Find the static files directory (React build output)
fn get_static_dir() -> PathBuf {
    // Try relative to current directory
    let paths = [
        PathBuf::from("frontend/dist"),
        PathBuf::from("submissions/frontend/dist"),
        PathBuf::from("../frontend/dist"),
        // Fallback to old static paths
        PathBuf::from("static"),
        PathBuf::from("submissions/static"),
    ];
    
    for path in &paths {
        if path.exists() && path.is_dir() {
            return path.clone();
        }
    }
    
    // Try relative to executable
    if let Ok(exe_path) = env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let dist_path = exe_dir.join("frontend/dist");
            if dist_path.exists() {
                return dist_path;
            }
        }
    }
    
    // Default fallback
    PathBuf::from("frontend/dist")
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    
    // Check for help flag
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }
    
    // Check for web mode
    if args.iter().any(|a| a == "--web") {
        let port = args.iter()
            .position(|a| a == "--port")
            .and_then(|i| args.get(i + 1))
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(3000);
        
        start_web_server(port).await;
        return;
    }
    
    // CLI mode - parse arguments
    let mut output_path: Option<String> = None;
    let mut input_path: Option<String> = None;
    let mut visualize = false;
    let mut verbose = false;
    let mut use_colors = true;
    
    let mut positional_idx = 0;
    let mut skip_next = false;
    
    for (i, arg) in args.iter().skip(1).enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        
        match arg.as_str() {
            "--visualize" => visualize = true,
            "--verbose" => verbose = true,
            "--no-color" => use_colors = false,
            "--port" => skip_next = true,
            _ if !arg.starts_with("--") => {
                if positional_idx == 0 {
                    output_path = Some(arg.clone());
                    positional_idx += 1;
                } else if positional_idx == 1 {
                    input_path = Some(arg.clone());
                    positional_idx += 1;
                }
            }
            _ => {}
        }
    }
    
    let output_path = output_path.expect("Output path not provided. Use --help for usage.");
    let input_path = input_path.expect("Input path not provided. Use --help for usage.");
    
    // Read input data
    let input_data = read_json_from_file(Path::new(&input_path))
        .expect("Failed to parse input JSON");
    
    // Parse session key
    let mut private_key = [0u8; 32];
    hex::decode_to_slice(&input_data.session_key, &mut private_key)
        .expect("Failed to decode session key");
    let session_key = SecretKey::from_byte_array(private_key)
        .expect("Invalid session key");
    
    // Build onion packet (with or without visualization)
    let packet = if visualize {
        let associated_data = hex::decode(&input_data.associated_data).unwrap();
        
        let config = VisualizerConfig {
            show_hex_values: true,
            hex_truncate_len: if verbose { 64 } else { 32 },
            use_colors,
            show_intermediate_states: true,
            verbose,
        };
        
        let mut visualizer = OnionVisualizer::new(config);
        let packet = visualizer.build_and_visualize(&session_key, &input_data.hops, &associated_data);
        
        // Print wire format if verbose
        if verbose {
            visualizer.print_wire_format(&packet);
        }
        
        packet
    } else {
        build_onion_packet_quiet(&session_key, &input_data)
    };
    
    // Write output
    let output_file_path = Path::new(&output_path).join("output.txt");
    fs::write(&output_file_path, packet.to_hex())
        .expect("Failed to write output file");
    
    if !visualize {
        println!("Onion packet written to: {}", output_file_path.display());
    } else {
        println!("\n📁 Output written to: {}", output_file_path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_build_onion_packet() {
        let input_json = r#"{
            "session_key": "4141414141414141414141414141414141414141414141414141414141414141",
            "associated_data": "4242424242424242424242424242424242424242424242424242424242424242",
            "hops": [
                {
                    "pubkey": "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
                    "payload": "1202023a98040205dc06080000000000000001"
                }
            ]
        }"#;
        
        let input_data: InputData = serde_json::from_str(input_json).unwrap();
        let mut private_key = [0u8; 32];
        hex::decode_to_slice(&input_data.session_key, &mut private_key).unwrap();
        let session_key = SecretKey::from_byte_array(private_key).unwrap();
        
        let packet = build_onion_packet_quiet(&session_key, &input_data);
        
        // Verify packet structure
        assert_eq!(packet.version, 0x00);
        assert_eq!(packet.ephemeral_pubkey.len(), 33);
        assert_eq!(packet.mix_header.len(), 1300);
        assert_eq!(packet.hmac.len(), 32);
    }
}
