//! Lightning Onion Packet Builder
//!
//! Implementation of Sphinx onion routing for Lightning Network payments.
//! Web server for visual packet construction.
//!
//! ## Usage
//!
//! ```bash
//! cargo run -- --web [--port 3000]
//! ```

#![allow(unused)]

mod api;
mod crypto;
mod types;
mod utils;

use std::{env, net::SocketAddr, path::PathBuf};

use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use api::create_api_router;

/// Print help message
fn print_help() {
    println!("Lightning Onion Packet Builder - Web Server");
    println!();
    println!("USAGE:");
    println!("    backend --web [--port PORT]");
    println!();
    println!("OPTIONS:");
    println!("    --web           Start web server with visual UI (required)");
    println!("    --port PORT     Port for web server (default: 3000)");
    println!("    --help, -h      Show this help message");
    println!();
    println!("EXAMPLES:");
    println!("    backend --web");
    println!("    backend --web --port 8080");
}

/// Start the web server
async fn start_web_server(port: u16) {
    let static_dir = get_static_dir();

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .merge(create_api_router())
        .nest_service("/", ServeDir::new(&static_dir))
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    println!("Lightning Onion Packet Visualizer");
    println!("==================================");
    println!();
    println!("Web UI available at:");
    println!("   http://localhost:{}", port);
    println!("   http://127.0.0.1:{}", port);
    println!();
    println!("API endpoints:");
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
    let paths = [
        PathBuf::from("frontend/dist"),
        PathBuf::from("../frontend/dist"),
        PathBuf::from("static"),
    ];

    for path in &paths {
        if path.exists() && path.is_dir() {
            return path.clone();
        }
    }

    if let Ok(exe_path) = env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let dist_path = exe_dir.join("frontend/dist");
            if dist_path.exists() {
                return dist_path;
            }
        }
    }

    PathBuf::from("frontend/dist")
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    if args.iter().any(|a| a == "--web") {
        let port = args
            .iter()
            .position(|a| a == "--port")
            .and_then(|i| args.get(i + 1))
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(3000);

        start_web_server(port).await;
        return;
    }

    print_help();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::InputData;
    use secp256k1::SecretKey;

    #[test]
    fn test_input_parsing() {
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

        assert_eq!(input_data.hops.len(), 1);
        assert_eq!(session_key.secret_bytes().len(), 32);
    }
}
