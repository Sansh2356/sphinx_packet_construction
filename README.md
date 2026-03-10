# Lightning Onion Packet Visualizer

A visual tool for understanding Sphinx onion packet construction used in the Lightning Network.

## Overview

This application demonstrates how Lightning Network onion packets are built layer by layer using the Sphinx protocol. It provides:

- **Interactive packet builder** - Configure session keys, associated data, and multiple hops
- **Step-by-step visualization** - See how each layer wraps the previous with encryption
- **Flow diagram** - React Flow-based graphical representation of packet construction
- **Shared secrets display** - View ECDH shared secrets and derived keys (rho, mu)
- **Final packet output** - Copy the complete 1366-byte onion packet

## Project Structure

```
sphinx_packet_visualizer/
├── backend/          # Rust backend server
│   ├── src/
│   │   ├── main.rs       # Entry point, web server
│   │   ├── api.rs        # REST API endpoints
│   │   ├── crypto.rs     # Cryptographic operations
│   │   ├── types.rs      # Data structures
│   │   └── utils.rs      # Helper functions
│   └── Cargo.toml
├── frontend/         # React frontend
│   ├── src/
│   │   ├── components/   # React components
│   │   │   ├── FlowVisualization.jsx
│   │   │   ├── LayerVisualization.jsx
│   │   │   ├── SharedSecrets.jsx
│   │   │   └── ...
│   │   └── styles/
│   └── package.json
└── test/             # Test inputs
```

## Requirements

### Backend
- Rust 1.70+ (edition 2021)
- Cargo

### Frontend
- Node.js 18+
- npm

## Installation

### Backend

```bash
cd backend
cargo build --release
```

### Frontend

```bash
cd frontend
npm install
```

## Running the Application

### Start the backend server

```bash
cd backend
cargo run -- --web --port 3000
```

The API will be available at `http://localhost:3000`

### Start the frontend development server

```bash
cd frontend
npm run dev
```

The UI will be available at `http://localhost:5173`

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/example` | GET | Get example input data |
| `/api/build` | POST | Build onion packet with visualization data |

### Build Request Example

```json
{
  "session_key": "4141414141414141414141414141414141414141414141414141414141414141",
  "associated_data": "4242424242424242424242424242424242424242424242424242424242424242",
  "hops": [
    {
      "pubkey": "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
      "payload": "1202023a98040205dc06080000000000000001"
    }
  ]
}
```

## Technical Details

### Cryptographic Primitives

- **ECDH**: secp256k1 elliptic curve for shared secret derivation
- **Key Derivation**: HMAC-SHA256 for generating rho/mu keys
- **Stream Cipher**: ChaCha20 for mix header encryption
- **Authentication**: HMAC-SHA256 for packet integrity

### Packet Structure (1366 bytes)

| Field | Size | Description |
|-------|------|-------------|
| Version | 1 byte | Packet version (0x00) |
| Ephemeral Public Key | 33 bytes | Session public key |
| Mix Header | 1300 bytes | Encrypted routing information |
| HMAC | 32 bytes | Authentication tag |

## License

GPL-3.0
