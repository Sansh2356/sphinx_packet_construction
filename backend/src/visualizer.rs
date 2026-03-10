//! Onion Packet Visualizer
//! 
//! Provides visual representations of the Sphinx packet construction process,
//! showing each layer as it's wrapped around the inner payload.

use secp256k1::{Secp256k1, SecretKey};

use crate::crypto::{
    compute_next_hmac, compute_shared_secrets, generate_cipher_stream,
    generate_filler, generate_initial_header,
};
use crate::types::{Hops, OnionLayerState, OnionPacket};
use crate::utils::{key_generation, right_shift, truncate_hex, xor_bytes, MIX_HEADER_SIZE};

/// ANSI color codes for terminal output
pub mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
    
    pub const BG_BLUE: &str = "\x1b[44m";
    pub const BG_GREEN: &str = "\x1b[42m";
    pub const BG_YELLOW: &str = "\x1b[43m";
    pub const BG_MAGENTA: &str = "\x1b[45m";
}

/// Configuration for the visualizer
pub struct VisualizerConfig {
    pub show_hex_values: bool,
    pub hex_truncate_len: usize,
    pub use_colors: bool,
    pub show_intermediate_states: bool,
    pub verbose: bool,
}

impl Default for VisualizerConfig {
    fn default() -> Self {
        Self {
            show_hex_values: true,
            hex_truncate_len: 32,
            use_colors: true,
            show_intermediate_states: true,
            verbose: false,
        }
    }
}

/// Sphinx Onion Packet Visualizer
pub struct OnionVisualizer {
    config: VisualizerConfig,
    layer_states: Vec<OnionLayerState>,
}

impl OnionVisualizer {
    pub fn new(config: VisualizerConfig) -> Self {
        Self {
            config,
            layer_states: Vec::new(),
        }
    }

    /// Build and visualize onion packet construction
    pub fn build_and_visualize(
        &mut self,
        session_key: &SecretKey,
        hops: &Vec<Hops>,
        associated_data: &[u8],
    ) -> OnionPacket {
        self.print_header();
        self.print_input_summary(session_key, hops, associated_data);
        
        // Step 1: Generate padding key and initial header
        let padding_key = key_generation("pad", &session_key.secret_bytes());
        let mut mix_header = generate_initial_header(&padding_key);
        self.print_initial_header_generation(&padding_key, &mix_header);
        
        // Step 2: Compute shared secrets
        let hop_secrets = compute_shared_secrets(*session_key, hops);
        self.print_shared_secrets_generation(hops, &hop_secrets);
        
        // Step 3: Generate filler
        let filler = generate_filler(hops, &hop_secrets);
        self.print_filler_generation(&filler);
        
        // Step 4: Build layers (reverse order)
        let mut next_hmac = [0u8; 32];
        self.print_layer_construction_header();
        
        for (hop_num, hop) in hops.iter().rev().enumerate() {
            let actual_hop_index = hops.len() - 1 - hop_num;
            let mut layer_state = OnionLayerState::new(actual_hop_index, hop.pubkey.clone());
            
            layer_state.mix_header_before_shift = Some(mix_header.to_vec());
            
            let curr_shared_secret = hop_secrets.get(actual_hop_index).unwrap();
            layer_state.shared_secret = *curr_shared_secret;
            
            let curr_hop_rho_key = key_generation("rho", curr_shared_secret);
            let curr_hop_mu_key = key_generation("mu", curr_shared_secret);
            layer_state.rho_key = curr_hop_rho_key;
            layer_state.mu_key = curr_hop_mu_key;
            
            // Calculate shift
            let payload_bytes_len = hop.payload.len() / 2;
            let shift_key = 32 + payload_bytes_len;
            layer_state.payload_size = payload_bytes_len;
            
            // Right shift
            right_shift(&mut mix_header, shift_key);
            for i in 0..shift_key {
                mix_header[i] = 0u8;
            }
            layer_state.mix_header_after_shift = Some(mix_header.to_vec());
            
            // Insert payload and HMAC
            let mut serialized_field = Vec::new();
            serialized_field.extend_from_slice(&hex::decode(&hop.payload).unwrap());
            serialized_field.extend_from_slice(&next_hmac);
            mix_header[..serialized_field.len()].copy_from_slice(&serialized_field);
            layer_state.mix_header_after_payload = Some(mix_header.to_vec());
            
            // Apply XOR obfuscation
            let cipher_stream = generate_cipher_stream(&curr_hop_rho_key, MIX_HEADER_SIZE);
            mix_header = xor_bytes(&mix_header, &cipher_stream).try_into().unwrap();
            layer_state.mix_header_after_xor = Some(mix_header.to_vec());
            
            // Add filler for last hop (first in reverse order)
            if hop_num == 0 {
                let start = mix_header.len() - filler.len();
                mix_header[start..].copy_from_slice(&filler);
            }
            layer_state.mix_header_after_filler = Some(mix_header.to_vec());
            
            // Compute HMAC
            next_hmac = compute_next_hmac(&curr_hop_mu_key, &mix_header, associated_data);
            layer_state.computed_hmac = next_hmac;
            
            self.print_layer_construction(&layer_state, hop_num == 0);
            self.layer_states.push(layer_state);
        }
        
        // Create final packet
        let ephemeral_pubkey = session_key.public_key(&Secp256k1::new()).serialize();
        let packet = OnionPacket::new(0x00, ephemeral_pubkey, mix_header, next_hmac);
        
        self.print_final_packet(&packet);
        self.print_packet_structure_diagram(&packet);
        
        packet
    }

    fn print_header(&self) {
        if self.config.use_colors {
            println!("\n{}{}╔══════════════════════════════════════════════════════════════════╗{}",
                     colors::BOLD, colors::CYAN, colors::RESET);
            println!("{}{}║           🧅 SPHINX ONION PACKET VISUALIZER 🧅                   ║{}",
                     colors::BOLD, colors::CYAN, colors::RESET);
            println!("{}{}╚══════════════════════════════════════════════════════════════════╝{}",
                     colors::BOLD, colors::CYAN, colors::RESET);
        } else {
            println!("\n╔══════════════════════════════════════════════════════════════════╗");
            println!("║           SPHINX ONION PACKET VISUALIZER                         ║");
            println!("╚══════════════════════════════════════════════════════════════════╝");
        }
    }

    fn print_input_summary(&self, session_key: &SecretKey, hops: &Vec<Hops>, associated_data: &[u8]) {
        let c = if self.config.use_colors { colors::YELLOW } else { "" };
        let r = if self.config.use_colors { colors::RESET } else { "" };
        let b = if self.config.use_colors { colors::BOLD } else { "" };
        
        println!("\n{}{}📥 INPUT SUMMARY{}", b, c, r);
        println!("{}├─ Session Key: {}{}",
                 c, truncate_hex(&hex::encode(session_key.secret_bytes()), self.config.hex_truncate_len), r);
        println!("{}├─ Associated Data: {}{}",
                 c, truncate_hex(&hex::encode(associated_data), self.config.hex_truncate_len), r);
        println!("{}└─ Number of Hops: {}{}", c, hops.len(), r);
        
        println!("\n{}{}🛤️  ROUTE PATH:{}", b, c, r);
        for (i, hop) in hops.iter().enumerate() {
            let arrow = if i < hops.len() - 1 { "├─►" } else { "└─►" };
            let hop_type = if i == 0 { "(Entry)" } 
                          else if i == hops.len() - 1 { "(Exit)" } 
                          else { "(Relay)" };
            println!("{}  {} Hop {}: {} {}{}",
                     c, arrow, i + 1, truncate_hex(&hop.pubkey, 20), hop_type, r);
        }
    }

    fn print_initial_header_generation(&self, padding_key: &[u8; 32], header: &[u8; MIX_HEADER_SIZE]) {
        let c = if self.config.use_colors { colors::GREEN } else { "" };
        let r = if self.config.use_colors { colors::RESET } else { "" };
        let b = if self.config.use_colors { colors::BOLD } else { "" };
        
        println!("\n{}{}🔐 INITIAL HEADER GENERATION{}", b, c, r);
        println!("{}├─ Padding Key (from 'pad' + session_key):", c);
        println!("{}│    {}{}", c, truncate_hex(&hex::encode(padding_key), 64), r);
        println!("{}└─ Initial Header (1300 bytes of ChaCha20 stream):", c);
        println!("{}     {}{}", c, truncate_hex(&hex::encode(header), 64), r);
    }

    fn print_shared_secrets_generation(&self, hops: &Vec<Hops>, secrets: &Vec<[u8; 32]>) {
        let c = if self.config.use_colors { colors::MAGENTA } else { "" };
        let r = if self.config.use_colors { colors::RESET } else { "" };
        let b = if self.config.use_colors { colors::BOLD } else { "" };
        
        println!("\n{}{}🤝 SHARED SECRETS (ECDH){}", b, c, r);
        println!("{}Formula: SS = SHA256(ECDH(ephemeral_privkey, hop_pubkey)){}", c, r);
        
        for (i, (hop, secret)) in hops.iter().zip(secrets.iter()).enumerate() {
            let connector = if i < hops.len() - 1 { "├" } else { "└" };
            println!("{}{}─ Hop {}: {}{}", c, connector, i + 1, truncate_hex(&hex::encode(secret), 64), r);
            if self.config.verbose {
                println!("{}│    Pubkey: {}{}", c, truncate_hex(&hop.pubkey, 40), r);
            }
        }
    }

    fn print_filler_generation(&self, filler: &[u8]) {
        let c = if self.config.use_colors { colors::BLUE } else { "" };
        let r = if self.config.use_colors { colors::RESET } else { "" };
        let b = if self.config.use_colors { colors::BOLD } else { "" };
        
        println!("\n{}{}🧱 FILLER GENERATION{}", b, c, r);
        println!("{}├─ Purpose: Maintains constant packet size during peeling{}", c, r);
        println!("{}├─ Filler Size: {} bytes{}", c, filler.len(), r);
        println!("{}└─ Filler Data: {}{}", c, truncate_hex(&hex::encode(filler), 64), r);
    }

    fn print_layer_construction_header(&self) {
        let c = if self.config.use_colors { colors::RED } else { "" };
        let r = if self.config.use_colors { colors::RESET } else { "" };
        let b = if self.config.use_colors { colors::BOLD } else { "" };
        
        println!("\n{}{}🧅 LAYER-BY-LAYER CONSTRUCTION (Inside → Out){}", b, c, r);
        println!("{}═══════════════════════════════════════════════════════════════════{}", c, r);
    }

    fn print_layer_construction(&self, state: &OnionLayerState, is_innermost: bool) {
        let c = if self.config.use_colors { colors::WHITE } else { "" };
        let r = if self.config.use_colors { colors::RESET } else { "" };
        let b = if self.config.use_colors { colors::BOLD } else { "" };
        let layer_color = match state.hop_index % 4 {
            0 => if self.config.use_colors { colors::RED } else { "" },
            1 => if self.config.use_colors { colors::GREEN } else { "" },
            2 => if self.config.use_colors { colors::YELLOW } else { "" },
            _ => if self.config.use_colors { colors::CYAN } else { "" },
        };
        
        let layer_label = if is_innermost { "🎯 INNERMOST" } else { "📦 LAYER" };
        
        println!("\n{}{}┌─────────────────────────────────────────────────────────────────┐{}", layer_color, b, r);
        println!("{}{}│  {} - Hop {} (Index: {})                                          │{}", layer_color, b, layer_label, state.hop_index + 1, state.hop_index, r);
        println!("{}{}└─────────────────────────────────────────────────────────────────┘{}", layer_color, b, r);
        
        println!("{}├─ Hop Pubkey: {}{}", c, truncate_hex(&state.hop_pubkey, 50), r);
        println!("{}├─ Shared Secret: {}{}", c, hex::encode(state.shared_secret), r);
        println!("{}├─ Rho Key (for encryption): {}{}", c, truncate_hex(&hex::encode(state.rho_key), 40), r);
        println!("{}├─ Mu Key (for HMAC): {}{}", c, truncate_hex(&hex::encode(state.mu_key), 40), r);
        println!("{}├─ Payload Size: {} bytes{}", c, state.payload_size, r);
        
        if self.config.show_intermediate_states {
            self.print_layer_transformation(state, is_innermost);
        }
        
        println!("{}└─ Computed HMAC: {}{}", c, hex::encode(state.computed_hmac), r);
    }

    fn print_layer_transformation(&self, _state: &OnionLayerState, is_innermost: bool) {
        let c = if self.config.use_colors { colors::DIM } else { "" };
        let r = if self.config.use_colors { colors::RESET } else { "" };
        
        println!("{}│{}", c, r);
        println!("{}│  📊 TRANSFORMATION STEPS:{}", c, r);
        
        // Visual representation of the mix header transformation
        println!("{}│{}", c, r);
        println!("{}│     ┌──────────────────────────────────────┐{}", c, r);
        println!("{}│     │      Before Right Shift              │{}", c, r);
        println!("{}│     │  [...previous encrypted data...]     │{}", c, r);
        println!("{}│     └──────────────────────────────────────┘{}", c, r);
        println!("{}│                      │{}", c, r);
        println!("{}│                      ▼{}", c, r);
        println!("{}│     ┌──────────────────────────────────────┐{}", c, r);
        println!("{}│     │ [zeros] │  [shifted data...]         │{}", c, r);
        println!("{}│     └──────────────────────────────────────┘{}", c, r);
        println!("{}│                      │{}", c, r);
        println!("{}│                      ▼{}", c, r);
        println!("{}│     ┌──────────────────────────────────────┐{}", c, r);
        println!("{}│     │ [payload|HMAC] │ [shifted data...]   │{}", c, r);
        println!("{}│     └──────────────────────────────────────┘{}", c, r);
        println!("{}│                      │{}", c, r);
        println!("{}│              XOR with cipher stream{}", c, r);
        println!("{}│                      │{}", c, r);
        println!("{}│                      ▼{}", c, r);
        println!("{}│     ┌──────────────────────────────────────┐{}", c, r);
        println!("{}│     │     [obfuscated layer data]          │{}", c, r);
        println!("{}│     └──────────────────────────────────────┘{}", c, r);
        
        if is_innermost {
            println!("{}│                      │{}", c, r);
            println!("{}│            Add filler at end{}", c, r);
            println!("{}│                      │{}", c, r);
            println!("{}│                      ▼{}", c, r);
            println!("{}│     ┌──────────────────────────────────────┐{}", c, r);
            println!("{}│     │ [obfuscated]    │    [filler]        │{}", c, r);
            println!("{}│     └──────────────────────────────────────┘{}", c, r);
        }
        println!("{}│{}", c, r);
    }

    fn print_final_packet(&self, packet: &OnionPacket) {
        let c = if self.config.use_colors { colors::GREEN } else { "" };
        let r = if self.config.use_colors { colors::RESET } else { "" };
        let b = if self.config.use_colors { colors::BOLD } else { "" };
        
        println!("\n{}{}✅ FINAL ONION PACKET{}", b, c, r);
        println!("{}═══════════════════════════════════════════════════════════════════{}", c, r);
        println!("{}├─ Version: 0x{:02x}{}", c, packet.version, r);
        println!("{}├─ Ephemeral Pubkey (33 bytes):", c);
        println!("{}│    {}{}", c, hex::encode(packet.ephemeral_pubkey), r);
        println!("{}├─ Mix Header (1300 bytes):", c);
        println!("{}│    {}{}", c, truncate_hex(&hex::encode(packet.mix_header), 80), r);
        println!("{}└─ HMAC (32 bytes):", c);
        println!("{}     {}{}", c, hex::encode(packet.hmac), r);
        println!("\n{}Total Size: {} bytes{}", c, 1 + 33 + 1300 + 32, r);
    }

    fn print_packet_structure_diagram(&self, packet: &OnionPacket) {
        let c = if self.config.use_colors { colors::CYAN } else { "" };
        let r = if self.config.use_colors { colors::RESET } else { "" };
        let b = if self.config.use_colors { colors::BOLD } else { "" };
        
        println!("\n{}{}📐 PACKET STRUCTURE:{}", b, c, r);
        println!("{}", c);
        println!("┌─────┬─────────────────────────────────┬─────────────────────────────────────────────────┬─────────────────────────────────┐");
        println!("│ Ver │      Ephemeral Public Key       │                   Mix Header                    │              HMAC               │");
        println!("│ 1B  │            33 bytes             │                  1300 bytes                     │            32 bytes             │");
        println!("├─────┼─────────────────────────────────┼─────────────────────────────────────────────────┼─────────────────────────────────┤");
        println!("│ 00  │ {:>31} │ {:>47} │ {:>31} │",
                 truncate_hex(&hex::encode(packet.ephemeral_pubkey), 31),
                 truncate_hex(&hex::encode(&packet.mix_header[..40]), 47),
                 truncate_hex(&hex::encode(packet.hmac), 31));
        println!("└─────┴─────────────────────────────────┴─────────────────────────────────────────────────┴─────────────────────────────────┘");
        println!("{}", r);
        
        // Print layered structure
        self.print_onion_layers_visual();
    }

    fn print_onion_layers_visual(&self) {
        let c = if self.config.use_colors { colors::MAGENTA } else { "" };
        let r = if self.config.use_colors { colors::RESET } else { "" };
        let b = if self.config.use_colors { colors::BOLD } else { "" };
        
        let num_layers = self.layer_states.len();
        
        println!("\n{}{}🧅 ONION LAYERS (Cross-section view):{}", b, c, r);
        println!("{}", c);
        
        // Draw onion layers from outside to inside
        for i in 0..num_layers {
            let padding = "  ".repeat(i);
            let _inner_padding = "  ".repeat(num_layers - i - 1);
            let layer_num = i + 1;
            
            if i == 0 {
                println!("{}╔═══════════════════════════════════════════════════════════════╗", padding);
                println!("{}║ {}LAYER {} (Outermost - First hop will peel){}                      ║", padding, b, layer_num, r);
            } else if i == num_layers - 1 {
                println!("{}╔═════════════════════════════════════════════╗", padding);
                println!("{}║ {}LAYER {} (Innermost - Contains final payload){}║", padding, b, layer_num, r);
                println!("{}╚═════════════════════════════════════════════╝", padding);
            } else {
                println!("{}╔══════════════════════════════════════════════════════╗", padding);
                println!("{}║ {}LAYER {} (Intermediate){}                               ║", padding, b, layer_num, r);
            }
        }
        
        // Close outer layers
        for i in (0..num_layers-1).rev() {
            let padding = "  ".repeat(i);
            if i == 0 {
                println!("{}╚═══════════════════════════════════════════════════════════════╝", padding);
            } else {
                println!("{}╚══════════════════════════════════════════════════════════════╝", padding);
            }
        }
        
        println!("{}", r);
    }

    /// Print wire format of the packet
    pub fn print_wire_format(&self, packet: &OnionPacket) {
        let c = if self.config.use_colors { colors::YELLOW } else { "" };
        let r = if self.config.use_colors { colors::RESET } else { "" };
        let b = if self.config.use_colors { colors::BOLD } else { "" };
        
        println!("\n{}{}📡 WIRE FORMAT (hex):{}", b, c, r);
        println!("{}", c);
        
        let hex_data = packet.to_hex();
        let line_width = 64;
        
        for (i, chunk) in hex_data.as_bytes().chunks(line_width).enumerate() {
            let offset = i * line_width / 2;
            println!("{:04x}: {}", offset, std::str::from_utf8(chunk).unwrap_or(""));
        }
        println!("{}", r);
    }

    /// Get layer states for external analysis
    pub fn get_layer_states(&self) -> &Vec<OnionLayerState> {
        &self.layer_states
    }
}

/// Quick visualization function for simple use cases
pub fn visualize_onion_construction(
    session_key: &SecretKey,
    hops: &Vec<Hops>,
    associated_data: &[u8],
) -> OnionPacket {
    let config = VisualizerConfig::default();
    let mut visualizer = OnionVisualizer::new(config);
    visualizer.build_and_visualize(session_key, hops, associated_data)
}

/// Create a minimal/quiet visualizer
pub fn create_quiet_visualizer() -> OnionVisualizer {
    OnionVisualizer::new(VisualizerConfig {
        show_hex_values: false,
        hex_truncate_len: 16,
        use_colors: false,
        show_intermediate_states: false,
        verbose: false,
    })
}

/// Create a verbose visualizer with all details
pub fn create_verbose_visualizer() -> OnionVisualizer {
    OnionVisualizer::new(VisualizerConfig {
        show_hex_values: true,
        hex_truncate_len: 64,
        use_colors: true,
        show_intermediate_states: true,
        verbose: true,
    })
}
