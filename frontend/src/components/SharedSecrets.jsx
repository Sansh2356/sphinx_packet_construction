function SharedSecrets({ secrets }) {
  return (
    <div className="shared-secrets">
      <h3>ECDH Shared Secrets</h3>
      <p className="description">
        Each hop's shared secret is derived from elliptic curve Diffie-Hellman 
        between the session key and the hop's public key, then hashed with SHA-256.
      </p>
      
      <div className="secrets-list">
        {secrets.map((secret, index) => (
          <div key={index} className="secret-card">
            <div className="secret-header">
              <span className="hop-badge">Hop {secret.hop_index + 1}</span>
            </div>
            
            <div className="secret-row">
              <span className="label">Public Key:</span>
              <code className="value pubkey">{secret.hop_pubkey}</code>
            </div>
            
            <div className="secret-row">
              <span className="label">Shared Secret:</span>
              <code className="value secret">{secret.shared_secret}</code>
            </div>
            
            <div className="derived-keys">
              <h4>Derived Keys</h4>
              <div className="key-grid">
                <div className="key-item">
                  <span className="key-name">rho (ρ)</span>
                  <code>{secret.rho_key}</code>
                  <span className="key-desc">Stream cipher key</span>
                </div>
                <div className="key-item">
                  <span className="key-name">mu (μ)</span>
                  <code>{secret.mu_key}</code>
                  <span className="key-desc">HMAC key for routing</span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default SharedSecrets
