import { useState } from 'react'

function LayerVisualization({ layers }) {
  const [expandedLayers, setExpandedLayers] = useState({})

  const toggleLayer = (index) => {
    setExpandedLayers(prev => ({
      ...prev,
      [index]: !prev[index]
    }))
  }

  const truncateHex = (hex, maxLen = 64) => {
    if (!hex || hex.length <= maxLen) return hex
    return hex.slice(0, maxLen / 2) + '...' + hex.slice(-maxLen / 2)
  }

  return (
    <div className="layer-visualization">
      <h3>Layer-by-Layer Construction</h3>
      <p className="description">
        The onion is built from the innermost (final hop) to the outermost (first hop).
        Each layer wraps the previous with encryption and authentication.
      </p>

      <div className="layers-timeline">
        {layers.map((layer, index) => (
          <div key={index} className="layer-card">
            <div 
              className="layer-header"
              onClick={() => toggleLayer(index)}
            >
              <div className="layer-info">
                <span className="layer-number">Layer {layers.length - index}</span>
                <span className="hop-label">→ Hop {layer.hop_index + 1}</span>
                {layer.is_innermost && <span className="innermost-badge">Innermost</span>}
              </div>
              <button className="expand-btn">
                {expandedLayers[index] ? '-' : '+'}
              </button>
            </div>

            {expandedLayers[index] && (
              <div className="layer-details">
                <div className="detail-section">
                  <h4>Payload ({layer.payload_size} bytes)</h4>
                  <code className="hex-block">{layer.payload_hex}</code>
                </div>

                <div className="detail-section">
                  <h4>Mix Header Before Shift</h4>
                  <code className="hex-block routing-info">
                    {truncateHex(layer.mix_header_before_shift)}
                  </code>
                </div>

                <div className="detail-section">
                  <h4>Mix Header After Shift + Payload</h4>
                  <code className="hex-block routing-info">
                    {truncateHex(layer.mix_header_after_shift)}
                  </code>
                </div>

                <div className="detail-section">
                  <h4>ChaCha20 Stream Applied</h4>
                  <div className="cipher-indicator">
                    <span className="cipher-icon">[encrypted]</span>
                    <span>XOR with rho key stream</span>
                  </div>
                  <code className="hex-block routing-info encrypted">
                    {truncateHex(layer.mix_header_after_xor)}
                  </code>
                </div>

                <div className="detail-section hmac-section">
                  <h4>Computed HMAC (32 bytes)</h4>
                  <code className="hex-block hmac">{layer.computed_hmac}</code>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

export default LayerVisualization
