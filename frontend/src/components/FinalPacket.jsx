import { useState } from 'react'

function FinalPacket({ packet }) {
  const [copied, setCopied] = useState(false)

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(packet.full_packet_hex)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }

  return (
    <div className="final-packet">
      <h3>Final Onion Packet</h3>
      <p className="description">
        The complete Sphinx packet ready to be sent to the first hop.
        Total size: {packet.total_size} bytes (1366 bytes standard)
      </p>

      <div className="packet-structure">
        <div className="packet-part version">
          <div className="part-header">
            <span className="part-name">Version</span>
            <span className="part-size">1 byte</span>
          </div>
          <code>{packet.version}</code>
        </div>

        <div className="packet-part pubkey">
          <div className="part-header">
            <span className="part-name">Ephemeral Public Key</span>
            <span className="part-size">33 bytes</span>
          </div>
          <code>{packet.ephemeral_pubkey}</code>
        </div>

        <div className="packet-part routing">
          <div className="part-header">
            <span className="part-name">Encrypted Mix Header</span>
            <span className="part-size">1300 bytes</span>
          </div>
          <div className="routing-preview">
            <code className="truncated">
              {packet.mix_header?.slice(0, 128)}...
            </code>
            <details>
              <summary>Show full mix header</summary>
              <code className="full-routing">{packet.mix_header}</code>
            </details>
          </div>
        </div>

        <div className="packet-part hmac">
          <div className="part-header">
            <span className="part-name">HMAC</span>
            <span className="part-size">32 bytes</span>
          </div>
          <code>{packet.hmac}</code>
        </div>
      </div>

      <div className="packet-diagram">
        <h4>Packet Layout</h4>
        <div className="diagram">
          <div className="segment version" style={{ flex: 1 }}>Ver</div>
          <div className="segment pubkey" style={{ flex: 33 }}>Public Key</div>
          <div className="segment routing" style={{ flex: 200 }}>Encrypted Mix Header</div>
          <div className="segment hmac" style={{ flex: 32 }}>HMAC</div>
        </div>
      </div>

      <button className="btn btn-primary copy-btn" onClick={copyToClipboard}>
        {copied ? 'Copied!' : 'Copy Full Packet'}
      </button>
    </div>
  )
}

export default FinalPacket
