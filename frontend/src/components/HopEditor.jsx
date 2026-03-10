function HopEditor({ index, hop, onUpdate, onRemove }) {
  return (
    <div className="hop-card">
      <div className="hop-header">
        <span className="hop-number">Hop {index + 1}</span>
        <button
          className="btn btn-icon"
          onClick={() => onRemove(index)}
          title="Remove hop"
        >
          X
        </button>
      </div>
      
      <div className="form-group">
        <label>Public Key (33 bytes hex)</label>
        <input
          type="text"
          value={hop.pubkey}
          onChange={(e) => onUpdate(index, 'pubkey', e.target.value)}
          placeholder="02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"
          maxLength={66}
        />
        <span className="char-count">{hop.pubkey.length}/66</span>
      </div>
      
      <div className="form-group">
        <label>Payload (hex)</label>
        <textarea
          value={hop.payload}
          onChange={(e) => onUpdate(index, 'payload', e.target.value)}
          placeholder="1202023a98040205dc06080000000000000001"
          rows={2}
        />
        <span className="byte-count">
          {hop.payload.length / 2} bytes
        </span>
      </div>
    </div>
  )
}

export default HopEditor
