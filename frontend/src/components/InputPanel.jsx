import HopEditor from './HopEditor'

function InputPanel({
  sessionKey,
  setSessionKey,
  associatedData,
  setAssociatedData,
  hops,
  setHops,
  onBuild,
  onLoadExample,
  onClear,
  loading
}) {
  const addHop = () => {
    setHops([...hops, { pubkey: '', payload: '' }])
  }

  const updateHop = (index, field, value) => {
    const newHops = [...hops]
    newHops[index] = { ...newHops[index], [field]: value }
    setHops(newHops)
  }

  const removeHop = (index) => {
    setHops(hops.filter((_, i) => i !== index))
  }

  return (
    <section className="input-panel">
      <h2>Input Configuration</h2>
      
      <div className="form-group">
        <label htmlFor="sessionKey">Session Key (32 bytes hex)</label>
        <input
          id="sessionKey"
          type="text"
          value={sessionKey}
          onChange={(e) => setSessionKey(e.target.value)}
          placeholder="4141414141414141414141414141414141414141414141414141414141414141"
          maxLength={64}
        />
        <span className="char-count">{sessionKey.length}/64</span>
      </div>

      <div className="form-group">
        <label htmlFor="associatedData">Associated Data (32 bytes hex)</label>
        <input
          id="associatedData"
          type="text"
          value={associatedData}
          onChange={(e) => setAssociatedData(e.target.value)}
          placeholder="4242424242424242424242424242424242424242424242424242424242424242"
          maxLength={64}
        />
        <span className="char-count">{associatedData.length}/64</span>
      </div>

      <div className="hops-section">
        <div className="hops-header">
          <h3>Hops ({hops.length})</h3>
          <button className="btn btn-secondary" onClick={addHop}>
            + Add Hop
          </button>
        </div>
        
        {hops.length === 0 && (
          <p className="no-hops">No hops configured. Add hops or load an example.</p>
        )}
        
        {hops.map((hop, index) => (
          <HopEditor
            key={index}
            index={index}
            hop={hop}
            onUpdate={updateHop}
            onRemove={removeHop}
          />
        ))}
      </div>

      <div className="button-group">
        <button
          className="btn btn-primary"
          onClick={onBuild}
          disabled={loading || hops.length === 0}
        >
          {loading ? 'Building...' : 'Build Onion Packet'}
        </button>
        <button className="btn btn-secondary" onClick={onLoadExample}>
          Load Example
        </button>
        <button className="btn btn-danger" onClick={onClear}>
          Clear All
        </button>
      </div>
    </section>
  )
}

export default InputPanel
