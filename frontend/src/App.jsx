import { useState, useCallback } from 'react'
import Header from './components/Header'
import InputPanel from './components/InputPanel'
import VisualizationPanel from './components/VisualizationPanel'
import ErrorModal from './components/ErrorModal'

const API_BASE = '/api'

function App() {
  const [sessionKey, setSessionKey] = useState('')
  const [associatedData, setAssociatedData] = useState('')
  const [hops, setHops] = useState([])
  const [buildResult, setBuildResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const loadExample = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/example`)
      const example = await response.json()
      setSessionKey(example.session_key)
      setAssociatedData(example.associated_data)
      setHops(example.hops.map(h => ({ pubkey: h.pubkey, payload: h.payload })))
    } catch (err) {
      // Fallback
      setSessionKey('4141414141414141414141414141414141414141414141414141414141414141')
      setAssociatedData('4242424242424242424242424242424242424242424242424242424242424242')
      setHops([{
        pubkey: '02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619',
        payload: '1202023a98040205dc06080000000000000001'
      }])
    }
  }, [])

  const clearAll = useCallback(() => {
    setSessionKey('')
    setAssociatedData('')
    setHops([])
    setBuildResult(null)
  }, [])

  const buildOnion = useCallback(async () => {
    // Validation
    if (!sessionKey || sessionKey.length !== 64) {
      setError('Session key must be 32 bytes (64 hex characters)')
      return
    }
    if (!associatedData || associatedData.length !== 64) {
      setError('Associated data must be 32 bytes (64 hex characters)')
      return
    }
    if (hops.length === 0) {
      setError('At least one hop is required')
      return
    }
    for (let i = 0; i < hops.length; i++) {
      if (!hops[i].pubkey || hops[i].pubkey.length !== 66) {
        setError(`Hop ${i + 1}: Public key must be 33 bytes (66 hex characters)`)
        return
      }
      if (!hops[i].payload) {
        setError(`Hop ${i + 1}: Payload is required`)
        return
      }
    }

    setLoading(true)
    setBuildResult(null)

    try {
      const response = await fetch(`${API_BASE}/build`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_key: sessionKey,
          associated_data: associatedData,
          hops
        })
      })

      const result = await response.json()

      if (!result.success) {
        setError(result.error || 'Failed to build onion packet')
        return
      }

      setBuildResult(result)
    } catch (err) {
      setError('Failed to connect to server: ' + err.message)
    } finally {
      setLoading(false)
    }
  }, [sessionKey, associatedData, hops])

  return (
    <div className="app">
      <Header />
      
      <main className="main-content">
        <InputPanel
          sessionKey={sessionKey}
          setSessionKey={setSessionKey}
          associatedData={associatedData}
          setAssociatedData={setAssociatedData}
          hops={hops}
          setHops={setHops}
          onBuild={buildOnion}
          onLoadExample={loadExample}
          onClear={clearAll}
          loading={loading}
        />

        {(loading || buildResult) && (
          <VisualizationPanel
            result={buildResult}
            loading={loading}
          />
        )}
      </main>

      <ErrorModal
        error={error}
        onClose={() => setError(null)}
      />
    </div>
  )
}

export default App
