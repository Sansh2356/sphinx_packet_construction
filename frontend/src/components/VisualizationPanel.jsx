import { useState } from 'react'
import SharedSecrets from './SharedSecrets'
import LayerVisualization from './LayerVisualization'
import FinalPacket from './FinalPacket'
import FlowVisualization from './FlowVisualization'

function VisualizationPanel({ result, loading }) {
  const [activeTab, setActiveTab] = useState('flow')

  if (loading) {
    return (
      <section className="visualization-panel">
        <div className="loading">
          <div className="spinner"></div>
          <p>Building onion packet...</p>
        </div>
      </section>
    )
  }

  if (!result) return null

  const tabs = [
    { id: 'flow', label: 'Flow Diagram' },
    { id: 'shared-secrets', label: 'Shared Secrets' },
    { id: 'layers', label: 'Layer Construction' },
    { id: 'final', label: 'Final Packet' }
  ]

  return (
    <section className="visualization-panel">
      <h2>Visualization</h2>
      
      <div className="tab-bar">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="tab-content">
        {activeTab === 'flow' && (
          <FlowVisualization result={result} />
        )}
        {activeTab === 'shared-secrets' && (
          <SharedSecrets secrets={result.shared_secrets} />
        )}
        {activeTab === 'layers' && (
          <LayerVisualization layers={result.layers} />
        )}
        {activeTab === 'final' && (
          <FinalPacket packet={result.final_packet} />
        )}
      </div>
    </section>
  )
}

export default VisualizationPanel
