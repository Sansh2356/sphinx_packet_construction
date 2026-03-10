import { useCallback, useMemo } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'

// Custom node styles
const nodeStyles = {
  input: {
    background: 'linear-gradient(135deg, #7c3aed 0%, #5b21b6 100%)',
    color: '#fff',
    border: '2px solid #8b5cf6',
    borderRadius: '8px',
    padding: '12px 16px',
    fontSize: '12px',
    fontFamily: 'JetBrains Mono, monospace',
    minWidth: '180px',
  },
  secret: {
    background: 'linear-gradient(135deg, #059669 0%, #047857 100%)',
    color: '#fff',
    border: '2px solid #10b981',
    borderRadius: '8px',
    padding: '12px 16px',
    fontSize: '11px',
    fontFamily: 'JetBrains Mono, monospace',
    minWidth: '200px',
  },
  layer: {
    background: 'linear-gradient(135deg, #ea580c 0%, #c2410c 100%)',
    color: '#fff',
    border: '2px solid #f97316',
    borderRadius: '8px',
    padding: '12px 16px',
    fontSize: '11px',
    fontFamily: 'JetBrains Mono, monospace',
    minWidth: '220px',
  },
  output: {
    background: 'linear-gradient(135deg, #0891b2 0%, #0e7490 100%)',
    color: '#fff',
    border: '2px solid #06b6d4',
    borderRadius: '12px',
    padding: '16px 20px',
    fontSize: '12px',
    fontFamily: 'JetBrains Mono, monospace',
    minWidth: '240px',
  },
  operation: {
    background: 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)',
    color: '#fff',
    border: '2px solid #6366f1',
    borderRadius: '50%',
    width: '60px',
    height: '60px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '10px',
    fontWeight: 'bold',
  },
}

const truncateHex = (hex, len = 8) => {
  if (!hex || hex.length <= len * 2) return hex
  return hex.slice(0, len) + '...' + hex.slice(-len)
}

function FlowVisualization({ result }) {
  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
    if (!result) return { nodes: [], edges: [] }

    const nodes = []
    const edges = []
    let nodeId = 0
    const getId = () => `node-${nodeId++}`

    // Column positions
    const inputX = 50
    const secretX = 350
    const layerX = 700
    const outputX = 1050

    // Input Section
    const sessionKeyId = getId()
    nodes.push({
      id: sessionKeyId,
      position: { x: inputX, y: 50 },
      data: {
        label: (
          <div>
            <div style={{ fontWeight: 'bold', marginBottom: '4px' }}>Session Key</div>
            <div style={{ fontSize: '10px', opacity: 0.9 }}>{truncateHex(result.session_key, 12)}</div>
          </div>
        ),
      },
      style: nodeStyles.input,
    })

    const ephemeralId = getId()
    nodes.push({
      id: ephemeralId,
      position: { x: inputX, y: 150 },
      data: {
        label: (
          <div>
            <div style={{ fontWeight: 'bold', marginBottom: '4px' }}>Ephemeral Pubkey</div>
            <div style={{ fontSize: '10px', opacity: 0.9 }}>{truncateHex(result.ephemeral_pubkey, 12)}</div>
          </div>
        ),
      },
      style: nodeStyles.input,
    })

    edges.push({
      id: `edge-session-ephemeral`,
      source: sessionKeyId,
      target: ephemeralId,
      animated: true,
      style: { stroke: '#8b5cf6', strokeWidth: 2 },
      label: 'derive',
      labelStyle: { fill: '#8b5cf6', fontSize: 10 },
    })

    const assocDataId = getId()
    nodes.push({
      id: assocDataId,
      position: { x: inputX, y: 250 },
      data: {
        label: (
          <div>
            <div style={{ fontWeight: 'bold', marginBottom: '4px' }}>Associated Data</div>
            <div style={{ fontSize: '10px', opacity: 0.9 }}>{truncateHex(result.associated_data, 12)}</div>
          </div>
        ),
      },
      style: nodeStyles.input,
    })

    // Initial Header
    const initialHeaderId = getId()
    nodes.push({
      id: initialHeaderId,
      position: { x: inputX, y: 380 },
      data: {
        label: (
          <div>
            <div style={{ fontWeight: 'bold', marginBottom: '4px' }}>Initial Header</div>
            <div style={{ fontSize: '10px', opacity: 0.9 }}>1300 bytes padding</div>
            <div style={{ fontSize: '9px', opacity: 0.7, marginTop: '2px' }}>
              pad_key: {truncateHex(result.padding_key, 8)}
            </div>
          </div>
        ),
      },
      style: nodeStyles.input,
    })

    // Shared Secrets Section
    const secretIds = []
    result.shared_secrets.forEach((secret, index) => {
      const secretId = getId()
      secretIds.push(secretId)
      
      nodes.push({
        id: secretId,
        position: { x: secretX, y: 50 + index * 160 },
        data: {
          label: (
            <div>
              <div style={{ fontWeight: 'bold', marginBottom: '6px' }}>
                Hop {secret.hop_index + 1} Secret
              </div>
              <div style={{ fontSize: '9px', marginBottom: '2px' }}>
                <span style={{ opacity: 0.7 }}>pubkey:</span> {truncateHex(secret.hop_pubkey, 8)}
              </div>
              <div style={{ fontSize: '9px', marginBottom: '2px' }}>
                <span style={{ opacity: 0.7 }}>secret:</span> {truncateHex(secret.shared_secret, 8)}
              </div>
              <div style={{ fontSize: '9px', display: 'flex', gap: '8px' }}>
                <span><span style={{ color: '#fcd34d' }}>ρ:</span> {truncateHex(secret.rho_key, 4)}</span>
                <span><span style={{ color: '#a5f3fc' }}>μ:</span> {truncateHex(secret.mu_key, 4)}</span>
              </div>
            </div>
          ),
        },
        style: nodeStyles.secret,
      })

      // Connect session key to each secret (ECDH)
      edges.push({
        id: `edge-session-secret-${index}`,
        source: sessionKeyId,
        target: secretId,
        animated: true,
        style: { stroke: '#10b981', strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#10b981' },
        label: 'ECDH',
        labelStyle: { fill: '#10b981', fontSize: 9 },
      })
    })

    // Layer Construction Section (reverse order - innermost first)
    const layerIds = []
    result.layers.forEach((layer, index) => {
      const layerId = getId()
      layerIds.push(layerId)
      
      const actualHopIndex = layer.hop_index
      const layerNum = result.layers.length - index

      nodes.push({
        id: layerId,
        position: { x: layerX, y: 50 + index * 180 },
        data: {
          label: (
            <div>
              <div style={{ fontWeight: 'bold', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span>Layer {layerNum}</span>
                {layer.is_innermost && (
                  <span style={{ 
                    background: '#fcd34d', 
                    color: '#000', 
                    padding: '2px 6px', 
                    borderRadius: '4px',
                    fontSize: '8px',
                  }}>INNERMOST</span>
                )}
              </div>
              <div style={{ fontSize: '9px', marginBottom: '4px' }}>
                <span style={{ opacity: 0.7 }}>→ Hop {actualHopIndex + 1}</span>
                <span style={{ marginLeft: '8px' }}>payload: {layer.payload_size} bytes</span>
              </div>
              <div style={{ fontSize: '8px', opacity: 0.8, lineHeight: 1.4 }}>
                <div>1. shift header right</div>
                <div>2. insert payload + HMAC</div>
                <div>3. XOR with ρ stream</div>
                <div>4. compute μ HMAC</div>
              </div>
              <div style={{ fontSize: '9px', marginTop: '4px' }}>
                <span style={{ color: '#fcd34d' }}>HMAC:</span> {truncateHex(layer.computed_hmac, 6)}
              </div>
            </div>
          ),
        },
        style: nodeStyles.layer,
      })

      // Connect secret to layer
      edges.push({
        id: `edge-secret-layer-${index}`,
        source: secretIds[actualHopIndex],
        target: layerId,
        animated: true,
        style: { stroke: '#f97316', strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#f97316' },
        label: 'encrypt',
        labelStyle: { fill: '#f97316', fontSize: 9 },
      })

      // Connect to previous layer or initial header
      if (index === 0) {
        edges.push({
          id: `edge-init-layer-${index}`,
          source: initialHeaderId,
          target: layerId,
          animated: true,
          style: { stroke: '#8b5cf6', strokeWidth: 2 },
          markerEnd: { type: MarkerType.ArrowClosed, color: '#8b5cf6' },
        })
      } else {
        edges.push({
          id: `edge-layer-layer-${index}`,
          source: layerIds[index - 1],
          target: layerId,
          animated: true,
          style: { stroke: '#f97316', strokeWidth: 2 },
          markerEnd: { type: MarkerType.ArrowClosed, color: '#f97316' },
          label: 'wrap',
          labelStyle: { fill: '#f97316', fontSize: 9 },
        })
      }
    })

    // Connect associated data to layers (for HMAC computation)
    layerIds.forEach((layerId, index) => {
      edges.push({
        id: `edge-assoc-layer-${index}`,
        source: assocDataId,
        target: layerId,
        animated: false,
        style: { stroke: '#6b7280', strokeWidth: 1, strokeDasharray: '4 4' },
        label: 'HMAC input',
        labelStyle: { fill: '#6b7280', fontSize: 8 },
      })
    })

    // Final Packet Output
    const finalPacketId = getId()
    nodes.push({
      id: finalPacketId,
      position: { x: outputX, y: 150 },
      data: {
        label: (
          <div>
            <div style={{ fontWeight: 'bold', marginBottom: '8px', fontSize: '14px' }}>
              Final Onion Packet
            </div>
            <div style={{ fontSize: '10px', marginBottom: '4px' }}>
              Total: {result.final_packet.total_size} bytes
            </div>
            <div style={{ fontSize: '9px', opacity: 0.9, lineHeight: 1.5 }}>
              <div>• Version: {result.final_packet.version}</div>
              <div>• Ephemeral: 33 bytes</div>
              <div>• Mix Header: 1300 bytes</div>
              <div>• HMAC: 32 bytes</div>
            </div>
            <div style={{ fontSize: '9px', marginTop: '6px' }}>
              <span style={{ color: '#fcd34d' }}>HMAC:</span> {truncateHex(result.final_packet.hmac, 8)}
            </div>
          </div>
        ),
      },
      style: nodeStyles.output,
    })

    // Connect ephemeral pubkey and last layer to final packet
    edges.push({
      id: `edge-ephemeral-final`,
      source: ephemeralId,
      target: finalPacketId,
      animated: true,
      style: { stroke: '#06b6d4', strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#06b6d4' },
    })

    if (layerIds.length > 0) {
      edges.push({
        id: `edge-layer-final`,
        source: layerIds[layerIds.length - 1],
        target: finalPacketId,
        animated: true,
        style: { stroke: '#06b6d4', strokeWidth: 3 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#06b6d4' },
        label: 'assemble',
        labelStyle: { fill: '#06b6d4', fontSize: 10 },
      })
    }

    return { nodes, edges }
  }, [result])

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)

  if (!result) {
    return (
      <div className="flow-visualization-empty">
        <p>Build an onion packet to see the flow visualization.</p>
      </div>
    )
  }

  return (
    <div className="flow-visualization">
      <h3>Packet Construction Flow</h3>
      <p className="description">
        Interactive diagram showing how the Sphinx onion packet is constructed.
        Drag to pan, scroll to zoom.
      </p>
      
      <div className="flow-container" style={{ width: '100%', height: '100%' }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.3}
          maxZoom={1.5}
          defaultEdgeOptions={{
            type: 'smoothstep',
          }}
        >
          <Background color="#30363d" gap={20} />
          <Controls 
            style={{ 
              background: '#21262d', 
              border: '1px solid #30363d',
              borderRadius: '8px',
            }}
          />
          <MiniMap
            style={{
              background: '#161b22',
              border: '1px solid #30363d',
              borderRadius: '8px',
            }}
            nodeColor={(node) => {
              if (node.style?.background?.includes('#7c3aed')) return '#8b5cf6'
              if (node.style?.background?.includes('#059669')) return '#10b981'
              if (node.style?.background?.includes('#ea580c')) return '#f97316'
              if (node.style?.background?.includes('#0891b2')) return '#06b6d4'
              return '#6b7280'
            }}
          />
        </ReactFlow>
      </div>

      <div className="flow-legend">
        <div className="legend-item">
          <span className="legend-color" style={{ background: '#8b5cf6' }}></span>
          <span>Input Data</span>
        </div>
        <div className="legend-item">
          <span className="legend-color" style={{ background: '#10b981' }}></span>
          <span>Shared Secrets (ECDH)</span>
        </div>
        <div className="legend-item">
          <span className="legend-color" style={{ background: '#f97316' }}></span>
          <span>Layer Construction</span>
        </div>
        <div className="legend-item">
          <span className="legend-color" style={{ background: '#06b6d4' }}></span>
          <span>Final Packet</span>
        </div>
      </div>
    </div>
  )
}

export default FlowVisualization
