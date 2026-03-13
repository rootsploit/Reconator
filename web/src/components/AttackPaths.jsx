import React, { useState, useEffect, useRef } from 'react'
import * as d3 from 'd3'

export default function AttackPaths({ report }) {
  const [expandedPath, setExpandedPath] = useState(null)
  const [viewMode, setViewMode] = useState('list') // 'list' or 'graph'
  const svgRef = useRef(null)

  const paths = report?.attack_paths || report?.scored_attack_paths || []

  if (!paths.length) {
    return (
      <div className="empty-state">
        <h3>No Attack Paths</h3>
        <p>No attack paths were identified in this scan</p>
      </div>
    )
  }

  const getSeverityClass = (impact) => {
    switch (impact?.toLowerCase()) {
      case 'critical': return 'badge-critical'
      case 'high': return 'badge-high'
      case 'medium': return 'badge-medium'
      case 'low': return 'badge-low'
      default: return 'badge-info'
    }
  }

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return '#ef4444'
      case 'high': return '#f97316'
      case 'medium': return '#eab308'
      case 'low': return '#22c55e'
      default: return '#6b7280'
    }
  }

  // D3.js Graph Visualization
  useEffect(() => {
    if (viewMode !== 'graph' || !svgRef.current || paths.length === 0) return

    // Build graph data from paths
    const nodes = new Map()
    const links = []

    paths.forEach((path, pathIdx) => {
      path.nodes?.forEach((node, nodeIdx) => {
        const host = node.vuln?.host || node.vulnerability?.host || `node-${nodeIdx}`
        const vulnName = node.vuln?.name || node.vulnerability?.name || 'Unknown'
        const severity = node.vuln?.severity || node.vulnerability?.severity || 'info'

        if (!nodes.has(host)) {
          nodes.set(host, {
            id: host,
            vulnName,
            severity,
            paths: []
          })
        }
        nodes.get(host).paths.push(pathIdx + 1)

        // Add link to next node
        if (nodeIdx < path.nodes.length - 1) {
          const nextHost = path.nodes[nodeIdx + 1].vuln?.host || path.nodes[nodeIdx + 1].vulnerability?.host || `node-${nodeIdx + 1}`
          links.push({ source: host, target: nextHost, pathIdx: pathIdx + 1 })
        }
      })
    })

    const graphData = {
      nodes: Array.from(nodes.values()),
      links
    }

    // Clear previous
    d3.select(svgRef.current).selectAll('*').remove()

    const width = 800
    const height = 500

    const svg = d3.select(svgRef.current)
      .attr('width', width)
      .attr('height', height)
      .attr('viewBox', [0, 0, width, height])

    // Add zoom
    const g = svg.append('g')
    const zoom = d3.zoom()
      .scaleExtent([0.5, 3])
      .on('zoom', (event) => g.attr('transform', event.transform))

    svg.call(zoom)

    // Force simulation
    const simulation = d3.forceSimulation(graphData.nodes)
      .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(120))
      .force('charge', d3.forceManyBody().strength(-400))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(50))

    // Draw links
    const link = g.append('g')
      .selectAll('line')
      .data(graphData.links)
      .join('line')
      .attr('stroke', '#4b5563')
      .attr('stroke-width', 2)
      .attr('stroke-opacity', 0.6)

    // Draw nodes
    const node = g.append('g')
      .selectAll('g')
      .data(graphData.nodes)
      .join('g')
      .call(d3.drag()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart()
          d.fx = d.x
          d.fy = d.y
        })
        .on('drag', (event, d) => {
          d.fx = event.x
          d.fy = event.y
        })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0)
          d.fx = null
          d.fy = null
        }))

    // Node circles
    node.append('circle')
      .attr('r', 30)
      .attr('fill', d => getSeverityColor(d.severity))
      .attr('stroke', '#fff')
      .attr('stroke-width', 2)

    // Node labels (hostname)
    node.append('text')
      .text(d => d.id.length > 12 ? d.id.slice(0, 12) + '...' : d.id)
      .attr('text-anchor', 'middle')
      .attr('dy', 45)
      .attr('fill', '#9ca3af')
      .attr('font-size', '10px')

    // Node icons (first letter of severity)
    node.append('text')
      .text(d => d.severity[0].toUpperCase())
      .attr('text-anchor', 'middle')
      .attr('dy', 5)
      .attr('fill', '#fff')
      .attr('font-size', '14px')
      .attr('font-weight', 'bold')

    // Tooltip
    node.append('title')
      .text(d => `${d.id}\nVulnerability: ${d.vulnName}\nSeverity: ${d.severity}\nFound in paths: ${d.paths.join(', ')}`)

    // Update positions on tick
    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y)

      node.attr('transform', d => `translate(${d.x},${d.y})`)
    })

    return () => simulation.stop()
  }, [viewMode, paths])

  return (
    <div className="attack-paths">
      <div className="view-toggle" style={{ marginBottom: '16px', display: 'flex', gap: '8px' }}>
        <button
          className={`btn ${viewMode === 'list' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setViewMode('list')}
        >
          List View
        </button>
        <button
          className={`btn ${viewMode === 'graph' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setViewMode('graph')}
        >
          Graph View
        </button>
      </div>

      {viewMode === 'graph' && (
        <div className="graph-container" style={{ marginBottom: '24px', borderRadius: '8px', overflow: 'hidden', background: '#1a1a2e' }}>
          <svg ref={svgRef} style={{ width: '100%', height: '500px', display: 'block' }}></svg>
          <div style={{ padding: '12px', fontSize: '12px', color: '#9ca3af', textAlign: 'center' }}>
            Drag nodes to reposition | Scroll to zoom | Click nodes for details
          </div>
        </div>
      )}

      <div className="section-summary">
        <div className="summary-stat">
          <span className="stat-value">{paths.length}</span>
          <span className="stat-label">Attack Paths</span>
        </div>
        <div className="summary-stat">
          <span className="stat-value">{paths.filter(p => p.impact === 'critical' || p.impact === 'high').length}</span>
          <span className="stat-label">High/Critical</span>
        </div>
        <div className="summary-stat">
          <span className="stat-value">{[...new Set(paths.flatMap(p => p.mitre_ids || []))].length}</span>
          <span className="stat-label">MITRE Techniques</span>
        </div>
      </div>

      {viewMode === 'list' && (
        <div className="paths-list">
        {paths.map((path, idx) => (
          <div key={path.id || idx} className={`path-card ${path.impact || 'medium'}`}>
            <div
              className="path-header"
              onClick={() => setExpandedPath(expandedPath === idx ? null : idx)}
              style={{ cursor: 'pointer' }}
            >
              <div className="path-title-row">
                <span className="path-name">{path.name}</span>
                {path.category && <span className="badge badge-info">{path.category}</span>}
              </div>
              <div className="path-meta">
                <span className="path-score">{path.score?.toFixed(1)}/10</span>
                <span className={`badge ${getSeverityClass(path.impact)}`}>{path.impact}</span>
                <span className="expand-icon">{expandedPath === idx ? '▾' : '▸'}</span>
              </div>
            </div>

            {path.description && (
              <p className="path-description">{path.description}</p>
            )}

            {expandedPath === idx && (
              <div className="path-details">
                <div className="path-info-grid">
                  {path.likelihood && (
                    <div className="info-item">
                      <span className="info-label">Likelihood</span>
                      <span className="badge badge-info">{path.likelihood}</span>
                    </div>
                  )}
                  {path.mitre_ids?.length > 0 && (
                    <div className="info-item">
                      <span className="info-label">MITRE ATT&CK</span>
                      <div className="mitre-tags">
                        {path.mitre_ids.map(id => (
                          <span key={id} className="badge badge-secondary">{id}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {path.nodes?.length > 0 && (
                  <div className="path-section">
                    <h4>Vulnerabilities ({path.nodes.length})</h4>
                    <div className="vuln-list">
                      {path.nodes.map((node, nIdx) => (
                        <div key={nIdx} className="vuln-item">
                          <span className={`badge ${getSeverityClass(node.vulnerability?.severity || node.vuln?.severity)}`}>
                            {node.vulnerability?.severity || node.vuln?.severity || 'info'}
                          </span>
                          <span className="vuln-name">{node.vulnerability?.name || node.vuln?.name || 'Unknown'}</span>
                          <span className="vuln-host">{node.vulnerability?.host || node.vuln?.host || ''}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {path.edges?.length > 0 && (
                  <div className="path-section">
                    <h4>Attack Flow</h4>
                    <div className="flow-list">
                      {path.edges.map((edge, eIdx) => (
                        <div key={eIdx} className="flow-item">
                          <code>{edge.from}</code>
                          <span className="flow-arrow">→</span>
                          <code>{edge.to}</code>
                          {edge.label && <span className="flow-label">{edge.label}</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {path.mitigations?.length > 0 && (
                  <div className="path-section">
                    <h4>Mitigations</h4>
                    <ul className="mitigation-list">
                      {path.mitigations.map((m, mIdx) => (
                        <li key={mIdx}>{m}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
        </div>
      )}

      <style>{`
        .attack-paths { padding: 0; }
        .view-toggle { margin-bottom: 16px; }
        .btn { padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer; font-size: 0.85rem; font-weight: 500; transition: all 0.2s; }
        .btn-primary { background: #6366f1; color: #fff; }
        .btn-primary:hover { background: #4f46e5; }
        .btn-secondary { background: #374151; color: #d1d5db; }
        .btn-secondary:hover { background: #4b5563; }
        .section-summary { display: flex; gap: 24px; margin-bottom: 24px; }
        .summary-stat { display: flex; flex-direction: column; align-items: center; padding: 16px 24px; background: var(--bg-secondary, #1a1a2e); border-radius: 8px; min-width: 120px; }
        .stat-value { font-size: 1.5rem; font-weight: 700; color: var(--text-primary, #fff); }
        .stat-label { font-size: 0.8rem; color: var(--text-muted, #888); margin-top: 4px; }
        .paths-list { display: flex; flex-direction: column; gap: 16px; }
        .path-card { border: 1px solid var(--border, #333); border-radius: 8px; padding: 16px; background: var(--bg-card, #16162a); }
        .path-card.critical { border-left: 3px solid #ef4444; }
        .path-card.high { border-left: 3px solid #f97316; }
        .path-card.medium { border-left: 3px solid #eab308; }
        .path-card.low { border-left: 3px solid #22c55e; }
        .path-header { display: flex; justify-content: space-between; align-items: center; }
        .path-title-row { display: flex; align-items: center; gap: 8px; }
        .path-name { font-weight: 600; font-size: 0.95rem; }
        .path-meta { display: flex; align-items: center; gap: 8px; }
        .path-score { font-weight: 700; font-size: 1rem; }
        .expand-icon { color: var(--text-muted, #888); }
        .path-description { font-size: 0.85rem; color: var(--text-secondary, #aaa); margin: 8px 0 0; }
        .path-details { margin-top: 16px; border-top: 1px solid var(--border, #333); padding-top: 16px; }
        .path-info-grid { display: flex; gap: 24px; margin-bottom: 16px; flex-wrap: wrap; }
        .info-item { display: flex; flex-direction: column; gap: 4px; }
        .info-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: var(--text-muted, #888); }
        .mitre-tags { display: flex; gap: 4px; flex-wrap: wrap; }
        .path-section { margin-top: 16px; }
        .path-section h4 { font-size: 0.85rem; font-weight: 600; margin-bottom: 8px; color: var(--text-secondary, #aaa); }
        .vuln-list { display: flex; flex-direction: column; gap: 6px; }
        .vuln-item { display: flex; align-items: center; gap: 8px; padding: 6px 10px; background: var(--bg-secondary, #1a1a2e); border-radius: 4px; font-size: 0.85rem; }
        .vuln-host { margin-left: auto; font-size: 0.8rem; color: var(--text-muted, #888); }
        .flow-list { display: flex; flex-direction: column; gap: 6px; }
        .flow-item { display: flex; align-items: center; gap: 8px; padding: 6px 10px; background: var(--bg-secondary, #1a1a2e); border-radius: 4px; font-size: 0.85rem; }
        .flow-arrow { color: var(--text-muted, #888); }
        .flow-label { margin-left: auto; font-size: 0.8rem; color: var(--text-secondary, #aaa); }
        .mitigation-list { padding-left: 20px; font-size: 0.85rem; color: var(--text-secondary, #aaa); line-height: 1.8; }
      `}
      </style>
    </div>
  )
}
