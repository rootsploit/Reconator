import { useState, useEffect } from 'react'
import { api } from '../utils/api'
import FindingsFilter from './FindingsFilter'
import { getVulnDescription } from '../utils/vulnDescriptions'

function ScanDetails({ scan: initialScan, onBack }) {
  const [activeTab, setActiveTab] = useState('summary')
  const [report, setReport] = useState(null)
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [scan, setScan] = useState(initialScan) // Local state for live updates
  const [filters, setFilters] = useState({
    severities: [],
    types: [],
    host: '',
    search: '',
    includeFP: true
  })

  useEffect(() => {
    if (scan?.id) {
      fetchData()

      // Poll for updates if scan is running
      if (scan.status === 'running') {
        const interval = setInterval(() => {
          fetchData()
        }, 3000) // Poll every 3 seconds

        return () => clearInterval(interval)
      }
    }
  }, [scan?.id, scan?.status, filters])

  const handleFilterChange = (newFilters) => {
    setFilters(newFilters)
  }

  const fetchData = async () => {
    setLoading(true)
    try {
      // Build query params for filtering
      const params = new URLSearchParams()
      if (filters.severities.length > 0) {
        filters.severities.forEach(sev => params.append('severity', sev))
      }
      if (filters.types.length > 0) {
        filters.types.forEach(typ => params.append('type', typ))
      }
      if (filters.host) {
        params.append('host', filters.host)
      }
      if (filters.search) {
        params.append('search', filters.search)
      }
      params.append('include_fp', filters.includeFP.toString())

      const queryString = params.toString()
      const findingsUrl = `/scans/${scan.id}/findings${queryString ? `?${queryString}` : ''}`

      const [scanRes, reportRes, findingsRes] = await Promise.all([
        api.get(`/scans/${scan.id}`),
        api.get(`/scans/${scan.id}/report`),
        api.get(findingsUrl)
      ])
      setScan(scanRes) // Update scan with live progress data
      setReport(reportRes)
      setFindings(findingsRes.findings || [])
    } catch (error) {
      console.error('Failed to fetch scan data:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleExport = async (format) => {
    try {
      const filename = `reconator_${scan.target}_${scan.id}.${format}`
      await api.download(`/export/${scan.id}/${format}`, filename)
    } catch (error) {
      alert('Export failed: ' + error.message)
    }
  }

  if (!scan) {
    return <div className="empty-state"><h3>No scan selected</h3><p>Select a scan to view details</p></div>
  }

  const tabs = [
    { id: 'summary', label: 'Summary', icon: 'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
    { id: 'assets', label: 'Asset Inventory', icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01' },
    { id: 'screenshots', label: 'Screenshots', icon: 'M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z' },
    { id: 'secheaders', label: 'Security Headers', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z' },
    { id: 'jsanalysis', label: 'JS Analysis', icon: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4' },
  ]

  return (
    <div className="scan-details">
      {/* Header */}
      <div className="scan-details-header">
        <div>
          <button onClick={onBack} className="back-btn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
            Back to Scans
          </button>
          <h1>{scan.target}</h1>
          <div className="scan-meta">
            <span>Scan ID: {scan.id}</span>
            <span>Started: {new Date(scan.started_at).toLocaleString()}</span>
            {scan.duration && <span>Duration: {scan.duration}</span>}
            <span className={`badge badge-${scan.status}`}>{scan.status}</span>
          </div>
        </div>
        <div className="export-btns">
          <button className="btn btn-secondary" onClick={() => handleExport('csv')}>Export CSV</button>
          <button className="btn btn-secondary" onClick={() => handleExport('json')}>Export JSON</button>
          <button className="btn btn-secondary" onClick={() => handleExport('sarif')}>Export SARIF</button>
          <button className="btn btn-primary" onClick={() => handleExport('html')}>Export HTML</button>
        </div>
      </div>

      {/* Tabs */}
      <div className="tabs-container">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d={tab.icon} />
            </svg>
            {tab.label}
            {tab.id === 'vulnerabilities' && findings.length > 0 && (
              <span className="tab-badge">{findings.length}</span>
            )}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="tab-content">
        {loading ? (
          <div className="empty-state"><div className="animate-pulse">Loading...</div></div>
        ) : (
          <>
            {activeTab === 'summary' && <SummaryTab scan={scan} report={report} findings={findings} />}
            {activeTab === 'assets' && <AssetsTab report={report} />}
            {activeTab === 'screenshots' && <ScreenshotsTab report={report} scan={scan} />}
            {activeTab === 'secheaders' && <SecurityHeadersTab report={report} />}
            {activeTab === 'vulnerabilities' && (
              <VulnerabilitiesTab
                findings={findings}
                filters={filters}
                onFilterChange={handleFilterChange}
              />
            )}
            {activeTab === 'jsanalysis' && <JSAnalysisTab report={report} />}
          </>
        )}
      </div>
    </div>
  )
}

function SummaryTab({ scan, report, findings }) {
  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  // Colorize severity keywords in text
  const colorizeText = (text) => {
    if (!text) return null

    // Split text and wrap severity keywords with colored spans
    const parts = text.split(/(\d+\s+(?:critical|high|medium|low|info|informational))/gi)

    return parts.map((part, idx) => {
      const match = part.match(/(\d+)\s+(critical|high|medium|low|info|informational)/i)
      if (match) {
        const count = match[1]
        const severity = match[2].toLowerCase()
        const colors = {
          critical: 'var(--critical)',
          high: 'var(--high)',
          medium: 'var(--medium)',
          low: 'var(--low)',
          info: 'var(--info)',
          informational: 'var(--info)'
        }
        return (
          <span key={idx}>
            <span style={{ color: colors[severity], fontWeight: 600 }}>{count} {severity}</span>
          </span>
        )
      }
      return <span key={idx}>{part}</span>
    })
  }

  return (
    <div className="summary-tab">
      {/* Scan Progress (if running) */}
      {scan.status === 'running' && (
        <div className="card" style={{ marginBottom: 24, background: 'var(--card-bg)' }}>
          <div className="card-header">
            <h2>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                <span className="pulse-dot" style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent)', animation: 'pulse 2s infinite' }}></span>
                Scan in Progress
              </span>
            </h2>
          </div>
          <div className="card-body">
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span style={{ fontWeight: 500 }}>{scan.current_phase || 'Initializing...'}</span>
                <span style={{ color: 'var(--accent)', fontWeight: 600 }}>{scan.progress || 0}%</span>
              </div>
              <div className="progress-bar" style={{ height: 8, marginBottom: 4 }}>
                <div className="fill" style={{ width: `${scan.progress || 0}%` }} />
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 8 }}>
                Started {new Date(scan.started_at).toLocaleTimeString()} • {scan.duration || 'calculating...'}
              </div>
            </div>
            <div style={{ padding: 12, background: 'var(--bg-secondary)', borderRadius: 8, fontSize: 13 }}>
              <div style={{ color: 'var(--text-secondary)', marginBottom: 4 }}>Partial results will appear below as phases complete</div>
            </div>
          </div>
        </div>
      )}

      {/* Stats Overview */}
      <div className="stats-grid scan-stats-grid">
        <div className="stat-card">
          <div className="label">Total Findings</div>
          <div className="value">{findings.length}</div>
        </div>
        <div className="stat-card">
          <div className="label">Critical</div>
          <div className="value critical">{severityCounts.critical || 0}</div>
        </div>
        <div className="stat-card">
          <div className="label">High</div>
          <div className="value high">{severityCounts.high || 0}</div>
        </div>
        <div className="stat-card">
          <div className="label">Medium</div>
          <div className="value medium">{severityCounts.medium || 0}</div>
        </div>
        <div className="stat-card">
          <div className="label">Low</div>
          <div className="value low">{severityCounts.low || 0}</div>
        </div>
        <div className="stat-card">
          <div className="label">Info</div>
          <div className="value info">{severityCounts.info || severityCounts.informational || severityCounts.informative || 0}</div>
        </div>
      </div>

      {/* Scan Results Summary */}
      {report && (
        <div className="card" style={{ marginTop: 24 }}>
          <div className="card-header"><h2>Scan Results</h2></div>
          <div className="card-body">
            <div className="summary-grid">
              {report.Subdomain && (
                <div className="summary-item">
                  <div className="summary-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                  </div>
                  <div className="summary-data">
                    <div className="summary-value">{report.Subdomain.total || 0}</div>
                    <div className="summary-label">Subdomains</div>
                  </div>
                </div>
              )}
              {report.Ports && (
                <>
                  <div className="summary-item">
                    <div className="summary-icon">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                    </div>
                    <div className="summary-data">
                      <div className="summary-value">{report.Ports.alive_count || 0}</div>
                      <div className="summary-label">Alive Hosts</div>
                    </div>
                  </div>
                  <div className="summary-item">
                    <div className="summary-icon">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
                    </div>
                    <div className="summary-data">
                      <div className="summary-value">{report.Ports.total_ports || 0}</div>
                      <div className="summary-label">Open Ports</div>
                    </div>
                  </div>
                </>
              )}
              {report.Tech && (
                <div className="summary-item">
                  <div className="summary-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
                  </div>
                  <div className="summary-data">
                    <div className="summary-value">{Object.keys(report.Tech.tech_count || {}).length}</div>
                    <div className="summary-label">Technologies</div>
                  </div>
                </div>
              )}
              {report.Screenshot && (
                <div className="summary-item">
                  <div className="summary-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>
                  </div>
                  <div className="summary-data">
                    <div className="summary-value">{report.Screenshot.total_screenshots || 0}</div>
                    <div className="summary-label">Screenshots</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* AI Executive Summary if available */}
      {report?.AIGuided?.executive_summary && (
        <div className="card" style={{ marginTop: 24 }}>
          <div className="card-header">
            <h2>🤖 AI Security Summary</h2>
          </div>
          <div className="card-body">
            <div className="ai-summary" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* One-liner summary */}
              {report.AIGuided.executive_summary.one_liner && (
                <div className="summary-section" style={{
                  padding: '16px',
                  background: 'var(--bg-secondary)',
                  borderRadius: '8px',
                  borderLeft: '4px solid var(--accent)'
                }}>
                  <p style={{ margin: 0, fontSize: '16px', lineHeight: '1.6' }}>
                    {colorizeText(report.AIGuided.executive_summary.one_liner)}
                  </p>
                </div>
              )}

              {/* Risk Assessment */}
              {report.AIGuided.executive_summary.risk_assessment && (
                <div className="risk-section">
                  <h3 style={{ margin: '0 0 12px 0', fontSize: '14px', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                    Risk Assessment
                  </h3>
                  <div style={{
                    padding: '12px 16px',
                    background: 'var(--bg-secondary)',
                    borderRadius: '6px',
                    fontSize: '15px'
                  }}>
                    {colorizeText(report.AIGuided.executive_summary.risk_assessment)}
                  </div>
                </div>
              )}

              {/* Key Findings */}
              {report.AIGuided.executive_summary.key_findings && report.AIGuided.executive_summary.key_findings.length > 0 && (
                <div className="findings-section">
                  <h3 style={{ margin: '0 0 12px 0', fontSize: '14px', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                    Key Findings
                  </h3>
                  <ul style={{ margin: 0, paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {report.AIGuided.executive_summary.key_findings.map((finding, idx) => (
                      <li key={idx} style={{ lineHeight: '1.6' }}>{colorizeText(finding)}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Immediate Actions */}
              {report.AIGuided.executive_summary.immediate_actions && report.AIGuided.executive_summary.immediate_actions.length > 0 && (
                <div className="actions-section">
                  <h3 style={{ margin: '0 0 12px 0', fontSize: '14px', fontWeight: 600, textTransform: 'uppercase', color: 'var(--critical)' }}>
                    Immediate Actions Required
                  </h3>
                  <ul style={{ margin: 0, paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {report.AIGuided.executive_summary.immediate_actions.map((action, idx) => (
                      <li key={idx} style={{ lineHeight: '1.6', color: 'var(--critical)' }}>{colorizeText(action)}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Business Impact */}
              {report.AIGuided.executive_summary.business_impact && (
                <div className="impact-section">
                  <h3 style={{ margin: '0 0 12px 0', fontSize: '14px', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                    Business Impact
                  </h3>
                  <div style={{
                    padding: '12px 16px',
                    background: 'var(--bg-secondary)',
                    borderRadius: '6px',
                    fontSize: '15px',
                    lineHeight: '1.6'
                  }}>
                    {report.AIGuided.executive_summary.business_impact}
                  </div>
                </div>
              )}

              {/* Recommended Next Steps */}
              {report.AIGuided.executive_summary.recommended_next_steps && report.AIGuided.executive_summary.recommended_next_steps.length > 0 && (
                <div className="next-steps-section">
                  <h3 style={{ margin: '0 0 12px 0', fontSize: '14px', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                    📋 Recommended Next Steps
                  </h3>
                  <ul style={{ margin: 0, paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {report.AIGuided.executive_summary.recommended_next_steps.map((step, idx) => (
                      <li key={idx} style={{ lineHeight: '1.6' }}>{step}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function AssetsTab({ report }) {
  const [filter, setFilter] = useState('')

  // Extract data from report
  const subdomains = report?.Subdomain?.subdomains || []
  const aliveHosts = report?.Ports?.alive_hosts || []
  const techByHost = report?.Tech?.tech_by_host || {}
  const openPorts = report?.Ports?.open_ports || {}
  const tlsInfo = report?.Ports?.tls_info || {}

  // Build asset table rows
  const assetRows = subdomains.map(host => {
    const techs = techByHost[host] || []
    const ports = openPorts[host] || []
    const tls = tlsInfo[host] || {}
    const isAlive = aliveHosts.some(url => url.includes(host))

    // Format SSL certificate info
    let sslInfo = '-'
    if (tls.issuer || tls.subject) {
      sslInfo = tls.issuer || tls.subject
      if (tls.days_left !== undefined) {
        sslInfo += ` (${tls.days_left} days left)`
      }
    }

    return {
      host,
      isAlive,
      technologies: techs.join(', ') || '-',
      ports: ports.length > 0 ? [...new Set(ports)].join(', ') : '-',
      ssl: sslInfo,
      httpStatus: '-', // TODO: Add HTTP probe data
      title: '-' // TODO: Add HTTP probe data
    }
  })

  const filteredRows = assetRows.filter(row =>
    row.host.toLowerCase().includes(filter.toLowerCase())
  )

  return (
    <div className="assets-tab">
      {/* Search */}
      <div className="search-bar">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
        </svg>
        <input
          type="text"
          placeholder="Search assets..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>

      {/* Assets Table */}
      <div className="card">
        <div className="card-header">
          <h3>Assets ({filteredRows.length})</h3>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {filteredRows.length === 0 ? (
            <div className="empty-state" style={{ padding: '60px 20px' }}>
              <h3>No assets found</h3>
              <p>Try adjusting your search filter</p>
            </div>
          ) : (
            <div className="table-container">
              <table className="assets-table">
                <thead>
                  <tr>
                    <th style={{ width: '60px' }}>Sr No</th>
                    <th style={{ width: '30%' }}>Asset</th>
                    <th style={{ width: '25%' }}>Technologies</th>
                    <th style={{ width: '15%' }}>Ports</th>
                    <th style={{ width: '30%' }}>SSL Certificate</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRows.slice(0, 200).map((row, idx) => (
                    <tr key={idx} className={row.isAlive ? 'alive-row' : ''}>
                      <td style={{ textAlign: 'center', color: 'var(--text-secondary)', fontSize: 13 }}>
                        {idx + 1}
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <code style={{ fontSize: 13 }}>{row.host}</code>
                          {row.isAlive && (
                            <span className="status-dot" style={{ width: 6, height: 6, background: '#10b981', borderRadius: '50%' }} title="Alive"></span>
                          )}
                        </div>
                      </td>
                      <td>
                        <div className="tech-tags">
                          {row.technologies === '-' ? (
                            <span style={{ color: 'var(--text-secondary)', fontSize: 13 }}>-</span>
                          ) : (
                            row.technologies.split(', ').map((tech, i) => (
                              <span key={i} className="tech-tag">{tech}</span>
                            ))
                          )}
                        </div>
                      </td>
                      <td>
                        <div className="port-tags">
                          {row.ports === '-' ? (
                            <span style={{ color: 'var(--text-secondary)', fontSize: 13 }}>-</span>
                          ) : (
                            row.ports.split(', ').map((port, i) => (
                              <span key={i} className="port-tag">{port}</span>
                            ))
                          )}
                        </div>
                      </td>
                      <td>
                        <span style={{ fontSize: 13, color: row.ssl === '-' ? 'var(--text-secondary)' : 'var(--text)' }}>
                          {row.ssl.length > 40 ? row.ssl.substring(0, 40) + '...' : row.ssl}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {filteredRows.length > 200 && (
            <div style={{ padding: 16, textAlign: 'center', color: 'var(--text-secondary)', fontSize: 13, borderTop: '1px solid var(--border)' }}>
              Showing first 200 of {filteredRows.length} assets
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ScreenshotsTab({ report, scan }) {
  const [lightbox, setLightbox] = useState(null)
  const screenshots = report?.Screenshot?.screenshots || []

  if (screenshots.length === 0) {
    return (
      <div className="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 48, height: 48 }}>
          <rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/>
        </svg>
        <h3>No screenshots available</h3>
        <p>Screenshots are captured during the scan process</p>
      </div>
    )
  }

  return (
    <div className="screenshots-tab">
      <div className="screenshots-grid">
        {screenshots.map((ss, idx) => (
          <div key={idx} className="screenshot-card" onClick={() => setLightbox(ss)}>
            <div className="screenshot-img">
              <img
                src={`/scan-data/${ss.file_path}`}
                alt={ss.url}
                onError={(e) => { e.target.src = 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">?</text></svg>' }}
              />
            </div>
            <div className="screenshot-info">
              <div className="screenshot-url">{ss.url}</div>
              {ss.title && <div className="screenshot-title">{ss.title}</div>}
            </div>
          </div>
        ))}
      </div>

      {/* Lightbox */}
      {lightbox && (
        <div className="lightbox" onClick={() => setLightbox(null)}>
          <div className="lightbox-content" onClick={(e) => e.stopPropagation()}>
            <button className="lightbox-close" onClick={() => setLightbox(null)}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
              </svg>
            </button>
            <img src={`/scan-data/${lightbox.file_path}`} alt={lightbox.url} />
            <div className="lightbox-info">
              <h3>{lightbox.url}</h3>
              {lightbox.title && <p>{lightbox.title}</p>}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function VulnerabilitiesTab({ findings, filters, onFilterChange }) {
  const [vulnData, setVulnData] = useState(findings)

  // Update vuln data when findings prop changes
  useEffect(() => {
    setVulnData(findings)
  }, [findings])

  const handleVulnUpdate = (vulnId, updates) => {
    setVulnData(prev => prev.map(v =>
      v.id === vulnId ? { ...v, ...updates } : v
    ))
  }

  const toggleSeverity = (severity) => {
    const newSeverities = filters.severities.includes(severity)
      ? filters.severities.filter(s => s !== severity)
      : [...filters.severities, severity]
    onFilterChange({ ...filters, severities: newSeverities })
  }

  const severityButtons = [
    { value: 'critical', label: 'Critical', color: 'var(--critical)' },
    { value: 'high', label: 'High', color: 'var(--high)' },
    { value: 'medium', label: 'Medium', color: 'var(--medium)' },
    { value: 'low', label: 'Low', color: 'var(--low)' },
    { value: 'info', label: 'Info', color: 'var(--info)' }
  ]

  return (
    <div className="vulnerabilities-tab">
      {/* Quick Severity Filters */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 20, flexWrap: 'wrap' }}>
        {severityButtons.map(sev => (
          <button
            key={sev.value}
            onClick={() => toggleSeverity(sev.value)}
            style={{
              padding: '10px 20px',
              borderRadius: 8,
              fontSize: 13,
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.2s',
              background: filters.severities.includes(sev.value) ? `${sev.color}20` : 'var(--bg-secondary)',
              color: filters.severities.includes(sev.value) ? sev.color : 'var(--text-secondary)',
              border: filters.severities.includes(sev.value) ? `2px solid ${sev.color}` : '2px solid var(--border)',
            }}
          >
            {sev.label}
          </button>
        ))}
      </div>

      {/* Advanced Filters */}
      <div style={{ marginBottom: 24 }}>
        <FindingsFilter
          onFilterChange={onFilterChange}
          initialFilters={filters}
        />
      </div>

      {/* Findings List */}
      <div className="findings-list">
        {vulnData.length === 0 ? (
          <div className="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 48, height: 48 }}>
              <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
            <h3>No vulnerabilities found</h3>
            <p>No findings match your current filters</p>
          </div>
        ) : (
          vulnData.map((finding, idx) => (
            <FindingItem key={finding.id || idx} finding={finding} onUpdate={handleVulnUpdate} />
          ))
        )}
      </div>
    </div>
  )
}

function FindingItem({ finding, onUpdate }) {
  const [expanded, setExpanded] = useState(false)
  const [showFPModal, setShowFPModal] = useState(false)
  const [fpReason, setFpReason] = useState('')
  const [loading, setLoading] = useState(false)

  const badgeClass = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low', info: 'badge-info' }[finding.severity] || 'badge-info'

  // Parse URL that may contain matcher text like "param id is reflected and allows " on http://..."
  const parseUrl = (urlString) => {
    if (!urlString) return { url: '', host: '', matcher: '' }

    // Check if URL contains matcher text (format: "matcher text on URL")
    const onMatch = urlString.match(/^(.+?)\s+on\s+(https?:\/\/.+)$/i)
    if (onMatch) {
      const matcher = onMatch[1].trim()
      const url = onMatch[2].trim()
      try {
        const urlObj = new URL(url)
        return { url, host: urlObj.hostname, matcher }
      } catch (e) {
        return { url, host: url, matcher }
      }
    }

    // Regular URL without matcher
    try {
      const urlObj = new URL(urlString)
      return { url: urlString, host: urlObj.hostname, matcher: '' }
    } catch (e) {
      return { url: urlString, host: urlString, matcher: '' }
    }
  }

  const parsed = parseUrl(finding.url)
  const displayUrl = parsed.url || finding.url
  const displayHost = parsed.host || finding.host
  const matcherText = parsed.matcher

  // Get enhanced vulnerability description
  const enhancedVuln = getVulnDescription(finding)

  const handleMarkFP = async () => {
    if (!fpReason.trim()) {
      alert('Please provide a reason for marking as false positive')
      return
    }
    setLoading(true)
    try {
      await api.post(`/vulnerabilities/${finding.id}/mark-fp`, {
        reason: fpReason,
        marked_by: 'analyst'
      })
      onUpdate(finding.id, {
        is_false_positive: true,
        fp_reason: fpReason,
        marked_at: new Date().toISOString()
      })
      setShowFPModal(false)
      setFpReason('')
    } catch (error) {
      alert('Failed to mark as false positive: ' + error.message)
    } finally {
      setLoading(false)
    }
  }

  const handleUnmarkFP = async () => {
    setLoading(true)
    try {
      await api.delete(`/vulnerabilities/${finding.id}/mark-fp`)
      onUpdate(finding.id, {
        is_false_positive: false,
        fp_reason: null,
        marked_at: null
      })
    } catch (error) {
      alert('Failed to unmark false positive: ' + error.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <div className={`finding-item ${finding.severity} ${finding.is_false_positive ? 'false-positive' : ''}`}>
        <div className="finding-header" onClick={() => setExpanded(!expanded)}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1 }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)', transition: 'transform 0.2s', color: 'var(--text-muted)', flexShrink: 0 }}>
              <polyline points="6 9 12 15 18 9" style={{ transform: 'rotate(-90deg)', transformOrigin: 'center' }} />
            </svg>
            <div className="finding-title" style={{ flex: 1 }}>
              {finding.name}
              {finding.is_false_positive && <span className="fp-badge">FP</span>}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className={`badge ${badgeClass}`}>{finding.severity}</span>
            {finding.tool && <span className="tool-badge" style={{ fontSize: '0.7rem' }}>{finding.tool}</span>}
          </div>
        </div>

        <div className="finding-summary" style={{ padding: '8px 16px', display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          {displayUrl && (() => {
            // For summary, show hostname + path without long query params
            try {
              const urlObj = new URL(displayUrl)
              const shortUrl = urlObj.origin + urlObj.pathname + (urlObj.search.length > 20 ? urlObj.search.substring(0, 20) + '...' : urlObj.search)
              return (
                <a
                  href={displayUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  style={{
                    color: 'var(--accent)',
                    textDecoration: 'none',
                    fontFamily: 'monospace',
                    fontSize: 13,
                    maxWidth: '600px',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap'
                  }}
                  title={displayUrl}
                >
                  {shortUrl}
                </a>
              )
            } catch (e) {
              return (
                <a
                  href={displayUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  style={{
                    color: 'var(--accent)',
                    textDecoration: 'none',
                    fontFamily: 'monospace',
                    fontSize: 13,
                    maxWidth: '600px',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap'
                  }}
                  title={displayUrl}
                >
                  {displayUrl.length > 80 ? displayUrl.substring(0, 80) + '...' : displayUrl}
                </a>
              )
            }
          })()}
          {displayHost && !displayUrl && <code>{displayHost}</code>}
          {finding.type && (
            <span style={{
              padding: '3px 10px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              borderRadius: '12px',
              fontSize: '0.7rem',
              color: 'var(--text-muted)',
              fontWeight: 500
            }}>
              {finding.type}
            </span>
          )}
        </div>

        {expanded && (
          <div className="finding-expanded" style={{ padding: '16px', borderTop: '1px solid var(--border)', background: 'var(--bg-secondary)' }}>
            {/* Detail Grid */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '16px',
              marginBottom: '16px'
            }}>
              {(displayUrl || displayHost) && (
                <div className="vuln-detail-section">
                  <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '6px' }}>
                    Target
                  </div>
                  <div style={{ fontSize: '0.9rem' }}>
                    {displayUrl ? (
                      <a href={displayUrl} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()} style={{ color: 'var(--accent)', textDecoration: 'none' }}>
                        {displayHost || displayUrl}
                      </a>
                    ) : (
                      <code>{displayHost}</code>
                    )}
                  </div>
                </div>
              )}

              {matcherText && (
                <div className="vuln-detail-section">
                  <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '6px' }}>
                    Matcher
                  </div>
                  <div style={{ fontSize: '0.9rem', fontStyle: 'italic', color: 'var(--accent)' }}>
                    {matcherText}
                  </div>
                </div>
              )}

              {finding.type && (
                <div className="vuln-detail-section">
                  <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '6px' }}>
                    Type
                  </div>
                  <div style={{ fontSize: '0.9rem' }}>{finding.type}</div>
                </div>
              )}

              {finding.template_id && (
                <div className="vuln-detail-section">
                  <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '6px' }}>
                    Template ID
                  </div>
                  <div style={{ fontSize: '0.9rem', fontFamily: 'monospace' }}>{finding.template_id}</div>
                </div>
              )}

              {finding.cvss && (
                <div className="vuln-detail-section">
                  <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '6px' }}>
                    CVSS Score
                  </div>
                  <div style={{ fontSize: '0.9rem' }}>{finding.cvss}</div>
                </div>
              )}

              {finding.cwe && (
                <div className="vuln-detail-section">
                  <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '6px' }}>
                    CWE
                  </div>
                  <div style={{ fontSize: '0.9rem' }}>{finding.cwe}</div>
                </div>
              )}
            </div>

            {/* Enhanced Description */}
            {enhancedVuln.description && (
              <div className="vuln-detail-section" style={{ marginTop: '16px' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '6px' }}>
                  Description
                </div>
                <div style={{ fontSize: '0.9rem', lineHeight: '1.6', whiteSpace: 'pre-wrap' }}>
                  {enhancedVuln.description}
                </div>
              </div>
            )}

            {/* Impact */}
            {enhancedVuln.impact && (
              <div className="vuln-detail-section" style={{ marginTop: '16px', padding: '12px', background: 'rgba(234, 88, 12, 0.08)', borderRadius: '6px', borderLeft: '3px solid var(--high)' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--high)', marginBottom: '6px' }}>
                  ⚠️ Impact
                </div>
                <div style={{ fontSize: '0.9rem', lineHeight: '1.6' }}>
                  {enhancedVuln.impact}
                </div>
              </div>
            )}

            {/* Remediation */}
            {enhancedVuln.remediation && (
              <div className="vuln-detail-section" style={{ marginTop: '16px', padding: '12px', background: 'rgba(34, 197, 94, 0.08)', borderRadius: '6px', borderLeft: '3px solid var(--success)' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--success)', marginBottom: '6px' }}>
                  ✓ Remediation
                </div>
                <div style={{ fontSize: '0.9rem', lineHeight: '1.6' }}>
                  {enhancedVuln.remediation}
                </div>
              </div>
            )}

            {/* Reference */}
            {finding.reference && (
              <div className="vuln-detail-section" style={{ marginTop: '12px' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '6px' }}>
                  Reference
                </div>
                <div style={{ fontSize: '0.9rem' }}>
                  <a href={finding.reference} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>
                    {finding.reference}
                  </a>
                </div>
              </div>
            )}

            {/* False Positive Info */}
            {finding.is_false_positive && finding.fp_reason && (
              <div className="fp-info" style={{ marginTop: '16px', padding: '12px', background: 'var(--bg-primary)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '6px' }}>
                  False Positive Reason
                </div>
                <div>{finding.fp_reason}</div>
                {finding.marked_at && (
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                    Marked: {new Date(finding.marked_at).toLocaleString()}
                  </div>
                )}
              </div>
            )}

            {/* Notes */}
            {finding.notes && (
              <div className="vuln-notes" style={{ marginTop: '16px', padding: '12px', background: 'var(--bg-primary)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '6px' }}>
                  Notes
                </div>
                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontFamily: 'inherit', fontSize: '0.9rem' }}>{finding.notes}</pre>
              </div>
            )}

            {/* Actions */}
            <div className="finding-actions" style={{ marginTop: '16px', display: 'flex', gap: '8px' }}>
              {!finding.is_false_positive ? (
                <button className="btn btn-sm btn-secondary" onClick={(e) => { e.stopPropagation(); setShowFPModal(true) }} disabled={loading}>
                  Mark as False Positive
                </button>
              ) : (
                <button className="btn btn-sm btn-secondary" onClick={(e) => { e.stopPropagation(); handleUnmarkFP() }} disabled={loading}>
                  Unmark False Positive
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Mark FP Modal */}
      {showFPModal && (
        <div className="modal-overlay" onClick={() => setShowFPModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Mark as False Positive</h3>
            <p>Please provide a reason for marking this vulnerability as a false positive:</p>
            <textarea
              value={fpReason}
              onChange={(e) => setFpReason(e.target.value)}
              placeholder="e.g., Expected behavior, authentication required, etc."
              rows="4"
              style={{ width: '100%', padding: '8px', marginBottom: '16px' }}
            />
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button className="btn btn-secondary" onClick={() => setShowFPModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleMarkFP} disabled={loading}>
                {loading ? 'Saving...' : 'Mark as FP'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

function SecurityHeadersTab({ report }) {
  const secHeaders = report?.SecHeaders

  if (!secHeaders) {
    return (
      <div className="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 48, height: 48 }}>
          <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
        </svg>
        <h3>No security headers data</h3>
        <p>Security headers check was not part of this scan</p>
      </div>
    )
  }

  return (
    <div className="security-headers-tab">
      {/* Summary Stats */}
      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', marginBottom: 16, gap: 12 }}>
        <div className="stat-card" style={{ padding: 16 }}>
          <div className="label" style={{ fontSize: 12, marginBottom: 6 }}>Hosts Scanned</div>
          <div className="value" style={{ fontSize: 1.8 + 'rem' }}>{secHeaders.total_scanned || 0}</div>
        </div>
        <div className="stat-card" style={{ padding: 16 }}>
          <div className="label" style={{ fontSize: 12, marginBottom: 6 }}>Missing Headers</div>
          <div className="value" style={{ fontSize: 1.8 + 'rem' }}>{secHeaders.missing_headers || 0}</div>
        </div>
        <div className="stat-card" style={{ padding: 16 }}>
          <div className="label" style={{ fontSize: 12, marginBottom: 6 }}>Weak Configurations</div>
          <div className="value" style={{ fontSize: 1.8 + 'rem' }}>{secHeaders.weak_headers || 0}</div>
        </div>
        <div className="stat-card" style={{ padding: 16 }}>
          <div className="label" style={{ fontSize: 12, marginBottom: 6 }}>Email Issues</div>
          <div className="value" style={{ fontSize: 1.8 + 'rem' }}>{secHeaders.email_issues || 0}</div>
        </div>
        <div className="stat-card" style={{ padding: 16 }}>
          <div className="label" style={{ fontSize: 12, marginBottom: 6 }}>DNS Issues</div>
          <div className="value" style={{ fontSize: 1.8 + 'rem' }}>{secHeaders.dns_issues || 0}</div>
        </div>
        <div className="stat-card" style={{ padding: 16 }}>
          <div className="label" style={{ fontSize: 12, marginBottom: 6 }}>Misconfigurations</div>
          <div className="value high" style={{ fontSize: 1.8 + 'rem' }}>{secHeaders.misconfig_count || 0}</div>
        </div>
      </div>

      {/* DNS Security */}
      {secHeaders.dns_security && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header">
            <h2>DNS Security</h2>
            <div style={{
              display: 'inline-block',
              padding: '4px 10px',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 600,
              background: secHeaders.dns_security.score >= 80 ? 'rgba(16, 185, 129, 0.1)' :
                          secHeaders.dns_security.score >= 60 ? 'rgba(245, 158, 11, 0.1)' :
                          'rgba(239, 68, 68, 0.1)',
              color: secHeaders.dns_security.score >= 80 ? '#10b981' :
                     secHeaders.dns_security.score >= 60 ? '#f59e0b' :
                     '#ef4444',
              marginLeft: 8
            }}>
              Score: {secHeaders.dns_security.score}/100
            </div>
          </div>
          <div className="card-body">
            <div style={{ display: 'grid', gap: 12 }}>
              {/* CAA Records */}
              {secHeaders.dns_security.caa && (
                <div style={{ padding: 10, background: 'var(--bg-secondary)', borderRadius: 6 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <h3 style={{ fontSize: 14, fontWeight: 600 }}>CAA (Certificate Authority Authorization)</h3>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 600,
                      background: secHeaders.dns_security.caa.has_records ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                      color: secHeaders.dns_security.caa.has_records ? '#10b981' : '#ef4444'
                    }}>
                      {secHeaders.dns_security.caa.has_records ? 'CONFIGURED' : 'NOT CONFIGURED'}
                    </span>
                  </div>
                  {secHeaders.dns_security.caa.records && secHeaders.dns_security.caa.records.length > 0 && (
                    <div style={{ fontSize: 12, marginBottom: 8 }}>
                      {secHeaders.dns_security.caa.records.map((rec, i) => (
                        <div key={i} style={{ fontFamily: 'monospace', padding: 4 }}>
                          {rec.tag}: {rec.value}
                        </div>
                      ))}
                    </div>
                  )}
                  {secHeaders.dns_security.caa.issues && secHeaders.dns_security.caa.issues.length > 0 && (
                    <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12, color: 'var(--text-secondary)' }}>
                      {secHeaders.dns_security.caa.issues.map((issue, i) => (
                        <li key={i}>{issue}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* DNSSEC */}
              {secHeaders.dns_security.dnssec && (
                <div style={{ padding: 10, background: 'var(--bg-secondary)', borderRadius: 6 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <h3 style={{ fontSize: 14, fontWeight: 600 }}>DNSSEC</h3>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 600,
                      background: secHeaders.dns_security.dnssec.enabled ? (secHeaders.dns_security.dnssec.validated ? 'rgba(16, 185, 129, 0.1)' : 'rgba(245, 158, 11, 0.1)') : 'rgba(239, 68, 68, 0.1)',
                      color: secHeaders.dns_security.dnssec.enabled ? (secHeaders.dns_security.dnssec.validated ? '#10b981' : '#f59e0b') : '#ef4444'
                    }}>
                      {secHeaders.dns_security.dnssec.enabled ? (secHeaders.dns_security.dnssec.validated ? 'VALIDATED' : 'ENABLED') : 'DISABLED'}
                    </span>
                  </div>
                  {secHeaders.dns_security.dnssec.issues && secHeaders.dns_security.dnssec.issues.length > 0 && (
                    <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12, color: 'var(--text-secondary)' }}>
                      {secHeaders.dns_security.dnssec.issues.map((issue, i) => (
                        <li key={i}>{issue}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* Zone Transfer */}
              {secHeaders.dns_security.zone_transfer && (
                <div style={{ padding: 10, background: 'var(--bg-secondary)', borderRadius: 6 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <h3 style={{ fontSize: 14, fontWeight: 600 }}>Zone Transfer (AXFR)</h3>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 600,
                      background: secHeaders.dns_security.zone_transfer.vulnerable ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
                      color: secHeaders.dns_security.zone_transfer.vulnerable ? '#ef4444' : '#10b981'
                    }}>
                      {secHeaders.dns_security.zone_transfer.vulnerable ? 'VULNERABLE' : 'PROTECTED'}
                    </span>
                  </div>
                  {secHeaders.dns_security.zone_transfer.vulnerable && secHeaders.dns_security.zone_transfer.vulnerable_ns && (
                    <div style={{ fontSize: 12, color: '#ef4444', marginTop: 6 }}>
                      Vulnerable nameservers: {secHeaders.dns_security.zone_transfer.vulnerable_ns.join(', ')}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Email Security */}
      {secHeaders.email_security && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header">
            <h2>Email Security (SPF/DKIM/DMARC)</h2>
            <div style={{
              display: 'inline-block',
              padding: '4px 10px',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 600,
              background: secHeaders.email_security.score >= 80 ? 'rgba(16, 185, 129, 0.1)' :
                          secHeaders.email_security.score >= 60 ? 'rgba(245, 158, 11, 0.1)' :
                          'rgba(239, 68, 68, 0.1)',
              color: secHeaders.email_security.score >= 80 ? '#10b981' :
                     secHeaders.email_security.score >= 60 ? '#f59e0b' :
                     '#ef4444',
              marginLeft: 8
            }}>
              Score: {secHeaders.email_security.score}/100
            </div>
          </div>
          <div className="card-body">
            <div style={{ display: 'grid', gap: 12 }}>
              {/* SPF */}
              {secHeaders.email_security.spf && (
                <div style={{ padding: 10, background: 'var(--bg-secondary)', borderRadius: 6 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <h3 style={{ fontSize: 14, fontWeight: 600 }}>SPF (Sender Policy Framework)</h3>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 600,
                      background: secHeaders.email_security.spf.found ? (secHeaders.email_security.spf.valid ? 'rgba(16, 185, 129, 0.1)' : 'rgba(245, 158, 11, 0.1)') : 'rgba(239, 68, 68, 0.1)',
                      color: secHeaders.email_security.spf.found ? (secHeaders.email_security.spf.valid ? '#10b981' : '#f59e0b') : '#ef4444'
                    }}>
                      {secHeaders.email_security.spf.found ? (secHeaders.email_security.spf.valid ? 'VALID' : 'ISSUES') : 'MISSING'}
                    </span>
                  </div>
                  {secHeaders.email_security.spf.record && (
                    <div style={{ fontSize: 12, fontFamily: 'monospace', background: 'var(--bg)', padding: 8, borderRadius: 4, marginBottom: 8, wordBreak: 'break-all' }}>
                      {secHeaders.email_security.spf.record}
                    </div>
                  )}
                  {secHeaders.email_security.spf.issues && secHeaders.email_security.spf.issues.length > 0 && (
                    <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12, color: 'var(--text-secondary)' }}>
                      {secHeaders.email_security.spf.issues.map((issue, i) => (
                        <li key={i}>{issue}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* DKIM */}
              {secHeaders.email_security.dkim && (
                <div style={{ padding: 10, background: 'var(--bg-secondary)', borderRadius: 6 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <h3 style={{ fontSize: 14, fontWeight: 600 }}>DKIM (DomainKeys Identified Mail)</h3>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 600,
                      background: secHeaders.email_security.dkim.found ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                      color: secHeaders.email_security.dkim.found ? '#10b981' : '#ef4444'
                    }}>
                      {secHeaders.email_security.dkim.found ? 'FOUND' : 'NOT FOUND'}
                    </span>
                  </div>
                  {secHeaders.email_security.dkim.selectors && secHeaders.email_security.dkim.selectors.length > 0 && (
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
                      Selectors: {secHeaders.email_security.dkim.selectors.join(', ')}
                    </div>
                  )}
                  {secHeaders.email_security.dkim.issues && secHeaders.email_security.dkim.issues.length > 0 && (
                    <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12, color: 'var(--text-secondary)' }}>
                      {secHeaders.email_security.dkim.issues.map((issue, i) => (
                        <li key={i}>{issue}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* DMARC */}
              {secHeaders.email_security.dmarc && (
                <div style={{ padding: 10, background: 'var(--bg-secondary)', borderRadius: 6 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <h3 style={{ fontSize: 14, fontWeight: 600 }}>DMARC (Domain-based Message Authentication)</h3>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 600,
                      background: secHeaders.email_security.dmarc.found ? (secHeaders.email_security.dmarc.policy === 'reject' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(245, 158, 11, 0.1)') : 'rgba(239, 68, 68, 0.1)',
                      color: secHeaders.email_security.dmarc.found ? (secHeaders.email_security.dmarc.policy === 'reject' ? '#10b981' : '#f59e0b') : '#ef4444'
                    }}>
                      {secHeaders.email_security.dmarc.found ? secHeaders.email_security.dmarc.policy?.toUpperCase() || 'FOUND' : 'MISSING'}
                    </span>
                  </div>
                  {secHeaders.email_security.dmarc.record && (
                    <div style={{ fontSize: 12, fontFamily: 'monospace', background: 'var(--bg)', padding: 8, borderRadius: 4, marginBottom: 8, wordBreak: 'break-all' }}>
                      {secHeaders.email_security.dmarc.record}
                    </div>
                  )}
                  {secHeaders.email_security.dmarc.issues && secHeaders.email_security.dmarc.issues.length > 0 && (
                    <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12, color: 'var(--text-secondary)' }}>
                      {secHeaders.email_security.dmarc.issues.map((issue, i) => (
                        <li key={i}>{issue}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* HTTP Security Headers Findings */}
      {secHeaders.header_findings && secHeaders.header_findings.length > 0 && (() => {
        // Calculate combined security headers score (use lowest score, not average)
        const scores = secHeaders.header_findings.map(f => f.score || 0)
        const lowestScore = scores.length > 0 ? Math.min(...scores) : 0
        const getGrade = (score) => {
          if (score >= 90) return 'A'
          if (score >= 80) return 'B'
          if (score >= 70) return 'C'
          if (score >= 60) return 'D'
          return 'F'
        }
        const grade = getGrade(lowestScore)

        return (
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-header">
              <h2>HTTP Security Headers</h2>
              <div style={{
                display: 'inline-block',
                padding: '4px 10px',
                borderRadius: 6,
                fontSize: 12,
                fontWeight: 600,
                background: lowestScore >= 80 ? 'rgba(16, 185, 129, 0.1)' :
                            lowestScore >= 60 ? 'rgba(245, 158, 11, 0.1)' :
                            'rgba(239, 68, 68, 0.1)',
                color: lowestScore >= 80 ? '#10b981' :
                       lowestScore >= 60 ? '#f59e0b' :
                       '#ef4444',
                marginLeft: 8
              }}>
                Score: {lowestScore}/100
              </div>
            </div>
            <div className="card-body" style={{ padding: 0 }}>
            {secHeaders.header_findings.map((finding, idx) => (
              <div key={idx} style={{
                padding: 12,
                borderBottom: idx < secHeaders.header_findings.length - 1 ? '1px solid var(--border)' : 'none'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 4 }}>{finding.host}</div>
                    <a href={finding.url} target="_blank" rel="noopener noreferrer" style={{ fontSize: 12, color: 'var(--accent)' }}>
                      {finding.url}
                    </a>
                  </div>
                  <div style={{
                    padding: '6px 12px',
                    borderRadius: 6,
                    fontSize: 13,
                    fontWeight: 600,
                    background: finding.score >= 80 ? 'rgba(16, 185, 129, 0.1)' :
                                finding.score >= 60 ? 'rgba(245, 158, 11, 0.1)' :
                                'rgba(239, 68, 68, 0.1)',
                    color: finding.score >= 80 ? '#10b981' :
                           finding.score >= 60 ? '#f59e0b' :
                           '#ef4444'
                  }}>
                    Score: {finding.score}/100
                  </div>
                </div>

                {finding.missing && finding.missing.length > 0 && (
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
                      MISSING HEADERS ({finding.missing.length}):
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                      {finding.missing.map((issue, i) => {
                        const severityColor = issue.severity === 'critical' ? 'var(--critical)' :
                                            issue.severity === 'high' ? 'var(--high)' :
                                            issue.severity === 'medium' ? 'var(--medium)' :
                                            'var(--text-secondary)'
                        return (
                          <div key={i} style={{
                            padding: '4px 8px',
                            background: 'var(--bg-secondary)',
                            borderRadius: 4,
                            border: '1px solid var(--border)',
                            fontSize: 11
                          }}>
                            <span style={{ fontWeight: 600, color: severityColor }}>{issue.header}</span>
                            <span style={{ color: 'var(--text-secondary)', marginLeft: 4 }}>({issue.severity})</span>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {finding.weak && finding.weak.length > 0 && (
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
                      WEAK CONFIGURATIONS ({finding.weak.length}):
                    </div>
                    {finding.weak.map((issue, i) => (
                      <div key={i} style={{
                        padding: '8px 12px',
                        background: 'var(--bg-secondary)',
                        borderRadius: 4,
                        marginBottom: 6,
                        fontSize: 12
                      }}>
                        <div style={{ fontWeight: 600, marginBottom: 2 }}>{issue.header}</div>
                        <div style={{ color: 'var(--text-secondary)' }}>{issue.description}</div>
                      </div>
                    ))}
                  </div>
                )}

                {finding.present && finding.present.length > 0 && (
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
                      PRESENT ({finding.present.length}):
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {finding.present.map((header, i) => (
                        <span key={i} style={{
                          padding: '2px 6px',
                          background: 'rgba(16, 185, 129, 0.1)',
                          color: '#10b981',
                          borderRadius: 3,
                          fontSize: 11
                        }}>
                          {header}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
        )
      })()}

      {/* Misconfiguration Vulnerabilities from Nuclei */}
      {secHeaders.misconfig_vulns && secHeaders.misconfig_vulns.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h2>Security Misconfigurations</h2>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
              Detected by Nuclei templates
            </p>
          </div>
          <div className="card-body" style={{ padding: 0 }}>
            {secHeaders.misconfig_vulns.map((vuln, idx) => (
              <div key={idx} style={{
                padding: 12,
                borderBottom: idx < secHeaders.misconfig_vulns.length - 1 ? '1px solid var(--border)' : 'none'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 8 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>{vuln.name}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 6 }}>
                      <code>{vuln.host}</code>
                      {vuln.url && <span> • {vuln.url}</span>}
                    </div>
                    {vuln.description && (
                      <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 8 }}>
                        {vuln.description}
                      </div>
                    )}
                  </div>
                  <span className={`badge ${vuln.severity === 'critical' ? 'badge-critical' : vuln.severity === 'high' ? 'badge-high' : vuln.severity === 'medium' ? 'badge-medium' : 'badge-low'}`} style={{ marginLeft: 12 }}>
                    {vuln.severity}
                  </span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                  Template: {vuln.template_id}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function JSAnalysisTab({ report }) {
  if (!report || !report.JSAnalysis) {
    return (
      <div className="empty-state">
        <h3>No JavaScript Analysis</h3>
        <p>JavaScript analysis data is not available for this scan.</p>
      </div>
    )
  }

  const js = report.JSAnalysis
  const domXssCount = js.taint_flows ? js.taint_flows.length : 0
  const endpointsCount = js.endpoints ? js.endpoints.length : 0
  const filesScanned = js.files_scanned || 0

  // Group taint flows by severity
  const flowsBySeverity = (js.taint_flows || []).reduce((acc, flow) => {
    const severity = flow.severity || 'info'
    if (!acc[severity]) acc[severity] = []
    acc[severity].push(flow)
    return acc
  }, {})

  return (
    <div className="js-analysis-tab">
      {/* Summary Card */}
      <div className="card" style={{ marginBottom: 24 }}>
        <h3 style={{ fontSize: '1.25rem', marginBottom: 16 }}>JavaScript Analysis Summary</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
          <div className="stat-card">
            <div className="label">Files Analyzed</div>
            <div className="value" style={{ color: 'var(--accent)' }}>{filesScanned}</div>
          </div>
          <div className="stat-card">
            <div className="label">Endpoints Found</div>
            <div className="value" style={{ color: 'var(--info)' }}>{endpointsCount}</div>
          </div>
          <div className="stat-card">
            <div className="label">DOM XSS Flows</div>
            <div className="value" style={{ color: 'var(--warning)' }}>{domXssCount}</div>
          </div>
        </div>
      </div>

      {/* Taint Flows / DOM XSS Vulnerabilities */}
      {domXssCount > 0 && (
        <div className="card">
          <h3 style={{ fontSize: '1.25rem', marginBottom: 16 }}>Potential DOM XSS Vulnerabilities</h3>
          <p style={{ color: 'var(--text-secondary)', marginBottom: 20, fontSize: '0.9rem' }}>
            Data flows from user-controllable sources to dangerous sinks. Exploitable flows may allow DOM-based XSS attacks.
          </p>

          {/* Show flows grouped by severity */}
          {['critical', 'high', 'medium', 'low'].map(severity => {
            const flows = flowsBySeverity[severity] || []
            if (flows.length === 0) return null

            return (
              <div key={severity} style={{ marginBottom: 24 }}>
                <h4 style={{
                  fontSize: '1rem',
                  marginBottom: 12,
                  color: `var(--${severity})`,
                  textTransform: 'capitalize'
                }}>
                  {severity} Severity ({flows.length})
                </h4>

                <div className="table-container">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Source</th>
                        <th>Sink</th>
                        <th>File</th>
                        <th>Exploitable</th>
                        <th>Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {flows.map((flow, idx) => (
                        <tr key={idx}>
                          <td>
                            <code style={{ fontSize: '0.85rem', color: 'var(--accent)' }}>
                              {flow.source_type}
                            </code>
                            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>
                              Line {flow.source_line}
                            </div>
                          </td>
                          <td>
                            <code style={{ fontSize: '0.85rem', color: 'var(--high)' }}>
                              {flow.sink_type}
                            </code>
                            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>
                              Line {flow.sink_line}
                            </div>
                          </td>
                          <td style={{ maxWidth: 300, fontSize: '0.8rem', wordBreak: 'break-all' }}>
                            <a href={flow.file} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)', textDecoration: 'none' }}>
                              {flow.file}
                            </a>
                          </td>
                          <td>
                            <span className={`badge ${flow.exploitable ? 'badge-critical' : 'badge-low'}`}>
                              {flow.exploitable ? 'Yes' : 'No'}
                            </span>
                          </td>
                          <td style={{ fontSize: '0.85rem' }}>{flow.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Endpoints */}
      {endpointsCount > 0 && (
        <div className="card" style={{ marginTop: 24 }}>
          <h3 style={{ fontSize: '1.25rem', marginBottom: 16 }}>Discovered Endpoints</h3>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Path</th>
                  <th>URL</th>
                  <th>Source File</th>
                  <th>Sensitive</th>
                </tr>
              </thead>
              <tbody>
                {(js.endpoints || []).map((endpoint, idx) => (
                  <tr key={idx}>
                    <td><code>{endpoint.path || '/'}</code></td>
                    <td style={{ fontSize: '0.8rem', wordBreak: 'break-all', maxWidth: 200 }}>
                      {endpoint.url && endpoint.url !== 'N/A' ? (
                        <a href={endpoint.url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)', textDecoration: 'none' }}>
                          {endpoint.url}
                        </a>
                      ) : 'N/A'}
                    </td>
                    <td style={{ fontSize: '0.8rem', wordBreak: 'break-all', maxWidth: 300 }}>
                      <a href={endpoint.source} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)', textDecoration: 'none' }}>
                        {endpoint.source}
                      </a>
                    </td>
                    <td>
                      <span className={`badge ${endpoint.sensitive ? 'badge-high' : 'badge-low'}`}>
                        {endpoint.sensitive ? 'Yes' : 'No'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

export default ScanDetails
