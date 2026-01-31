import { useState, useEffect } from 'react'
import { api } from '../utils/api'
import FindingsFilter from './FindingsFilter'

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
        params.append('severity', filters.severities.join(','))
      }
      if (filters.types.length > 0) {
        params.append('type', filters.types.join(','))
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

      {/* AI Summary if available */}
      {report?.AIGuided?.summary && (
        <div className="card" style={{ marginTop: 24 }}>
          <div className="card-header"><h2>AI Security Summary</h2></div>
          <div className="card-body">
            <div className="ai-summary">
              <p>{report.AIGuided.summary}</p>
              {report.AIGuided.risk_score && (
                <div className="risk-score">
                  <span className="risk-label">Risk Score:</span>
                  <span className={`risk-value ${report.AIGuided.risk_score >= 70 ? 'high' : report.AIGuided.risk_score >= 40 ? 'medium' : 'low'}`}>
                    {report.AIGuided.risk_score}/100
                  </span>
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
  const portDetails = report?.Ports?.port_details || {}
  const tlsInfo = report?.Ports?.tls_info || {}

  // Build asset table rows
  const assetRows = subdomains.map(host => {
    const techs = techByHost[host] || []
    const ports = portDetails[host] || []
    const tls = tlsInfo[host] || {}
    const isAlive = aliveHosts.includes(host)

    return {
      host,
      isAlive,
      technologies: techs.join(', ') || '-',
      ports: ports.length > 0 ? ports.join(', ') : '-',
      ssl: tls.issuer || tls.subject || '-',
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
                    <th style={{ width: '30%' }}>Asset</th>
                    <th style={{ width: '25%' }}>Technologies</th>
                    <th style={{ width: '15%' }}>Ports</th>
                    <th style={{ width: '30%' }}>SSL Certificate</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRows.slice(0, 200).map((row, idx) => (
                    <tr key={idx} className={row.isAlive ? 'alive-row' : ''}>
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
                src={`/${ss.file_path}`}
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
            <img src={`/${lightbox.file_path}`} alt={lightbox.url} />
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

  return (
    <div className="vulnerabilities-tab">
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
  const [showNoteModal, setShowNoteModal] = useState(false)
  const [showFPModal, setShowFPModal] = useState(false)
  const [note, setNote] = useState('')
  const [fpReason, setFpReason] = useState('')
  const [loading, setLoading] = useState(false)

  const badgeClass = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low', info: 'badge-info' }[finding.severity] || 'badge-info'

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

  const handleAddNote = async () => {
    if (!note.trim()) return
    setLoading(true)
    try {
      await api.post(`/vulnerabilities/${finding.id}/note`, { note })
      const currentNotes = finding.notes || ''
      const timestamp = new Date().toLocaleString()
      const newNotes = currentNotes + (currentNotes ? '\n\n' : '') + `[${timestamp}] ${note}`
      onUpdate(finding.id, { notes: newNotes })
      setShowNoteModal(false)
      setNote('')
    } catch (error) {
      alert('Failed to add note: ' + error.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <div className={`finding-item ${finding.severity} ${finding.is_false_positive ? 'false-positive' : ''}`}>
        <div className="finding-header" onClick={() => setExpanded(!expanded)}>
          <span className={`badge ${badgeClass}`}>{finding.severity}</span>
          <div className="finding-title">
            {finding.name}
            {finding.is_false_positive && <span className="fp-badge">FP</span>}
          </div>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ transform: expanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s', color: 'var(--text-muted)' }}>
            <polyline points="6 9 12 15 18 9"/>
          </svg>
        </div>
        <div className="finding-details">
          {finding.url && <code>{finding.url}</code>}
          {finding.host && !finding.url && <code>{finding.host}</code>}
          {finding.template_id && <span className="template-id">[{finding.template_id}]</span>}
          {finding.tool && <span className="tool-badge">{finding.tool}</span>}
        </div>
        {expanded && (
          <div className="finding-expanded">
            {finding.description && <p className="finding-desc">{finding.description}</p>}
            {finding.cvss && <div className="finding-meta"><strong>CVSS:</strong> {finding.cvss}</div>}
            {finding.cwe && <div className="finding-meta"><strong>CWE:</strong> {finding.cwe}</div>}
            {finding.reference && <div className="finding-meta"><strong>Reference:</strong> <a href={finding.reference} target="_blank" rel="noopener noreferrer">{finding.reference}</a></div>}

            {finding.is_false_positive && finding.fp_reason && (
              <div className="fp-info">
                <strong>False Positive Reason:</strong> {finding.fp_reason}
                {finding.marked_at && <div className="fp-date">Marked: {new Date(finding.marked_at).toLocaleString()}</div>}
              </div>
            )}

            {finding.notes && (
              <div className="vuln-notes">
                <strong>Notes:</strong>
                <pre>{finding.notes}</pre>
              </div>
            )}

            <div className="finding-actions">
              {!finding.is_false_positive ? (
                <button className="btn btn-sm btn-secondary" onClick={(e) => { e.stopPropagation(); setShowFPModal(true) }} disabled={loading}>
                  Mark as False Positive
                </button>
              ) : (
                <button className="btn btn-sm btn-secondary" onClick={(e) => { e.stopPropagation(); handleUnmarkFP() }} disabled={loading}>
                  Unmark False Positive
                </button>
              )}
              <button className="btn btn-sm btn-secondary" onClick={(e) => { e.stopPropagation(); setShowNoteModal(true) }} disabled={loading}>
                Add Note
              </button>
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

      {/* Add Note Modal */}
      {showNoteModal && (
        <div className="modal-overlay" onClick={() => setShowNoteModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Add Note</h3>
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Add your notes here..."
              rows="6"
              style={{ width: '100%', padding: '8px', marginBottom: '16px' }}
            />
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button className="btn btn-secondary" onClick={() => setShowNoteModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleAddNote} disabled={loading}>
                {loading ? 'Saving...' : 'Add Note'}
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
      <div className="stats-grid" style={{ marginBottom: 24 }}>
        <div className="stat-card">
          <div className="label">Hosts Scanned</div>
          <div className="value">{secHeaders.total_scanned || 0}</div>
        </div>
        <div className="stat-card">
          <div className="label">Missing Headers</div>
          <div className="value medium">{secHeaders.missing_headers || 0}</div>
        </div>
        <div className="stat-card">
          <div className="label">Weak Configurations</div>
          <div className="value low">{secHeaders.weak_headers || 0}</div>
        </div>
        <div className="stat-card">
          <div className="label">Email Issues</div>
          <div className="value medium">{secHeaders.email_issues || 0}</div>
        </div>
        <div className="stat-card">
          <div className="label">DNS Issues</div>
          <div className="value medium">{secHeaders.dns_issues || 0}</div>
        </div>
        <div className="stat-card">
          <div className="label">Misconfigurations</div>
          <div className="value high">{secHeaders.misconfig_count || 0}</div>
        </div>
      </div>

      {/* HTTP Security Headers Findings */}
      {secHeaders.header_findings && secHeaders.header_findings.length > 0 && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header">
            <h2>HTTP Security Headers</h2>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
              {secHeaders.header_findings.length} hosts analyzed
            </p>
          </div>
          <div className="card-body" style={{ padding: 0 }}>
            {secHeaders.header_findings.map((finding, idx) => (
              <div key={idx} style={{
                padding: 16,
                borderBottom: idx < secHeaders.header_findings.length - 1 ? '1px solid var(--border)' : 'none'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
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
                      {finding.missing.map((issue, i) => (
                        <div key={i} style={{
                          padding: '4px 8px',
                          background: 'var(--bg-secondary)',
                          borderRadius: 4,
                          border: '1px solid var(--border)',
                          fontSize: 11
                        }}>
                          <span style={{ fontWeight: 600, color: '#f59e0b' }}>{issue.header}</span>
                          <span style={{ color: 'var(--text-secondary)', marginLeft: 4 }}>({issue.severity})</span>
                        </div>
                      ))}
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
      )}

      {/* Email Security */}
      {secHeaders.email_security && (
        <div className="card" style={{ marginBottom: 24 }}>
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
            <div style={{ display: 'grid', gap: 16 }}>
              {/* SPF */}
              {secHeaders.email_security.spf && (
                <div style={{ padding: 14, background: 'var(--bg-secondary)', borderRadius: 8 }}>
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
                <div style={{ padding: 14, background: 'var(--bg-secondary)', borderRadius: 8 }}>
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
                <div style={{ padding: 14, background: 'var(--bg-secondary)', borderRadius: 8 }}>
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

      {/* DNS Security */}
      {secHeaders.dns_security && (
        <div className="card" style={{ marginBottom: 24 }}>
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
            <div style={{ display: 'grid', gap: 16 }}>
              {/* CAA Records */}
              {secHeaders.dns_security.caa && (
                <div style={{ padding: 14, background: 'var(--bg-secondary)', borderRadius: 8 }}>
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
                <div style={{ padding: 14, background: 'var(--bg-secondary)', borderRadius: 8 }}>
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
                <div style={{ padding: 14, background: 'var(--bg-secondary)', borderRadius: 8 }}>
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
                padding: 16,
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

export default ScanDetails
