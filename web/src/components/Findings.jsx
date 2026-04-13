import { useState, useEffect } from 'react'
import { api } from '../utils/api'

function Findings({ scan, onBack }) {
  const [findings, setFindings] = useState([])
  const [secrets, setSecrets] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')
  const [tab, setTab] = useState('vulnerabilities')
  const [report, setReport] = useState(null)

  useEffect(() => {
    if (scan?.id) {
      fetchFindings()
      fetchSecrets()
      fetchReport()
    }
  }, [scan?.id])

  const fetchFindings = async () => {
    try {
      const response = await api.get(`/scans/${scan.id}/findings`)
      setFindings(response.findings || [])
    } catch (error) {
      console.error('Failed to fetch findings:', error)
    } finally {
      setLoading(false)
    }
  }

  const fetchSecrets = async () => {
    try {
      const response = await api.get(`/scans/${scan.id}/secrets`)
      setSecrets(response.findings || [])
    } catch (error) {
      console.error('Failed to fetch secrets:', error)
    }
  }

  const fetchReport = async () => {
    try {
      const response = await api.get(`/scans/${scan.id}/report`)
      setReport(response)
    } catch (error) {
      console.error('Failed to fetch report:', error)
    }
  }

  const handleExport = async (format) => {
    try {
      const response = await api.post(`/export/${scan.id}/${format}`)
      alert(`Exported to: ${response.path}`)
    } catch (error) {
      alert('Export failed: ' + error.message)
    }
  }

  const filteredFindings = findings.filter(f => filter === 'all' || f.severity === filter)
  const severityCounts = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc }, {})

  if (!scan) {
    return <div className="empty-state"><h3>No scan selected</h3><p>Select a scan to view findings</p></div>
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <button onClick={onBack} style={{ background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 4 }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
            Back to Scans
          </button>
          <h1 style={{ fontSize: 24, fontWeight: 600, marginBottom: 4 }}>{scan.target}</h1>
          <div style={{ color: 'var(--text-secondary)', fontSize: 14 }}>Scan ID: {scan.id} | {new Date(scan.started_at).toLocaleString()}</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-secondary" onClick={() => handleExport('csv')}>Export CSV</button>
          <button className="btn btn-secondary" onClick={() => handleExport('json')}>Export JSON</button>
          <button className="btn btn-primary" onClick={() => handleExport('sarif')}>Export SARIF</button>
        </div>
      </div>

      <div className="stats-grid" style={{ marginBottom: 24 }}>
        <div className="stat-card"><div className="label">Vulnerabilities</div><div className="value">{findings.length}</div></div>
        <div className="stat-card"><div className="label">Critical</div><div className="value critical">{severityCounts.critical || 0}</div></div>
        <div className="stat-card"><div className="label">High</div><div className="value high">{severityCounts.high || 0}</div></div>
        <div className="stat-card warning"><div className="label">Secrets</div><div className="value">{secrets.length}</div></div>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="tabs" style={{ margin: 0, border: 'none', display: 'flex', gap: 16 }}>
            <div className={`tab ${tab === 'vulnerabilities' ? 'active' : ''}`} onClick={() => setTab('vulnerabilities')} style={{ padding: '8px 12px', cursor: 'pointer' }}>
              Vulnerabilities ({findings.length})
            </div>
            <div className={`tab ${tab === 'secrets' ? 'active' : ''}`} onClick={() => setTab('secrets')} style={{ padding: '8px 12px', cursor: 'pointer' }}>
              Secrets ({secrets.length})
            </div>
          </div>
          {tab === 'vulnerabilities' && (
            <div className="tabs" style={{ margin: 0, border: 'none' }}>
              {['all', 'critical', 'high', 'medium', 'low', 'info'].map(sev => (
                <div key={sev} className={`tab ${filter === sev ? 'active' : ''}`} onClick={() => setFilter(sev)} style={{ padding: '8px 12px' }}>
                  {sev.charAt(0).toUpperCase() + sev.slice(1)}
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {loading ? (
            <div className="empty-state"><div className="animate-pulse">Loading...</div></div>
          ) : tab === 'secrets' ? (
            secrets.length === 0 ? (
              <div className="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 48, height: 48 }}><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
                <h3>No secrets found</h3>
                <p>No exposed API keys or secrets detected</p>
              </div>
            ) : secrets.map((secret, idx) => <SecretItem key={idx} secret={secret} />)
          ) : filteredFindings.length === 0 ? (
            <div className="empty-state">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 48, height: 48 }}><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
              <h3>No vulnerabilities found</h3>
              <p>{filter === 'all' ? 'Great! No issues detected' : `No ${filter} severity findings`}</p>
            </div>
          ) : filteredFindings.map((finding, idx) => <FindingItem key={idx} finding={finding} />)}
        </div>
      </div>
    </div>
  )
}

function FindingItem({ finding }) {
  const [expanded, setExpanded] = useState(false)
  const badgeClass = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low', info: 'badge-info' }[finding.severity] || 'badge-info'

  return (
    <div className={`finding-item ${finding.severity}`} onClick={() => setExpanded(!expanded)}>
      <div className="finding-header">
        <span className={`badge ${badgeClass}`}>{finding.severity}</span>
        <div className="finding-title">{finding.name}</div>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ transform: expanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s', color: 'var(--text-muted)' }}><polyline points="6 9 12 15 18 9"/></svg>
      </div>
      <div className="finding-details">
        {finding.url && <code>{finding.url}</code>}
        {finding.host && !finding.url && <code>{finding.host}</code>}
        {finding.template_id && <span style={{ marginLeft: 8, color: 'var(--text-muted)' }}>[{finding.template_id}]</span>}
      </div>
      {expanded && finding.description && (
        <div className="finding-expanded">{finding.description}</div>
      )}
    </div>
  )
}

function SecretItem({ secret }) {
  const [expanded, setExpanded] = useState(false)
  const badgeClass = secret.verified ? 'badge-critical' : 'badge-high'

  return (
    <div className={`finding-item ${secret.verified ? 'critical' : 'high'}`} onClick={() => setExpanded(!expanded)}>
      <div className="finding-header">
        <span className={`badge ${badgeClass}`}>{secret.verified ? 'VERIFIED' : 'UNVERIFIED'}</span>
        <div className="finding-title">{secret.name}</div>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ transform: expanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s', color: 'var(--text-muted)' }}><polyline points="6 9 12 15 18 9"/></svg>
      </div>
      <div className="finding-details">
        <code>{secret.source_url}</code>
        {secret.source_line && <span style={{ marginLeft: 8, color: 'var(--text-muted)' }}>Line {secret.source_line}</span>}
        <span style={{ marginLeft: 8, color: 'var(--text-muted)' }}>[{secret.detector_type}]</span>
      </div>
      {expanded && (
        <div className="finding-expanded">
          <div><strong>Tool:</strong> {secret.tool}</div>
          <div style={{ marginTop: 8 }}><strong>Raw:</strong> <code style={{ fontSize: 12 }}>{secret.raw || '***'}</code></div>
        </div>
      )}
    </div>
  )
}

export default Findings
