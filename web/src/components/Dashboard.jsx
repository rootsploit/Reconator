import { useMemo, useState, useEffect } from 'react'

function Dashboard({ scans, stats, onViewScan }) {
  const recentScans = useMemo(() => {
    return [...(scans || [])].sort((a, b) =>
      new Date(b.started_at) - new Date(a.started_at)
    ).slice(0, 5)
  }, [scans])

  const runningScans = scans?.filter(s => s.status === 'running') || []

  // Get AI summaries from completed scans
  const [aiSummaries, setAiSummaries] = useState([])
  const [loadingAI, setLoadingAI] = useState(false)

  useEffect(() => {
    const fetchAISummaries = async () => {
      if (!scans || scans.length === 0) return

      setLoadingAI(true)
      try {
        // Get completed scans with reports
        const completedScans = scans.filter(s => s.status === 'completed').slice(0, 3)
        const summaries = []

        for (const scan of completedScans) {
          try {
            const response = await fetch(`/api/v1/scans/${scan.id}/report`)
            if (response.ok) {
              const report = await response.json()
              if (report?.AIGuided?.ExecutiveSummary) {
                summaries.push({
                  scanId: scan.id,
                  target: scan.target,
                  date: scan.started_at,
                  summary: report.AIGuided.ExecutiveSummary
                })
              }
            }
          } catch (err) {
            console.error(`Failed to fetch report for scan ${scan.id}:`, err)
          }
        }

        setAiSummaries(summaries)
      } catch (error) {
        console.error('Failed to fetch AI summaries:', error)
      } finally {
        setLoadingAI(false)
      }
    }

    fetchAISummaries()
  }, [scans])

  return (
    <div>
      <h1 style={{ marginBottom: 24, fontSize: 24, fontWeight: 600 }}>Dashboard</h1>

      {/* Stats Grid */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="label">Total Scans</div>
          <div className="value">{stats?.total_scans || 0}</div>
        </div>
        <div className="stat-card">
          <div className="label">Running</div>
          <div className="value" style={{ color: 'var(--accent-cyan)' }}>
            {stats?.running_scans || 0}
          </div>
        </div>
        <div className="stat-card">
          <div className="label">Completed</div>
          <div className="value green">{stats?.completed_scans || 0}</div>
        </div>
        <div className="stat-card">
          <div className="label">Failed</div>
          <div className="value critical">{stats?.failed_scans || 0}</div>
        </div>
      </div>

      {/* Vulnerability Stats */}
      {stats && stats.total_vulns > 0 && (
        <div style={{ marginTop: 24 }}>
          <h2 style={{ fontSize: 18, marginBottom: 16, fontWeight: 600 }}>Vulnerabilities</h2>
          <div className="stats-grid vuln-stats-grid">
            <div className="stat-card">
              <div className="label">Critical</div>
              <div className="value critical">{stats.vuln_critical || 0}</div>
            </div>
            <div className="stat-card">
              <div className="label">High</div>
              <div className="value high">{stats.vuln_high || 0}</div>
            </div>
            <div className="stat-card">
              <div className="label">Medium</div>
              <div className="value medium">{stats.vuln_medium || 0}</div>
            </div>
            <div className="stat-card">
              <div className="label">Low</div>
              <div className="value low">{stats.vuln_low || 0}</div>
            </div>
            <div className="stat-card">
              <div className="label">Info</div>
              <div className="value info">{stats.vuln_info || 0}</div>
            </div>
          </div>
        </div>
      )}

      {/* AI Security Insights */}
      {aiSummaries.length > 0 && !loadingAI && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header">
            <h2>🤖 AI Security Insights</h2>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
              Recent AI-generated security summaries
            </p>
          </div>
          <div className="card-body">
            {aiSummaries.map((item, idx) => (
              <div key={item.scanId} style={{
                padding: 16,
                background: 'var(--bg-secondary)',
                borderRadius: 8,
                marginBottom: idx < aiSummaries.length - 1 ? 12 : 0,
                border: '1px solid var(--border)'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 12 }}>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 4 }}>{item.target}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                      {new Date(item.date).toLocaleDateString()}
                    </div>
                  </div>
                  <span style={{
                    padding: '4px 8px',
                    borderRadius: 4,
                    fontSize: 11,
                    fontWeight: 600,
                    background: item.summary.risk_assessment?.includes('HIGH') ? 'rgba(239, 68, 68, 0.1)' :
                                item.summary.risk_assessment?.includes('MEDIUM') ? 'rgba(245, 158, 11, 0.1)' :
                                'rgba(16, 185, 129, 0.1)',
                    color: item.summary.risk_assessment?.includes('HIGH') ? '#ef4444' :
                           item.summary.risk_assessment?.includes('MEDIUM') ? '#f59e0b' :
                           '#10b981'
                  }}>
                    {item.summary.risk_assessment?.split(' -')[0] || 'ASSESSED'}
                  </span>
                </div>

                <div style={{ fontSize: 14, lineHeight: 1.6, marginBottom: 12, color: 'var(--text-primary)' }}>
                  {item.summary.one_liner}
                </div>

                {item.summary.key_findings && item.summary.key_findings.length > 0 && (
                  <div style={{ fontSize: 13, marginBottom: 8 }}>
                    <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-secondary)', marginBottom: 6 }}>KEY FINDINGS:</div>
                    <ul style={{ margin: 0, paddingLeft: 20, color: 'var(--text-secondary)' }}>
                      {item.summary.key_findings.slice(0, 3).map((finding, i) => (
                        <li key={i} style={{ marginBottom: 4 }}>{finding}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <button
                  onClick={() => onViewScan(scans.find(s => s.id === item.scanId))}
                  style={{
                    marginTop: 8,
                    padding: '6px 12px',
                    fontSize: 12,
                    color: 'var(--accent)',
                    background: 'none',
                    border: '1px solid var(--accent)',
                    borderRadius: 4,
                    cursor: 'pointer'
                  }}
                >
                  View Full Report →
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Running Scans */}
      {runningScans.length > 0 && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header">
            <h2>Active Scans</h2>
          </div>
          <div className="card-body" style={{ padding: 0 }}>
            {runningScans.map(scan => (
              <ScanCard key={scan.id} scan={scan} onView={() => onViewScan(scan)} />
            ))}
          </div>
        </div>
      )}

      {/* Recent Scans */}
      <div className="card">
        <div className="card-header">
          <h2>Recent Scans</h2>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {recentScans.length === 0 ? (
            <div className="empty-state">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8"/>
                <path d="M21 21l-4.35-4.35"/>
              </svg>
              <h3>No scans yet</h3>
              <p>Start a new scan to begin reconnaissance</p>
            </div>
          ) : (
            recentScans.map(scan => (
              <ScanCard key={scan.id} scan={scan} onView={() => onViewScan(scan)} />
            ))
          )}
        </div>
      </div>
    </div>
  )
}

function ScanCard({ scan, onView }) {
  const [stats, setStats] = useState(null)

  // Fetch scan stats for completed scans
  useEffect(() => {
    const fetchStats = async () => {
      if (scan.status === 'completed') {
        try {
          const response = await fetch(`/api/v1/scans/${scan.id}/report`)
          if (response.ok) {
            const report = await response.json()
            setStats({
              subdomains: report?.Subdomain?.total || 0,
              vulns: report?.VulnScan?.total_vulnerabilities || 0
            })
          }
        } catch (err) {
          console.error('Failed to fetch scan stats:', err)
        }
      }
    }
    fetchStats()
  }, [scan.id, scan.status])

  const statusClass = {
    running: 'badge-running',
    completed: 'badge-completed',
    failed: 'badge-failed',
    pending: 'badge-pending',
    cancelled: 'badge-failed',
    paused: 'badge-warning',
  }[scan.status] || 'badge-pending'

  return (
    <div className="scan-card" onClick={onView} style={{
      cursor: 'pointer',
      padding: '8px 12px',
      borderBottom: '1px solid var(--border)'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
        <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{scan.target}</span>
        <span className={`badge ${statusClass}`} style={{ fontSize: 10, padding: '2px 6px' }}>{scan.status}</span>
      </div>

      <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-secondary)', marginBottom: scan.status === 'running' ? 6 : 0 }}>
        <span>{new Date(scan.started_at).toLocaleDateString()}</span>
        {scan.duration && <span>⏱ {scan.duration}</span>}
        {stats && (
          <>
            <span>🌐 {stats.subdomains}</span>
            <span>🔍 {stats.vulns}</span>
          </>
        )}
      </div>

      {scan.status === 'running' && (
        <div style={{ marginTop: 6 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3, fontSize: 10, color: 'var(--text-secondary)' }}>
            <span>{scan.current_phase || 'Initializing...'}</span>
            <span style={{ fontWeight: 600, color: 'var(--accent)' }}>{scan.progress || 0}%</span>
          </div>
          <div className="progress-bar" style={{ height: 3 }}>
            <div className="fill" style={{ width: `${scan.progress || 0}%` }} />
          </div>
        </div>
      )}
    </div>
  )
}

export default Dashboard
