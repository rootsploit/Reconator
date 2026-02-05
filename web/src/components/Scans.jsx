import { useState } from 'react'

function Scans({ scans, onStop, onPause, onResume, onViewFindings, onRefresh }) {
  const [filter, setFilter] = useState('all')

  const filteredScans = scans?.filter(scan => {
    if (filter === 'all') return true
    return scan.status === filter
  }) || []

  const sortedScans = [...filteredScans].sort((a, b) =>
    new Date(b.started_at) - new Date(a.started_at)
  )

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600 }}>Scans</h1>
        <button className="btn btn-secondary" onClick={onRefresh}>Refresh</button>
      </div>

      <div className="tabs">
        {['all', 'running', 'paused', 'completed', 'failed'].map(f => (
          <div key={f} className={`tab ${filter === f ? 'active' : ''}`} onClick={() => setFilter(f)}>
            {f.charAt(0).toUpperCase() + f.slice(1)}
            {f !== 'all' && <span style={{ marginLeft: 6, opacity: 0.7 }}>({scans?.filter(s => s.status === f).length || 0})</span>}
          </div>
        ))}
      </div>

      {sortedScans.length === 0 ? (
        <div className="empty-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
          </svg>
          <h3>No scans found</h3>
          <p>{filter === 'all' ? 'Start a new scan to begin' : `No ${filter} scans`}</p>
        </div>
      ) : (
        <div className="card">
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Progress</th>
                  <th>Started</th>
                  <th>Duration</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sortedScans.map(scan => (
                  <ScanRow
                    key={scan.id}
                    scan={scan}
                    onStop={() => onStop(scan.id)}
                    onPause={() => onPause(scan.id)}
                    onResume={() => onResume(scan.id)}
                    onView={() => onViewFindings(scan)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

function ScanRow({ scan, onStop, onPause, onResume, onView }) {
  const [stopping, setStopping] = useState(false)
  const [pausing, setPausing] = useState(false)
  const [resuming, setResuming] = useState(false)
  const statusClass = {
    running: 'badge-running',
    paused: 'badge-warning',
    completed: 'badge-completed',
    failed: 'badge-failed',
    pending: 'badge-pending',
    cancelled: 'badge-failed'
  }[scan.status] || 'badge-pending'

  const handleStop = async (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (stopping) return

    console.log('[ScanRow] Stopping scan:', scan.id, scan.target)
    setStopping(true)
    try {
      await onStop()
      console.log('[ScanRow] Scan stopped successfully')
    } catch (error) {
      console.error('[ScanRow] Failed to stop scan:', error)
      alert('Failed to stop scan: ' + error.message)
    } finally {
      setStopping(false)
    }
  }

  const handlePause = async (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (pausing) return

    console.log('[ScanRow] Pausing scan:', scan.id, scan.target)
    setPausing(true)
    try {
      await onPause()
      console.log('[ScanRow] Scan paused successfully')
    } catch (error) {
      console.error('[ScanRow] Failed to pause scan:', error)
      alert('Failed to pause scan: ' + error.message)
    } finally {
      setPausing(false)
    }
  }

  const handleResume = async (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (resuming) return

    console.log('[ScanRow] Resuming scan:', scan.id, scan.target)
    setResuming(true)
    try {
      await onResume()
      console.log('[ScanRow] Scan resumed successfully')
    } catch (error) {
      console.error('[ScanRow] Failed to resume scan:', error)
      alert('Failed to resume scan: ' + error.message)
    } finally {
      setResuming(false)
    }
  }

  const handleView = (e) => {
    e.preventDefault()
    e.stopPropagation()
    onView()
  }

  return (
    <tr>
      <td>
        <div style={{ fontWeight: 500 }}>{scan.target}</div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>ID: {scan.id}</div>
      </td>
      <td><span className={`badge ${statusClass}`}>{scan.status}</span></td>
      <td>
        {scan.status === 'running' || scan.status === 'paused' ? (
          <div style={{ minWidth: 120 }}>
            <div className="progress-bar" style={{ marginBottom: 4 }}>
              <div className="fill" style={{ width: `${scan.progress || 0}%` }} />
            </div>
            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              {scan.status === 'paused' ? '⏸️ Paused' : scan.current_phase || 'Starting...'} ({scan.progress || 0}%)
            </span>
          </div>
        ) : scan.status === 'completed' ? (
          <span style={{ color: 'var(--accent-green)' }}>100%</span>
        ) : <span style={{ color: 'var(--text-muted)' }}>-</span>}
      </td>
      <td style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{new Date(scan.started_at).toLocaleString()}</td>
      <td style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{scan.duration || '-'}</td>
      <td>
        <div style={{ display: 'flex', gap: 8 }}>
          {scan.status === 'running' ? (
            <>
              <button className="btn btn-primary" onClick={handleView} style={{ padding: '4px 12px', fontSize: 13, cursor: 'pointer' }}>View Progress</button>
              <button
                className="btn btn-warning"
                onClick={handlePause}
                disabled={pausing}
                style={{ padding: '4px 12px', fontSize: 13, cursor: pausing ? 'not-allowed' : 'pointer', opacity: pausing ? 0.6 : 1 }}
              >
                {pausing ? 'Pausing...' : 'Pause'}
              </button>
              <button
                className="btn btn-danger"
                onClick={handleStop}
                disabled={stopping}
                style={{ padding: '4px 12px', fontSize: 13, cursor: stopping ? 'not-allowed' : 'pointer', opacity: stopping ? 0.6 : 1 }}
              >
                {stopping ? 'Stopping...' : 'Stop'}
              </button>
            </>
          ) : scan.status === 'paused' ? (
            <>
              <button className="btn btn-primary" onClick={handleView} style={{ padding: '4px 12px', fontSize: 13, cursor: 'pointer' }}>View Progress</button>
              <button
                className="btn btn-success"
                onClick={handleResume}
                disabled={resuming}
                style={{ padding: '4px 12px', fontSize: 13, cursor: resuming ? 'not-allowed' : 'pointer', opacity: resuming ? 0.6 : 1 }}
              >
                {resuming ? 'Resuming...' : 'Resume'}
              </button>
              <button
                className="btn btn-danger"
                onClick={handleStop}
                disabled={stopping}
                style={{ padding: '4px 12px', fontSize: 13, cursor: stopping ? 'not-allowed' : 'pointer', opacity: stopping ? 0.6 : 1 }}
              >
                {stopping ? 'Stopping...' : 'Stop'}
              </button>
            </>
          ) : scan.status === 'completed' ? (
            <button className="btn btn-primary" onClick={handleView} style={{ padding: '4px 12px', fontSize: 13, cursor: 'pointer' }}>View Results</button>
          ) : scan.status === 'cancelled' || scan.status === 'failed' ? (
            <button className="btn btn-secondary" onClick={handleView} style={{ padding: '4px 12px', fontSize: 13, cursor: 'pointer' }}>View Details</button>
          ) : null}
        </div>
      </td>
    </tr>
  )
}

export default Scans
