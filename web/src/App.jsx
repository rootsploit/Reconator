import { useState, useEffect } from 'react'
import { useWebSocket } from './hooks/useWebSocket'
import { api } from './utils/api'
import Dashboard from './components/Dashboard'
import Scans from './components/Scans'
import ScanDetails from './components/ScanDetails'
import Configuration from './components/Configuration'
import NewScanModal from './components/NewScanModal'

// Icons as simple SVG components
const Icons = {
  Logo: () => (
    <svg viewBox="0 0 32 32" fill="none">
      <circle cx="16" cy="16" r="14" stroke="currentColor" strokeWidth="2" fill="none"/>
      <path d="M16 6v10l7 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
      <circle cx="16" cy="16" r="3" fill="currentColor"/>
    </svg>
  ),
  Dashboard: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="3" width="7" height="9" rx="1"/>
      <rect x="14" y="3" width="7" height="5" rx="1"/>
      <rect x="14" y="12" width="7" height="9" rx="1"/>
      <rect x="3" y="16" width="7" height="5" rx="1"/>
    </svg>
  ),
  Scan: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="11" cy="11" r="8"/>
      <path d="M21 21l-4.35-4.35"/>
    </svg>
  ),
  Alert: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/>
      <line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  ),
  Config: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="3"/>
      <path d="M12 1v6m0 6v6M5.64 5.64l4.24 4.24m4.24 4.24l4.24 4.24M1 12h6m6 0h6M5.64 18.36l4.24-4.24m4.24-4.24l4.24-4.24"/>
    </svg>
  ),
  Plus: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <line x1="12" y1="5" x2="12" y2="19"/>
      <line x1="5" y1="12" x2="19" y2="12"/>
    </svg>
  ),
}

function App() {
  const [view, setView] = useState('dashboard')
  const [scans, setScans] = useState([])
  const [stats, setStats] = useState(null)
  const [showNewScan, setShowNewScan] = useState(false)
  const [selectedScan, setSelectedScan] = useState(null)
  const [version, setVersion] = useState('')
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [showLogin, setShowLogin] = useState(false)
  const [usernameInput, setUsernameInput] = useState('')
  const [passwordInput, setPasswordInput] = useState('')
  const [authError, setAuthError] = useState('')

  const { isConnected, lastMessage } = useWebSocket()

  // Check authentication on mount
  useEffect(() => {
    if (api.isAuthenticated()) {
      // Verify auth with a test request
      verifyAuth()
    } else {
      setShowLogin(true)
    }
  }, [])

  useEffect(() => {
    if (isAuthenticated) {
      fetchScans()
      fetchStats()
      fetchVersion()
    }
  }, [isAuthenticated])

  useEffect(() => {
    if (lastMessage) {
      const { type, data } = lastMessage
      console.log('[WebSocket] Received:', type, data) // Debug logging
      if (type === 'scan_started' || type === 'scan_stopped' || type === 'scan_completed' || type === 'scan_failed') {
        fetchScans()
        fetchStats()
      } else if (type === 'scan_progress') {
        // Immediately update the scan progress in the UI
        setScans(prev => prev.map(scan =>
          scan.id === data.id ? { ...scan, ...data } : scan
        ))
        // Also update stats to reflect running scans
        fetchStats()
      }
    }
  }, [lastMessage])

  const fetchScans = async () => {
    try {
      const response = await api.get('/scans')
      setScans(response.scans || [])
    } catch (error) {
      console.error('Failed to fetch scans:', error)
    }
  }

  const fetchStats = async () => {
    try {
      const response = await api.get('/stats')
      setStats(response)
    } catch (error) {
      console.error('Failed to fetch stats:', error)
    }
  }

  const fetchVersion = async () => {
    try {
      const response = await api.get('/version')
      setVersion(response.version)
    } catch (error) {
      console.error('Failed to fetch version:', error)
    }
  }

  const verifyAuth = async () => {
    try {
      // Test authentication with a simple request
      await api.get('/version')
      setIsAuthenticated(true)
      setShowLogin(false)
      setAuthError('')
    } catch (error) {
      setIsAuthenticated(false)
      setAuthError('Session expired. Please login again.')
      setShowLogin(true)
    }
  }

  const handleLogin = async (e) => {
    e.preventDefault()

    // Validate username
    if (!usernameInput.trim()) {
      setAuthError('Please enter username')
      return
    }

    // Validate password
    if (!passwordInput.trim()) {
      setAuthError('Please enter password')
      return
    }

    try {
      // Login with JWT
      await api.login(usernameInput.trim(), passwordInput.trim())
      setIsAuthenticated(true)
      setShowLogin(false)
      setAuthError('')
      setPasswordInput('') // Clear password
    } catch (error) {
      setAuthError(error.message || 'Invalid credentials. Please try again.')
    }
  }

  const handleLogout = async () => {
    await api.logout()
    setIsAuthenticated(false)
    setShowLogin(true)
    setUsernameInput('')
    setPasswordInput('')
  }

  const handleStartScan = async (scanConfig) => {
    try {
      await api.post('/scans', scanConfig)
      setShowNewScan(false)
      fetchScans()
      fetchStats()
    } catch (error) {
      console.error('Failed to start scan:', error)
      alert('Failed to start scan: ' + error.message)
    }
  }

  const handleStopScan = async (scanId) => {
    console.log('[App] Stopping scan:', scanId)
    try {
      const result = await api.delete(`/scans/${scanId}`)
      console.log('[App] Stop scan response:', result)
      fetchScans()
      fetchStats()
    } catch (error) {
      console.error('[App] Failed to stop scan:', error)
      throw error // Re-throw so ScanRow can show alert
    }
  }

  const handlePauseScan = async (scanId) => {
    console.log('[App] Pausing scan:', scanId)
    try {
      const result = await api.post(`/scans/${scanId}/pause`)
      console.log('[App] Pause scan response:', result)
      fetchScans()
      fetchStats()
    } catch (error) {
      console.error('[App] Failed to pause scan:', error)
      throw error // Re-throw so ScanRow can show alert
    }
  }

  const handleResumeScan = async (scanId) => {
    console.log('[App] Resuming scan:', scanId)
    try {
      const result = await api.post(`/scans/${scanId}/resume`)
      console.log('[App] Resume scan response:', result)
      fetchScans()
      fetchStats()
    } catch (error) {
      console.error('[App] Failed to resume scan:', error)
      throw error // Re-throw so ScanRow can show alert
    }
  }

  const handleViewFindings = (scan) => {
    setSelectedScan(scan)
    setView('findings')
  }

  const renderContent = () => {
    switch (view) {
      case 'dashboard':
        return <Dashboard scans={scans} stats={stats} onViewScan={handleViewFindings} />
      case 'scans':
        return <Scans scans={scans} onStop={handleStopScan} onPause={handlePauseScan} onResume={handleResumeScan} onViewFindings={handleViewFindings} onRefresh={fetchScans} />
      case 'findings':
        return <ScanDetails scan={selectedScan} onBack={() => setView('scans')} />
      case 'configuration':
        return <Configuration />
      default:
        return null
    }
  }

  return (
    <div className="app">
      {/* Login Screen */}
      {showLogin && (
        <div className="login-screen">
          <div className="login-box">
            <div className="login-icon">
              <img src="/logo-full.png" alt="Reconator" style={{ width: 200, height: 200, objectFit: 'contain' }} />
            </div>
            <h1 className="login-title">Reconator</h1>
            <p className="login-subtitle">Authentication Required</p>

            <form onSubmit={handleLogin} className="login-form">
              <div className="form-group">
                <label htmlFor="username">Username</label>
                <input
                  id="username"
                  type="text"
                  className="input"
                  placeholder="Username"
                  value={usernameInput}
                  onChange={(e) => setUsernameInput(e.target.value)}
                  autoFocus
                  autoComplete="username"
                />
              </div>
              <div className="form-group">
                <label htmlFor="password">Password</label>
                <input
                  id="password"
                  type="password"
                  className="input"
                  placeholder="Password"
                  value={passwordInput}
                  onChange={(e) => setPasswordInput(e.target.value)}
                  autoComplete="current-password"
                />
              </div>
              {authError && (
                <div className="alert alert-error">
                  {authError}
                </div>
              )}
              <button type="submit" className="btn btn-primary login-button">
                Sign In
              </button>
            </form>
          </div>
        </div>
      )}

      <header className="header">
        <div className="header-logo">
          <div className="logo-icon">
            <img src="/logo.png" alt="Reconator" style={{ width: 72, height: 72, objectFit: 'contain' }} />
          </div>
          <h1>Reconator</h1>
          {version && <span>v{version}</span>}
        </div>
        <div className="header-status">
          <div className="connection-status">
            <div className={`connection-dot ${isConnected ? 'connected' : ''}`} />
            {isConnected ? 'Connected' : 'Disconnected'}
          </div>
          {isAuthenticated && (
            <>
              <button
                className="btn btn-primary"
                onClick={() => setShowNewScan(true)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '8px 16px',
                  fontSize: '14px',
                  fontWeight: 500,
                  whiteSpace: 'nowrap'
                }}
              >
                <Icons.Plus />
                New Scan
              </button>
              <button
                className="btn btn-secondary"
                onClick={handleLogout}
                style={{
                  marginLeft: '8px',
                  padding: '8px 16px',
                  fontSize: '14px'
                }}
              >
                Logout
              </button>
            </>
          )}
        </div>
      </header>

      {isAuthenticated && (
        <main className="main">
          <nav className="sidebar">
            <div className={`nav-item ${view === 'dashboard' ? 'active' : ''}`} onClick={() => setView('dashboard')}>
              <Icons.Dashboard />
              Dashboard
            </div>
            <div className={`nav-item ${view === 'scans' ? 'active' : ''}`} onClick={() => setView('scans')}>
              <Icons.Scan />
              Scans
            </div>
            <div className={`nav-item ${view === 'findings' ? 'active' : ''}`} onClick={() => selectedScan && setView('findings')}>
              <Icons.Alert />
              Findings
            </div>
            <div className={`nav-item ${view === 'configuration' ? 'active' : ''}`} onClick={() => setView('configuration')}>
              <Icons.Config />
              Configuration
            </div>
          </nav>

          <div className="content">
            {renderContent()}
          </div>
        </main>
      )}

      {!isAuthenticated && !showLogin && (
        <main className="main" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>
            <p>Verifying authentication...</p>
          </div>
        </main>
      )}

      {showNewScan && (
        <NewScanModal onClose={() => setShowNewScan(false)} onSubmit={handleStartScan} />
      )}
    </div>
  )
}

export default App
