import { useState, useRef } from 'react'

const PHASES = [
  { id: 'iprange', label: 'IP Range Discovery' },
  { id: 'subdomain', label: 'Subdomain Enumeration' },
  { id: 'waf', label: 'WAF/CDN Detection' },
  { id: 'ports', label: 'Port Scanning' },
  { id: 'vhost', label: 'Virtual Host Discovery' },
  { id: 'takeover', label: 'Takeover Check' },
  { id: 'historic', label: 'Historic URLs' },
  { id: 'tech', label: 'Tech Detection' },
  { id: 'jsanalysis', label: 'JavaScript Analysis' },
  { id: 'secheaders', label: 'Security Headers' },
  { id: 'dirbrute', label: 'Directory Bruteforce' },
  { id: 'vulnscan', label: 'Vulnerability Scan' },
  { id: 'screenshot', label: 'Screenshot Capture' },
  { id: 'aiguided', label: 'AI-Guided Analysis' },
]

// Scan templates for quick selection
const TEMPLATES = {
  'quick': {
    name: 'Quick Recon',
    phases: ['subdomain', 'ports', 'secheaders'],
    threads: 100,
    deepScan: false,
    passiveMode: false,
    description: 'Fast subdomain + port scan + security checks (5-10 min)'
  },
  'deep': {
    name: 'Deep Scan',
    phases: ['all'],
    threads: 50,
    deepScan: true,
    passiveMode: false,
    description: 'Complete reconnaissance (30-60 min)'
  },
  'bounty': {
    name: 'Bug Bounty',
    phases: ['subdomain', 'historic', 'tech', 'secheaders', 'vulnscan', 'aiguided'],
    threads: 75,
    deepScan: true,
    passiveMode: false,
    description: 'Bug hunting optimized (20-40 min)'
  },
  'tech': {
    name: 'Tech Stack Only',
    phases: ['subdomain', 'ports', 'tech', 'secheaders'],
    threads: 100,
    deepScan: false,
    passiveMode: true,
    description: 'Passive tech detection + security checks (10-15 min)'
  },
  'screenshot': {
    name: 'Screenshot Capture',
    phases: ['subdomain', 'ports', 'tech', 'secheaders', 'screenshot'],
    threads: 50,
    deepScan: false,
    passiveMode: false,
    description: 'Visual reconnaissance + security checks (15-20 min)'
  },
  'passive': {
    name: 'Passive Recon',
    phases: ['subdomain', 'historic', 'tech', 'secheaders'],
    threads: 100,
    deepScan: false,
    passiveMode: true,
    description: 'Non-intrusive scan (10-15 min)'
  }
}

function NewScanModal({ onClose, onSubmit }) {
  const [inputMode, setInputMode] = useState('single') // 'single' or 'file'
  const [target, setTarget] = useState('')
  const [targets, setTargets] = useState([])
  const [fileName, setFileName] = useState('')
  const [phases, setPhases] = useState(['all'])
  const [threads, setThreads] = useState(50)
  const [deepScan, setDeepScan] = useState(false)
  const [passiveMode, setPassiveMode] = useState(false)
  const [loading, setLoading] = useState(false)
  const fileInputRef = useRef(null)

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0]
    if (!file) return

    setFileName(file.name)
    const reader = new FileReader()
    reader.onload = (event) => {
      const content = event.target?.result
      if (typeof content === 'string') {
        // Parse file content - one target per line
        const lines = content
          .split(/\r?\n/)
          .map(line => line.trim())
          .filter(line => line && !line.startsWith('#'))
        setTargets(lines)
      }
    }
    reader.readAsText(file)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    const targetList = inputMode === 'single' ? [target.trim()] : targets
    if (targetList.length === 0 || (inputMode === 'single' && !target.trim())) return

    setLoading(true)
    try {
      // For single target, submit normally
      // For multiple targets, we could batch them or submit one by one
      for (const t of targetList) {
        await onSubmit({
          target: t,
          phases: phases.includes('all') ? [] : phases,
          threads,
          deep_scan: deepScan,
          passive_mode: passiveMode,
        })
      }
    } finally {
      setLoading(false)
    }
  }

  const togglePhase = (phaseId) => {
    if (phaseId === 'all') {
      setPhases(['all'])
    } else {
      setPhases(prev => {
        const filtered = prev.filter(p => p !== 'all')
        if (filtered.includes(phaseId)) {
          return filtered.filter(p => p !== phaseId)
        }
        return [...filtered, phaseId]
      })
    }
  }

  const applyTemplate = (templateId) => {
    const template = TEMPLATES[templateId]
    if (template) {
      setPhases(template.phases)
      setThreads(template.threads)
      setDeepScan(template.deepScan)
      setPassiveMode(template.passiveMode)
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2>New Scan</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            {/* Input Mode Toggle */}
            <div className="input-mode-toggle">
              <button
                type="button"
                className={`mode-btn ${inputMode === 'single' ? 'active' : ''}`}
                onClick={() => setInputMode('single')}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                </svg>
                Single Target
              </button>
              <button
                type="button"
                className={`mode-btn ${inputMode === 'file' ? 'active' : ''}`}
                onClick={() => setInputMode('file')}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
                </svg>
                Upload File
              </button>
            </div>

            {/* Single Target Input */}
            {inputMode === 'single' && (
              <div className="input-group">
                <label>Target Domain</label>
                <input type="text" className="input" placeholder="example.com" value={target} onChange={e => setTarget(e.target.value)} autoFocus />
              </div>
            )}

            {/* File Upload */}
            {inputMode === 'file' && (
              <div className="input-group">
                <label>Upload Target List</label>
                <div className="file-upload-area" onClick={() => fileInputRef.current?.click()}>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".txt,.csv"
                    onChange={handleFileUpload}
                    style={{ display: 'none' }}
                  />
                  {fileName ? (
                    <div className="file-info">
                      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
                      </svg>
                      <span className="file-name">{fileName}</span>
                      <span className="file-count">{targets.length} targets</span>
                    </div>
                  ) : (
                    <div className="file-placeholder">
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
                      </svg>
                      <p>Click to upload a file</p>
                      <span>Supports .txt or .csv with one target per line</span>
                      <span className="file-hint">IPs, domains, or ASN numbers</span>
                    </div>
                  )}
                </div>
                {targets.length > 0 && (
                  <div className="targets-preview">
                    <div className="preview-header">
                      <span>Targets Preview:</span>
                      <button type="button" className="clear-btn" onClick={() => { setTargets([]); setFileName('') }}>Clear</button>
                    </div>
                    <div className="preview-list">
                      {targets.slice(0, 5).map((t, i) => (
                        <code key={i}>{t}</code>
                      ))}
                      {targets.length > 5 && <span className="more">+{targets.length - 5} more</span>}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Scan Templates */}
            <div className="input-group">
              <label>Scan Templates (Quick Select)</label>
              <div className="template-grid">
                {Object.entries(TEMPLATES).map(([id, template]) => (
                  <button
                    key={id}
                    type="button"
                    className="template-card"
                    onClick={() => applyTemplate(id)}
                  >
                    <div className="template-name">{template.name}</div>
                    <div className="template-desc">{template.description}</div>
                  </button>
                ))}
              </div>
            </div>

            <div className="input-group">
              <label>Scan Phases (Customize)</label>
              <div className="checkbox-group">
                <div className={`checkbox-item ${phases.includes('all') ? 'checked' : ''}`} onClick={() => togglePhase('all')}>
                  <input type="checkbox" checked={phases.includes('all')} readOnly />
                  All Phases
                </div>
                {PHASES.map(phase => (
                  <div key={phase.id} className={`checkbox-item ${phases.includes(phase.id) ? 'checked' : ''}`} onClick={() => togglePhase(phase.id)}>
                    <input type="checkbox" checked={phases.includes(phase.id)} readOnly />
                    {phase.label}
                  </div>
                ))}
              </div>
            </div>

            <div className="input-group">
              <label>Threads ({threads})</label>
              <input type="range" min="10" max="200" value={threads} onChange={e => setThreads(parseInt(e.target.value))} style={{ width: '100%' }} />
            </div>

            <div className="input-group">
              <label>Options</label>
              <div style={{ display: 'flex', gap: 16 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input type="checkbox" checked={deepScan} onChange={e => setDeepScan(e.target.checked)} />
                  Deep Scan
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input type="checkbox" checked={passiveMode} onChange={e => setPassiveMode(e.target.checked)} />
                  Passive Mode
                </label>
              </div>
            </div>

            {/* Warning for passive mode with active phases */}
            {passiveMode && (phases.includes('screenshot') || phases.includes('tech') || phases.includes('ports') || phases.includes('all')) && (
              <div style={{ padding: '12px', background: 'rgba(251, 191, 36, 0.1)', border: '1px solid rgba(251, 191, 36, 0.3)', borderRadius: '8px', marginTop: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'start', gap: '8px' }}>
                  <span style={{ fontSize: '16px', color: '#fbbf24' }}>⚠️</span>
                  <div>
                    <div style={{ fontWeight: 500, color: '#fbbf24', marginBottom: '4px' }}>Passive Mode with Active Phases</div>
                    <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                      You've enabled passive mode but selected active phases (screenshot/tech/ports). These phases will actively interact with target assets during the scan.
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={(inputMode === 'single' ? !target.trim() : targets.length === 0) || loading}
            >
              {loading ? 'Starting...' : inputMode === 'file' && targets.length > 1 ? `Start ${targets.length} Scans` : 'Start Scan'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default NewScanModal
