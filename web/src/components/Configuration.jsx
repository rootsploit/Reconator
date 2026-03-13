import { useState, useEffect } from 'react'
import { api } from '../utils/api'

function Configuration() {
  const [config, setConfig] = useState(null)
  const [loading, setLoading] = useState(true)
  const [testing, setTesting] = useState({})
  const [testResults, setTestResults] = useState({})
  const [activeSection, setActiveSection] = useState('osint')
  const [editedKeys, setEditedKeys] = useState({})
  const [saving, setSaving] = useState({})
  const [syncing, setSyncing] = useState(false)
  const [infraConfig, setInfraConfig] = useState({})
  const [infraDirty, setInfraDirty] = useState(false)
  const [savingInfra, setSavingInfra] = useState(false)

  useEffect(() => {
    loadConfig()
  }, [])

  const loadConfig = async () => {
    try {
      const response = await api.get('/config')
      // API returns data directly, not wrapped in a data property
      setConfig(response)
      // Initialize infrastructure config from response
      const infra = response.infrastructure || {}
      setInfraConfig({
        distributed_provider: infra.distributed_provider || 'aws',
        distributed_workers: infra.distributed_workers ?? 3,
        distributed_spot: infra.distributed_spot ?? false,
        distributed_region: infra.distributed_region || '',
        distributed_instance_size: infra.distributed_instance_size || '',
        distributed_ssh_key_path: infra.distributed_ssh_key_path || '',
        distributed_ssh_key_id: infra.distributed_ssh_key_id || '',
        distributed_cloud_api_key: infra.distributed_cloud_api_key || '',
        ip_rotation_regions: infra.ip_rotation_regions || '',
      })
      setLoading(false)
    } catch (error) {
      console.error('Failed to load configuration:', error)
      setLoading(false)
    }
  }

  const testKey = async (provider, key) => {
    if (!key || key.includes('*')) {
      return // Don't test masked keys
    }

    setTesting(prev => ({ ...prev, [`${provider}`]: true }))

    try {
      const response = await api.post('/config/test', {
        provider,
        key
      })

      setTestResults(prev => ({
        ...prev,
        [`${provider}`]: {
          valid: response.valid,
          error: response.error,
          latency: response.latency
        }
      }))
    } catch (error) {
      setTestResults(prev => ({
        ...prev,
        [`${provider}`]: {
          valid: false,
          error: error.message || 'Test failed'
        }
      }))
    } finally {
      setTesting(prev => ({ ...prev, [`${provider}`]: false }))
    }
  }

  const handleKeyChange = (provider, value) => {
    setEditedKeys(prev => ({
      ...prev,
      [provider]: value
    }))
    // Clear test results when editing
    setTestResults(prev => ({
      ...prev,
      [provider]: null
    }))
  }

  const handleSaveKey = async (provider) => {
    const newKey = editedKeys[provider]
    if (!newKey || newKey.trim() === '') {
      return
    }

    setSaving(prev => ({ ...prev, [provider]: true }))

    try {
      await api.post('/config/update', {
        provider,
        keys: [newKey.trim()]
      })

      // Reload config to get masked key
      await loadConfig()

      // Clear edited state
      setEditedKeys(prev => {
        const next = { ...prev }
        delete next[provider]
        return next
      })

      // Show success in test results
      setTestResults(prev => ({
        ...prev,
        [provider]: {
          valid: true,
          error: 'Key saved successfully'
        }
      }))
    } catch (error) {
      setTestResults(prev => ({
        ...prev,
        [provider]: {
          valid: false,
          error: error.message || 'Failed to save'
        }
      }))
    } finally {
      setSaving(prev => ({ ...prev, [provider]: false }))
    }
  }

  const handleSync = async () => {
    setSyncing(true)
    try {
      await api.post('/config/sync')
      await loadConfig()
      alert('Configuration synced successfully from environment and config files')
    } catch (error) {
      alert('Sync failed: ' + error.message)
    } finally {
      setSyncing(false)
    }
  }

  const handleInfraChange = (field, value) => {
    setInfraConfig(prev => ({ ...prev, [field]: value }))
    setInfraDirty(true)
  }

  const handleSaveInfra = async () => {
    setSavingInfra(true)
    try {
      await api.post('/config/update', {
        provider: 'infrastructure',
        keys: [],
        infrastructure: infraConfig
      })
      setInfraDirty(false)
      setTestResults(prev => ({
        ...prev,
        infrastructure: { valid: true, error: 'Infrastructure settings saved successfully' }
      }))
    } catch (error) {
      setTestResults(prev => ({
        ...prev,
        infrastructure: { valid: false, error: error.message || 'Failed to save infrastructure settings' }
      }))
    } finally {
      setSavingInfra(false)
    }
  }

  const renderAPIKeyRow = (provider, displayName, keys, docUrl, customPlaceholder) => {
    const key = keys && keys.length > 0 ? keys[0].key : ''
    const enabled = keys && keys.length > 0 && keys[0].enabled
    const testResult = testResults[provider]
    const isTesting = testing[provider]
    const isSaving = saving[provider]
    const editedValue = editedKeys[provider]
    const hasEdit = editedValue !== undefined

    return (
      <div key={provider} className="api-key-row">
        <div className="api-key-info">
          <div className="api-key-name" style={{ opacity: enabled && !hasEdit ? 1 : 0.5 }}>
            {displayName}
            {docUrl && (
              <a href={docUrl} target="_blank" rel="noopener noreferrer" className="doc-link">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"/>
                  <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
                  <line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
              </a>
            )}
          </div>
          <div className="api-key-value">
            <input
              type="text"
              value={hasEdit ? editedValue : (enabled ? key : '')}
              onChange={(e) => handleKeyChange(provider, e.target.value)}
              className={`api-key-input ${!enabled && !hasEdit ? 'disabled' : ''}`}
              placeholder={customPlaceholder || `Enter ${displayName} API key`}
            />
          </div>
        </div>
        <div className="api-key-actions">
          {hasEdit && (
            <>
              <button
                onClick={() => handleSaveKey(provider)}
                disabled={isSaving || !editedValue.trim()}
                className="btn-save"
              >
                {isSaving ? (
                  <span className="spinner-small"></span>
                ) : (
                  'Save'
                )}
              </button>
              <button
                onClick={() => {
                  setEditedKeys(prev => {
                    const next = { ...prev }
                    delete next[provider]
                    return next
                  })
                  setTestResults(prev => ({
                    ...prev,
                    [provider]: null
                  }))
                }}
                className="btn-cancel"
                disabled={isSaving}
              >
                Cancel
              </button>
            </>
          )}
          {!hasEdit && enabled && key && !key.includes('*') && (
            <button
              onClick={() => testKey(provider, key)}
              disabled={isTesting}
              className="btn-test"
            >
              {isTesting ? (
                <span className="spinner-small"></span>
              ) : (
                'Test'
              )}
            </button>
          )}
          {testResult && (
            <div className={`test-result ${testResult.valid ? 'valid' : 'invalid'}`}>
              {testResult.valid ? (
                <>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="20 6 9 17 4 12"/>
                  </svg>
                  {testResult.latency && <span className="latency">{testResult.latency}ms</span>}
                  {testResult.error && !testResult.latency && <span className="latency">{testResult.error}</span>}
                </>
              ) : (
                <>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="15" y1="9" x2="9" y2="15"/>
                    <line x1="9" y1="9" x2="15" y2="15"/>
                  </svg>
                  <span className="error-text">{testResult.error}</span>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
        <p>Loading configuration...</p>
      </div>
    )
  }

  if (!config) {
    return (
      <div className="empty-state">
        <h3>Failed to load configuration</h3>
        <p>Please check your connection and try again</p>
      </div>
    )
  }

  const osintProviders = [
    { key: 'securitytrails', name: 'SecurityTrails', data: config.osint.securitytrails, url: 'https://securitytrails.com' },
    { key: 'shodan', name: 'Shodan', data: config.osint.shodan, url: 'https://shodan.io' },
    { key: 'censys', name: 'Censys', data: config.osint.censys, url: 'https://censys.io' },
    { key: 'virustotal', name: 'VirusTotal', data: config.osint.virustotal, url: 'https://virustotal.com' },
    { key: 'github', name: 'GitHub', data: config.osint.github, url: 'https://github.com/settings/tokens' },
    { key: 'chaos', name: 'Chaos (PDCP)', data: config.osint.chaos, url: 'https://cloud.projectdiscovery.io' },
    { key: 'binaryedge', name: 'BinaryEdge', data: config.osint.binaryedge, url: 'https://binaryedge.io' },
    { key: 'hunter', name: 'Hunter', data: config.osint.hunter, url: 'https://hunter.io' },
    { key: 'intelx', name: 'IntelX', data: config.osint.intelx, url: 'https://intelx.io' },
    { key: 'urlscan', name: 'URLScan', data: config.osint.urlscan, url: 'https://urlscan.io' },
    { key: 'whoisxmlapi', name: 'WhoisXMLAPI', data: config.osint.whoisxmlapi, url: 'https://whoisxmlapi.com' },
    { key: 'zoomeye', name: 'ZoomEye', data: config.osint.zoomeye, url: 'https://zoomeye.org' },
    { key: 'fofa', name: 'Fofa', data: config.osint.fofa, url: 'https://fofa.info' },
    { key: 'quake', name: 'Quake', data: config.osint.quake, url: 'https://quake.360.cn' },
    { key: 'netlas', name: 'Netlas', data: config.osint.netlas, url: 'https://netlas.io' },
    { key: 'fullhunt', name: 'FullHunt', data: config.osint.fullhunt, url: 'https://fullhunt.io' },
    { key: 'certspotter', name: 'CertSpotter', data: config.osint.certspotter, url: 'https://sslmate.com/certspotter' },
    { key: 'bufferover', name: 'BufferOver', data: config.osint.bufferover, url: 'https://tls.bufferover.run' },
    { key: 'c99', name: 'C99', data: config.osint.c99, url: 'https://api.c99.nl' },
    { key: 'chinaz', name: 'Chinaz', data: config.osint.chinaz, url: 'https://chinaz.com' },
    { key: 'dnsdb', name: 'DNSDB', data: config.osint.dnsdb, url: 'https://www.dnsdb.info' },
    { key: 'passivetotal', name: 'PassiveTotal', data: config.osint.passivetotal, url: 'https://community.riskiq.com' },
    { key: 'robtex', name: 'Robtex', data: config.osint.robtex, url: 'https://www.robtex.com' },
    { key: 'threatbook', name: 'ThreatBook', data: config.osint.threatbook, url: 'https://threatbook.cn' },
  ]

  const aiProviders = [
    { key: 'openai', name: 'OpenAI', data: config.ai.openai, url: 'https://platform.openai.com/api-keys' },
    { key: 'claude', name: 'Anthropic Claude', data: config.ai.claude, url: 'https://console.anthropic.com' },
    { key: 'gemini', name: 'Google Gemini', data: config.ai.gemini, url: 'https://aistudio.google.com/apikey' },
    { key: 'groq', name: 'Groq', data: config.ai.groq, url: 'https://console.groq.com/keys' },
    { key: 'deepseek', name: 'DeepSeek', data: config.ai.deepseek, url: 'https://platform.deepseek.com/api_keys' },
    { key: 'kimi', name: 'Kimi (Moonshot)', data: config.ai?.kimi, url: 'https://moonshot.cn' },
    { key: 'minimax', name: 'Minimax', data: config.ai?.minimax, url: 'https://minimaxi.com' },
    { key: 'ollama', name: 'Ollama (Local)', data: config.ai?.ollama, url: 'https://ollama.ai', isUrl: true, placeholder: 'http://localhost:11434' },
  ]

  return (
    <div>
      <h1 style={{ marginBottom: 12, fontSize: 24, fontWeight: 600 }}>Configuration</h1>
      <p style={{ color: 'var(--text-secondary)', marginBottom: 32, fontSize: 14 }}>
        Manage API keys for OSINT sources and AI providers. API keys are masked for security.
      </p>

      {/* Section Tabs */}
      <div className="config-tabs">
        <button
          className={`config-tab ${activeSection === 'osint' ? 'active' : ''}`}
          onClick={() => setActiveSection('osint')}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8"/>
            <path d="M21 21l-4.35-4.35"/>
          </svg>
          OSINT / Subdomain APIs
        </button>
        <button
          className={`config-tab ${activeSection === 'ai' ? 'active' : ''}`}
          onClick={() => setActiveSection('ai')}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 2L2 7l10 5 10-5-10-5z"/>
            <path d="M2 17l10 5 10-5"/>
            <path d="M2 12l10 5 10-5"/>
          </svg>
          AI Providers
        </button>
        <button
          className={`config-tab ${activeSection === 'infra' ? 'active' : ''}`}
          onClick={() => setActiveSection('infra')}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
            <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
            <line x1="6" y1="6" x2="6.01" y2="6"/>
            <line x1="6" y1="18" x2="6.01" y2="18"/>
          </svg>
          Infrastructure
        </button>
        <button
          className={`config-tab ${activeSection === 'notify' ? 'active' : ''}`}
          onClick={() => setActiveSection('notify')}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
            <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
          </svg>
          Notifications
        </button>
      </div>

      {/* OSINT Section */}
      {activeSection === 'osint' && (
        <div className="card" style={{ marginTop: 24 }}>
          <div className="card-header">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h2>OSINT Data Sources</h2>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
                  API keys for subdomain enumeration and reconnaissance
                </p>
              </div>
              <button
                onClick={handleSync}
                disabled={syncing}
                className="btn btn-secondary"
                style={{ marginLeft: 16 }}
              >
                {syncing ? (
                  <>
                    <span className="spinner-small" style={{ marginRight: 8 }}></span>
                    Syncing...
                  </>
                ) : (
                  <>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginRight: 8 }}>
                      <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/>
                    </svg>
                    Sync from Config
                  </>
                )}
              </button>
            </div>
          </div>
          <div className="card-body">
            <div className="api-keys-list">
              {osintProviders.map(provider =>
                renderAPIKeyRow(provider.key, provider.name, provider.data, provider.url)
              )}
            </div>
          </div>
        </div>
      )}

      {/* AI Section */}
      {activeSection === 'ai' && (
        <div className="card" style={{ marginTop: 24 }}>
          <div className="card-header">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h2>AI Provider Keys</h2>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
                  API keys for AI-powered reconnaissance features
                </p>
              </div>
              <button
                onClick={handleSync}
                disabled={syncing}
                className="btn btn-secondary"
                style={{ marginLeft: 16 }}
              >
                {syncing ? (
                  <>
                    <span className="spinner-small" style={{ marginRight: 8 }}></span>
                    Syncing...
                  </>
                ) : (
                  <>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginRight: 8 }}>
                      <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/>
                    </svg>
                    Sync from Config
                  </>
                )}
              </button>
            </div>
          </div>
          <div className="card-body">
            <div className="api-keys-list">
              {aiProviders.map(provider =>
                renderAPIKeyRow(provider.key, provider.name, provider.data, provider.url, provider.placeholder)
              )}
            </div>
          </div>
        </div>
      )}

      {/* Infrastructure Section */}
      {activeSection === 'infra' && (
        <>
          {/* Distributed Scanning Defaults */}
          <div className="card" style={{ marginTop: 24 }}>
            <div className="card-header">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h2>Distributed Scanning Defaults</h2>
                  <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
                    Default settings for cloud-based distributed scanning infrastructure
                  </p>
                </div>
                <div className="api-key-actions">
                  {infraDirty && (
                    <>
                      <button
                        onClick={handleSaveInfra}
                        disabled={savingInfra}
                        className="btn-save"
                      >
                        {savingInfra ? <span className="spinner-small"></span> : 'Save All'}
                      </button>
                      <button
                        onClick={() => {
                          const infra = config.infrastructure || {}
                          setInfraConfig({
                            distributed_provider: infra.distributed_provider || 'aws',
                            distributed_workers: infra.distributed_workers ?? 3,
                            distributed_spot: infra.distributed_spot ?? false,
                            distributed_region: infra.distributed_region || '',
                            distributed_instance_size: infra.distributed_instance_size || '',
                            distributed_ssh_key_path: infra.distributed_ssh_key_path || '',
                            distributed_ssh_key_id: infra.distributed_ssh_key_id || '',
                            distributed_cloud_api_key: infra.distributed_cloud_api_key || '',
                            ip_rotation_regions: infra.ip_rotation_regions || '',
                          })
                          setInfraDirty(false)
                          setTestResults(prev => ({ ...prev, infrastructure: null }))
                        }}
                        className="btn-cancel"
                        disabled={savingInfra}
                      >
                        Cancel
                      </button>
                    </>
                  )}
                  {testResults.infrastructure && (
                    <div className={`test-result ${testResults.infrastructure.valid ? 'valid' : 'invalid'}`}>
                      {testResults.infrastructure.valid ? (
                        <>
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <polyline points="20 6 9 17 4 12"/>
                          </svg>
                          <span className="latency">{testResults.infrastructure.error}</span>
                        </>
                      ) : (
                        <>
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="15" y1="9" x2="9" y2="15"/>
                            <line x1="9" y1="9" x2="15" y2="15"/>
                          </svg>
                          <span className="error-text">{testResults.infrastructure.error}</span>
                        </>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
            <div className="card-body">
              <div className="api-keys-list">
                {/* Default Provider */}
                <div className="api-key-row">
                  <div className="api-key-info">
                    <div className="api-key-name">Default Provider</div>
                    <div className="api-key-value">
                      <select
                        value={infraConfig.distributed_provider || 'aws'}
                        onChange={(e) => handleInfraChange('distributed_provider', e.target.value)}
                        className="api-key-input"
                      >
                        <option value="aws">AWS</option>
                        <option value="digitalocean">DigitalOcean</option>
                      </select>
                    </div>
                  </div>
                </div>

                {/* Default Workers */}
                <div className="api-key-row">
                  <div className="api-key-info">
                    <div className="api-key-name">Default Workers</div>
                    <div className="api-key-value">
                      <input
                        type="number"
                        min="1"
                        max="50"
                        value={infraConfig.distributed_workers ?? 3}
                        onChange={(e) => handleInfraChange('distributed_workers', parseInt(e.target.value, 10) || 1)}
                        className="api-key-input"
                        placeholder="3"
                      />
                    </div>
                  </div>
                </div>

                {/* Spot Instances */}
                <div className="api-key-row">
                  <div className="api-key-info">
                    <div className="api-key-name">Spot Instances</div>
                    <div className="api-key-value" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 14, color: 'var(--text-secondary)' }}>
                        <input
                          type="checkbox"
                          checked={infraConfig.distributed_spot ?? false}
                          onChange={(e) => handleInfraChange('distributed_spot', e.target.checked)}
                          style={{ width: 16, height: 16, accentColor: 'var(--primary)' }}
                        />
                        Use spot/preemptible instances for cost savings
                      </label>
                    </div>
                  </div>
                </div>

                {/* Default Region */}
                <div className="api-key-row">
                  <div className="api-key-info">
                    <div className="api-key-name">Default Region</div>
                    <div className="api-key-value">
                      <input
                        type="text"
                        value={infraConfig.distributed_region || ''}
                        onChange={(e) => handleInfraChange('distributed_region', e.target.value)}
                        className="api-key-input"
                        placeholder="us-east-1"
                      />
                    </div>
                  </div>
                </div>

                {/* Default Instance Size */}
                <div className="api-key-row">
                  <div className="api-key-info">
                    <div className="api-key-name">Default Instance Size</div>
                    <div className="api-key-value">
                      <input
                        type="text"
                        value={infraConfig.distributed_instance_size || ''}
                        onChange={(e) => handleInfraChange('distributed_instance_size', e.target.value)}
                        className="api-key-input"
                        placeholder="t3.small"
                      />
                    </div>
                  </div>
                </div>

                {/* SSH Key Path */}
                <div className="api-key-row">
                  <div className="api-key-info">
                    <div className="api-key-name">SSH Key Path</div>
                    <div className="api-key-value">
                      <input
                        type="text"
                        value={infraConfig.distributed_ssh_key_path || ''}
                        onChange={(e) => handleInfraChange('distributed_ssh_key_path', e.target.value)}
                        className="api-key-input"
                        placeholder="~/.ssh/id_rsa"
                      />
                    </div>
                  </div>
                </div>

                {/* SSH Key ID */}
                <div className="api-key-row">
                  <div className="api-key-info">
                    <div className="api-key-name">SSH Key ID</div>
                    <div className="api-key-value">
                      <input
                        type="text"
                        value={infraConfig.distributed_ssh_key_id || ''}
                        onChange={(e) => handleInfraChange('distributed_ssh_key_id', e.target.value)}
                        className="api-key-input"
                        placeholder="key-0123456789abcdef"
                      />
                    </div>
                  </div>
                </div>

                {/* Cloud API Key */}
                <div className="api-key-row">
                  <div className="api-key-info">
                    <div className="api-key-name">Cloud API Key</div>
                    <div className="api-key-value">
                      <input
                        type="password"
                        value={infraConfig.distributed_cloud_api_key || ''}
                        onChange={(e) => handleInfraChange('distributed_cloud_api_key', e.target.value)}
                        className="api-key-input"
                        placeholder="Enter cloud provider API key"
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* IP Rotation Defaults */}
          <div className="card" style={{ marginTop: 24 }}>
            <div className="card-header">
              <div>
                <h2>IP Rotation Defaults</h2>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
                  Default settings for IP rotation during scans
                </p>
              </div>
            </div>
            <div className="card-body">
              <div className="api-keys-list">
                <div className="api-key-row">
                  <div className="api-key-info">
                    <div className="api-key-name">Default Regions</div>
                    <div className="api-key-value">
                      <input
                        type="text"
                        value={infraConfig.ip_rotation_regions || ''}
                        onChange={(e) => handleInfraChange('ip_rotation_regions', e.target.value)}
                        className="api-key-input"
                        placeholder="us-east-1, us-west-2, eu-west-1"
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Notifications Section */}
      {activeSection === 'notify' && (
        <>
          {/* Sync Button for Notifications */}
          <div style={{ marginTop: 24, marginBottom: 16, display: 'flex', justifyContent: 'flex-end' }}>
            <button
              onClick={handleSync}
              disabled={syncing}
              className="btn btn-secondary"
            >
              {syncing ? (
                <>
                  <span className="spinner-small" style={{ marginRight: 8 }}></span>
                  Syncing...
                </>
              ) : (
                <>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginRight: 8 }}>
                    <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/>
                  </svg>
                  Sync from Config
                </>
              )}
            </button>
          </div>

          {/* Slack */}
          <div className="card" style={{ marginTop: 8 }}>
            <div className="card-header">
              <h2>Slack</h2>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
                Get scan notifications via Slack webhook
              </p>
            </div>
            <div className="card-body">
              <div className="api-key-row">
                <div className="api-key-info" style={{ flex: 1 }}>
                  <div className="api-key-name">
                    Webhook URL
                    <a href="https://api.slack.com/messaging/webhooks" target="_blank" rel="noopener noreferrer" className="doc-link">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="12" cy="12" r="10"/>
                        <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                      </svg>
                    </a>
                  </div>
                  <div className="api-key-value">
                    <input
                      type="text"
                      value={editedKeys['slack_webhook'] || (config.notify?.slack?.[0]?.slack_webhook_url || '')}
                      onChange={(e) => handleKeyChange('slack_webhook', e.target.value)}
                      className="api-key-input"
                      placeholder="https://hooks.slack.com/services/XXX/XXX/XXX"
                    />
                  </div>
                </div>
                <div className="api-key-actions">
                  {editedKeys['slack_webhook'] !== undefined && (
                    <>
                      <button
                        onClick={() => handleSaveKey('slack_webhook')}
                        disabled={saving['slack_webhook']}
                        className="btn-save"
                      >
                        {saving['slack_webhook'] ? <span className="spinner-small"></span> : 'Save'}
                      </button>
                      <button
                        onClick={() => {
                          setEditedKeys(prev => {
                            const next = { ...prev }
                            delete next['slack_webhook']
                            return next
                          })
                        }}
                        className="btn-cancel"
                      >
                        Cancel
                      </button>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Discord */}
          <div className="card" style={{ marginTop: 24 }}>
            <div className="card-header">
              <h2>Discord</h2>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
                Get scan notifications via Discord webhook
              </p>
            </div>
            <div className="card-body">
              <div className="api-key-row">
                <div className="api-key-info" style={{ flex: 1 }}>
                  <div className="api-key-name">
                    Webhook URL
                    <a href="https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks" target="_blank" rel="noopener noreferrer" className="doc-link">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="12" cy="12" r="10"/>
                        <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                      </svg>
                    </a>
                  </div>
                  <div className="api-key-value">
                    <input
                      type="text"
                      value={editedKeys['discord_webhook'] || (config.notify?.discord?.[0]?.discord_webhook_url || '')}
                      onChange={(e) => handleKeyChange('discord_webhook', e.target.value)}
                      className="api-key-input"
                      placeholder="https://discord.com/api/webhooks/XXX/XXX"
                    />
                  </div>
                </div>
                <div className="api-key-actions">
                  {editedKeys['discord_webhook'] !== undefined && (
                    <>
                      <button
                        onClick={() => handleSaveKey('discord_webhook')}
                        disabled={saving['discord_webhook']}
                        className="btn-save"
                      >
                        {saving['discord_webhook'] ? <span className="spinner-small"></span> : 'Save'}
                      </button>
                      <button
                        onClick={() => {
                          setEditedKeys(prev => {
                            const next = { ...prev }
                            delete next['discord_webhook']
                            return next
                          })
                        }}
                        className="btn-cancel"
                      >
                        Cancel
                      </button>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Telegram */}
          <div className="card" style={{ marginTop: 24 }}>
            <div className="card-header">
              <h2>Telegram</h2>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
                Get scan notifications via Telegram bot
              </p>
            </div>
            <div className="card-body">
              <div className="api-key-row">
                <div className="api-key-info" style={{ flex: 1 }}>
                  <div className="api-key-name">
                    Bot API Key
                    <a href="https://core.telegram.org/bots#how-do-i-create-a-bot" target="_blank" rel="noopener noreferrer" className="doc-link">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="12" cy="12" r="10"/>
                        <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                      </svg>
                    </a>
                  </div>
                  <div className="api-key-value">
                    <input
                      type="text"
                      value={editedKeys['telegram_api_key'] || (config.notify?.telegram?.[0]?.telegram_api_key || '')}
                      onChange={(e) => handleKeyChange('telegram_api_key', e.target.value)}
                      className="api-key-input"
                      placeholder="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
                    />
                  </div>
                </div>
                <div className="api-key-actions">
                  {editedKeys['telegram_api_key'] !== undefined && (
                    <>
                      <button
                        onClick={() => handleSaveKey('telegram_api_key')}
                        disabled={saving['telegram_api_key']}
                        className="btn-save"
                      >
                        {saving['telegram_api_key'] ? <span className="spinner-small"></span> : 'Save'}
                      </button>
                      <button
                        onClick={() => {
                          setEditedKeys(prev => {
                            const next = { ...prev }
                            delete next['telegram_api_key']
                            return next
                          })
                        }}
                        className="btn-cancel"
                      >
                        Cancel
                      </button>
                    </>
                  )}
                </div>
              </div>
              <div className="api-key-row" style={{ marginTop: 12 }}>
                <div className="api-key-info" style={{ flex: 1 }}>
                  <div className="api-key-name">Chat ID</div>
                  <div className="api-key-value">
                    <input
                      type="text"
                      value={editedKeys['telegram_chat_id'] || (config.notify?.telegram?.[0]?.telegram_chat_id || '')}
                      onChange={(e) => handleKeyChange('telegram_chat_id', e.target.value)}
                      className="api-key-input"
                      placeholder="-1001234567890"
                    />
                  </div>
                </div>
                <div className="api-key-actions">
                  {editedKeys['telegram_chat_id'] !== undefined && (
                    <>
                      <button
                        onClick={() => handleSaveKey('telegram_chat_id')}
                        disabled={saving['telegram_chat_id']}
                        className="btn-save"
                      >
                        {saving['telegram_chat_id'] ? <span className="spinner-small"></span> : 'Save'}
                      </button>
                      <button
                        onClick={() => {
                          setEditedKeys(prev => {
                            const next = { ...prev }
                            delete next['telegram_chat_id']
                            return next
                          })
                        }}
                        className="btn-cancel"
                      >
                        Cancel
                      </button>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Security Notice */}
      <div className="info-box" style={{ marginTop: 24 }}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="16" x2="12" y2="12"/>
          <line x1="12" y1="8" x2="12.01" y2="8"/>
        </svg>
        <div>
          <strong>Security Notice</strong>
          <p>API keys are stored in ~/.reconator/config.yaml with 0600 permissions (owner read/write only).
          Keys are masked in this interface and never sent to the frontend. Use the CLI to manage keys:
          <code>reconator config</code></p>
        </div>
      </div>
    </div>
  )
}

export default Configuration
