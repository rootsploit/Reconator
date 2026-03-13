import { useState, useEffect } from 'react'

function FindingsFilter({ onFilterChange, initialFilters = {} }) {
  const [filters, setFilters] = useState({
    severities: initialFilters.severities || [],
    types: initialFilters.types || [],
    host: initialFilters.host || '',
    search: initialFilters.search || '',
    includeFP: initialFilters.includeFP || false
  })

  const [searchInput, setSearchInput] = useState(filters.search)
  const [searchTimeout, setSearchTimeout] = useState(null)
  const [isExpanded, setIsExpanded] = useState(false)

  // Debounced search
  useEffect(() => {
    if (searchTimeout) clearTimeout(searchTimeout)

    const timeout = setTimeout(() => {
      if (searchInput !== filters.search) {
        handleFilterChange('search', searchInput)
      }
    }, 500)

    setSearchTimeout(timeout)

    return () => {
      if (searchTimeout) clearTimeout(searchTimeout)
    }
  }, [searchInput])

  const handleFilterChange = (key, value) => {
    const newFilters = { ...filters, [key]: value }
    setFilters(newFilters)
    onFilterChange(newFilters)
  }

  const toggleSeverity = (severity) => {
    const newSeverities = filters.severities.includes(severity)
      ? filters.severities.filter(s => s !== severity)
      : [...filters.severities, severity]
    handleFilterChange('severities', newSeverities)
  }

  const toggleType = (type) => {
    const newTypes = filters.types.includes(type)
      ? filters.types.filter(t => t !== type)
      : [...filters.types, type]
    handleFilterChange('types', newTypes)
  }

  const clearFilters = () => {
    const emptyFilters = {
      severities: [],
      types: [],
      host: '',
      search: '',
      includeFP: false
    }
    setFilters(emptyFilters)
    setSearchInput('')
    onFilterChange(emptyFilters)
  }

  const hasActiveFilters = filters.severities.length > 0 || filters.types.length > 0 ||
                          filters.host !== '' || filters.search !== '' || filters.includeFP

  const severityOptions = [
    { value: 'critical', label: 'Critical', color: 'var(--critical)' },
    { value: 'high', label: 'High', color: 'var(--high)' },
    { value: 'medium', label: 'Medium', color: 'var(--medium)' },
    { value: 'low', label: 'Low', color: 'var(--low)' },
    { value: 'info', label: 'Info', color: 'var(--info)' }
  ]

  const typeOptions = [
    'xss', 'sqli', 'rce', 'lfi', 'ssrf', 'xxe', 'open-redirect',
    'idor', 'csrf', 'auth-bypass', 'info-leak', 'misconfiguration'
  ]

  return (
    <div className="findings-filter">
      <div className="filter-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            background: 'none',
            border: 'none',
            padding: 0,
            fontSize: 14,
            fontWeight: 600,
            color: 'var(--text-primary)',
            cursor: 'pointer'
          }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ transform: isExpanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}>
            <polyline points="6 9 12 15 18 9"/>
          </svg>
          Filters
          {hasActiveFilters && (
            <span style={{
              padding: '2px 6px',
              borderRadius: 4,
              fontSize: 10,
              fontWeight: 600,
              background: 'var(--accent-glow)',
              color: 'var(--accent)'
            }}>
              {filters.severities.length + filters.types.length + (filters.host ? 1 : 0) + (filters.search ? 1 : 0)}
            </span>
          )}
        </button>
        {hasActiveFilters && (
          <button
            className="btn btn-sm"
            onClick={clearFilters}
            style={{ padding: '4px 12px', fontSize: 12 }}
          >
            Clear All
          </button>
        )}
      </div>

      {isExpanded && (
        <div className="filter-content">

      {/* Search */}
      <div className="filter-section" style={{ marginBottom: 20 }}>
        <label style={{ display: 'block', fontSize: 12, fontWeight: 500, marginBottom: 8, color: 'var(--text-secondary)' }}>
          Search
        </label>
        <input
          type="text"
          placeholder="Search in names and descriptions..."
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          className="input"
          style={{
            width: '100%',
            padding: '8px 12px',
            borderRadius: 6,
            border: '1px solid var(--border)',
            background: 'var(--bg-secondary)',
            color: 'var(--text-primary)',
            fontSize: 13
          }}
        />
      </div>

      {/* Severity Filter */}
      <div className="filter-section" style={{ marginBottom: 20 }}>
        <label style={{ display: 'block', fontSize: 12, fontWeight: 500, marginBottom: 8, color: 'var(--text-secondary)' }}>
          Severity
        </label>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {severityOptions.map(sev => (
            <button
              key={sev.value}
              onClick={() => toggleSeverity(sev.value)}
              className={`filter-chip ${filters.severities.includes(sev.value) ? 'active' : ''}`}
              style={{
                padding: '6px 12px',
                borderRadius: 6,
                border: `1px solid ${filters.severities.includes(sev.value) ? sev.color : 'var(--border)'}`,
                background: filters.severities.includes(sev.value) ? `${sev.color}20` : 'var(--bg-secondary)',
                color: filters.severities.includes(sev.value) ? sev.color : 'var(--text-secondary)',
                fontSize: 12,
                fontWeight: 500,
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
            >
              {sev.label}
            </button>
          ))}
        </div>
      </div>

      {/* Type Filter */}
      <div className="filter-section" style={{ marginBottom: 20 }}>
        <label style={{ display: 'block', fontSize: 12, fontWeight: 500, marginBottom: 8, color: 'var(--text-secondary)' }}>
          Vulnerability Type
        </label>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {typeOptions.map(type => (
            <button
              key={type}
              onClick={() => toggleType(type)}
              className={`filter-chip ${filters.types.includes(type) ? 'active' : ''}`}
              style={{
                padding: '4px 10px',
                borderRadius: 4,
                border: `1px solid ${filters.types.includes(type) ? 'var(--accent)' : 'var(--border)'}`,
                background: filters.types.includes(type) ? 'var(--accent-glow)' : 'var(--bg-secondary)',
                color: filters.types.includes(type) ? 'var(--accent)' : 'var(--text-secondary)',
                fontSize: 11,
                fontWeight: 500,
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
            >
              {type.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Host Filter */}
      <div className="filter-section" style={{ marginBottom: 0 }}>
        <label style={{ display: 'block', fontSize: 12, fontWeight: 500, marginBottom: 8, color: 'var(--text-secondary)' }}>
          Host Filter
        </label>
        <input
          type="text"
          placeholder="Filter by hostname..."
          value={filters.host}
          onChange={(e) => handleFilterChange('host', e.target.value)}
          className="input"
          style={{
            width: '100%',
            padding: '8px 12px',
            borderRadius: 6,
            border: '1px solid var(--border)',
            background: 'var(--bg-secondary)',
            color: 'var(--text-primary)',
            fontSize: 13
          }}
        />
      </div>
        </div>
      )}

      {/* Active Filters Summary */}
      {hasActiveFilters && (
        <div className="active-filters" style={{ marginTop: 20, paddingTop: 20, borderTop: '1px solid var(--border)' }}>
          <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 8 }}>
            Active Filters
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {filters.severities.map(sev => (
              <div key={sev} className="filter-tag" style={{
                padding: '4px 8px',
                borderRadius: 4,
                background: 'var(--bg-hover)',
                color: 'var(--text-secondary)',
                fontSize: 11,
                display: 'flex',
                alignItems: 'center',
                gap: 4
              }}>
                {sev}
                <button onClick={() => toggleSeverity(sev)} style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: 0,
                  fontSize: 14,
                  lineHeight: 1
                }}>×</button>
              </div>
            ))}
            {filters.types.map(type => (
              <div key={type} className="filter-tag" style={{
                padding: '4px 8px',
                borderRadius: 4,
                background: 'var(--bg-hover)',
                color: 'var(--text-secondary)',
                fontSize: 11,
                display: 'flex',
                alignItems: 'center',
                gap: 4
              }}>
                {type}
                <button onClick={() => toggleType(type)} style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: 0,
                  fontSize: 14,
                  lineHeight: 1
                }}>×</button>
              </div>
            ))}
            {filters.host && (
              <div className="filter-tag" style={{
                padding: '4px 8px',
                borderRadius: 4,
                background: 'var(--bg-hover)',
                color: 'var(--text-secondary)',
                fontSize: 11,
                display: 'flex',
                alignItems: 'center',
                gap: 4
              }}>
                host: {filters.host}
                <button onClick={() => handleFilterChange('host', '')} style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: 0,
                  fontSize: 14,
                  lineHeight: 1
                }}>×</button>
              </div>
            )}
            {filters.search && (
              <div className="filter-tag" style={{
                padding: '4px 8px',
                borderRadius: 4,
                background: 'var(--bg-hover)',
                color: 'var(--text-secondary)',
                fontSize: 11,
                display: 'flex',
                alignItems: 'center',
                gap: 4
              }}>
                search: "{filters.search}"
                <button onClick={() => { setSearchInput(''); handleFilterChange('search', '') }} style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: 0,
                  fontSize: 14,
                  lineHeight: 1
                }}>×</button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export default FindingsFilter
