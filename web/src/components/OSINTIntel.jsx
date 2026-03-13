import React, { useState } from 'react'

export default function OSINTIntel({ report }) {
  const [activeTab, setActiveTab] = useState('whois')

  const osint = report?.osint || report?.osint_result || null

  if (!osint) {
    return (
      <div className="empty-state">
        <h3>No OSINT Data</h3>
        <p>No OSINT intelligence was collected in this scan</p>
      </div>
    )
  }

  const tabs = [
    { id: 'whois', label: 'WHOIS', icon: '🔍' },
    { id: 'asn', label: 'ASN', icon: '🌐' },
    { id: 'certs', label: 'Certificates', icon: '📜' },
    { id: 'related', label: 'Related Domains', icon: '🔗' },
    { id: 'breach', label: 'Breaches', icon: '⚠️' },
  ]

  return (
    <div className="osint-intel">
      <div className="osint-tabs-row">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`osint-tab-btn ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.icon} {tab.label}
          </button>
        ))}
      </div>

      <div className="osint-tab-content">
        {activeTab === 'whois' && <WHOISPanel data={osint.whois} />}
        {activeTab === 'asn' && <ASNPanel data={osint.asn} />}
        {activeTab === 'certs' && <CertsPanel data={osint.cert_transparency} />}
        {activeTab === 'related' && <RelatedPanel data={osint.related_domains} />}
        {activeTab === 'breach' && <BreachPanel data={osint.breach_data} />}
      </div>

      <style>{`
        .osint-tabs-row { display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; }
        .osint-tab-btn { padding: 8px 16px; border: 1px solid var(--border, #333); border-radius: 6px; background: var(--bg-secondary, #1a1a2e); color: var(--text-secondary, #aaa); cursor: pointer; font-size: 0.85rem; transition: all 0.2s; }
        .osint-tab-btn.active { background: var(--accent, #6366f1); color: #fff; border-color: var(--accent, #6366f1); }
        .osint-tab-btn:hover:not(.active) { border-color: var(--text-muted, #888); }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 16px; }
        .info-card { padding: 12px 16px; background: var(--bg-secondary, #1a1a2e); border-radius: 8px; }
        .info-card-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: var(--text-muted, #888); margin-bottom: 4px; }
        .info-card-value { font-size: 0.9rem; color: var(--text-primary, #fff); }
        .tags-row { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
      `}</style>
    </div>
  )
}

function WHOISPanel({ data }) {
  if (!data) return <div className="empty-state"><p>WHOIS data not available</p></div>
  return (
    <div>
      <div className="info-grid">
        <InfoCard label="Registrar" value={data.registrar} />
        <InfoCard label="Organization" value={data.org_name} />
        <InfoCard label="Country" value={data.country} />
        <InfoCard label="Created" value={data.created_date} />
        <InfoCard label="Expires" value={data.expiry_date} />
      </div>
      {data.emails?.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <strong style={{ fontSize: '0.85rem' }}>Emails:</strong>
          <div className="tags-row">{data.emails.map(e => <span key={e} className="badge badge-info">{e}</span>)}</div>
        </div>
      )}
      {data.nameservers?.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <strong style={{ fontSize: '0.85rem' }}>Name Servers:</strong>
          <div className="tags-row">{data.nameservers.map(ns => <span key={ns} className="badge badge-secondary">{ns}</span>)}</div>
        </div>
      )}
    </div>
  )
}

function ASNPanel({ data }) {
  if (!data) return <div className="empty-state"><p>ASN data not available</p></div>
  return (
    <div>
      <div className="info-grid">
        <InfoCard label="ASN" value={`AS${data.asn}`} />
        <InfoCard label="Organization" value={data.org_name} />
        <InfoCard label="Provider" value={data.provider || 'Unknown'} />
        <InfoCard label="Country" value={data.country} />
        <InfoCard label="RIR" value={data.rir} />
      </div>
      {data.cidrs?.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <strong style={{ fontSize: '0.85rem' }}>IP Ranges:</strong>
          <div className="tags-row">{data.cidrs.map(c => <span key={c} className="badge badge-secondary">{c}</span>)}</div>
        </div>
      )}
    </div>
  )
}

function CertsPanel({ data }) {
  if (!data?.length) return <div className="empty-state"><p>No certificate transparency data</p></div>
  return (
    <div className="data-table-wrapper">
      <table className="data-table">
        <thead><tr><th>Domain</th><th>Issuer</th><th>Valid From</th><th>Valid To</th></tr></thead>
        <tbody>
          {data.map((cert, i) => (
            <tr key={i}>
              <td style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{cert.domain}</td>
              <td>{cert.issuer}</td>
              <td>{cert.not_before}</td>
              <td>{cert.not_after}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function RelatedPanel({ data }) {
  if (!data?.length) return <div className="empty-state"><p>No related domains discovered</p></div>
  return (
    <div className="data-table-wrapper">
      <table className="data-table">
        <thead><tr><th>Domain</th><th>Relation</th><th>Confidence</th><th>Source</th></tr></thead>
        <tbody>
          {data.map((d, i) => (
            <tr key={i}>
              <td style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{d.domain}</td>
              <td><span className="badge badge-info">{d.relation}</span></td>
              <td>{Math.round((d.confidence || 0) * 100)}%</td>
              <td>{d.source}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function BreachPanel({ data }) {
  if (!data?.length) return <div className="empty-state"><p>No known breaches found</p></div>
  return (
    <div>
      {data.map((breach, i) => (
        <div key={i} style={{ borderBottom: '1px solid var(--border, #333)', padding: '16px 0' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
            <strong>{breach.name}</strong>
            <span className="badge badge-warning">{breach.breach_date}</span>
          </div>
          {breach.description && <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary, #aaa)', marginBottom: 8 }}>{breach.description}</p>}
          <div className="tags-row">
            {breach.record_count > 0 && <span className="badge badge-secondary">{breach.record_count.toLocaleString()} records</span>}
            {breach.data_classes?.map(dc => <span key={dc} className="badge badge-info">{dc}</span>)}
          </div>
        </div>
      ))}
    </div>
  )
}

function InfoCard({ label, value }) {
  return (
    <div className="info-card">
      <div className="info-card-label">{label}</div>
      <div className="info-card-value">{value || <span style={{ color: 'var(--text-muted, #888)' }}>N/A</span>}</div>
    </div>
  )
}
