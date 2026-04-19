import { useEffect, useState } from 'react'
import { api } from '../api'
import { LoadingSpinner } from '../components/Shared'
import type { ThreatIntelItem, ThreatCorrelation } from '../types'
import { AlertTriangle, Shield, Filter } from 'lucide-react'
import clsx from 'clsx'

const SEV_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-green-100 text-green-700',
}

export default function ThreatIntel() {
  const [feed, setFeed] = useState<ThreatIntelItem[]>([])
  const [correlations, setCorrelations] = useState<ThreatCorrelation[]>([])
  const [loading, setLoading] = useState(true)
  const [sevFilter, setSevFilter] = useState<string>('')
  const [tab, setTab] = useState<'feed' | 'correlations'>('feed')
  const [activeCorrelations, setActiveCorrelations] = useState(0)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let c = false
    setError(null)
    Promise.all([
      api.getThreatFeed(sevFilter || undefined),
      api.getThreatCorrelations(),
    ]).then(([feedRes, corrRes]) => {
      if (c) return
      setFeed(feedRes.items)
      setCorrelations(corrRes.correlations)
      setActiveCorrelations(corrRes.active_correlations)
    }).catch(() => { if (!c) setError('Failed to load threat intelligence feed.') }).finally(() => { if (!c) setLoading(false) })
    return () => { c = true }
  }, [sevFilter])

  if (loading) return <LoadingSpinner />

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 text-sm text-yellow-800 flex items-center gap-2">
          <AlertTriangle size={16} className="shrink-0" /> {error}
        </div>
      )}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Threat Intelligence</h1>
        <p className="text-sm text-gray-500 mt-1">
          Curated advisories correlated with organizational drift patterns
        </p>
      </div>

      {activeCorrelations > 0 && (
        <div className="card border-l-4 border-red-500 bg-red-50">
          <div className="flex items-center gap-2 text-red-800">
            <AlertTriangle size={18} />
            <span className="text-sm font-semibold">
              {activeCorrelations} active threat correlation{activeCorrelations !== 1 ? 's' : ''} detected
            </span>
          </div>
          <p className="text-xs text-red-700 mt-1">
            Known threat patterns match your organization's current drift signals.
          </p>
        </div>
      )}

      <div className="flex items-center gap-4">
        <div className="flex gap-1 bg-gray-100 p-1 rounded-lg">
          <button onClick={() => setTab('feed')}
            className={clsx('px-4 py-2 rounded-md text-sm font-medium transition-colors',
              tab === 'feed' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600')}>
            <Shield size={14} className="inline mr-1.5" />
            Advisory Feed ({feed.length})
          </button>
          <button onClick={() => setTab('correlations')}
            className={clsx('px-4 py-2 rounded-md text-sm font-medium transition-colors',
              tab === 'correlations' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600')}>
            <AlertTriangle size={14} className="inline mr-1.5" />
            Correlations ({correlations.length})
          </button>
        </div>
        {tab === 'feed' && (
          <div className="flex items-center gap-2 text-sm text-gray-500">
            <Filter size={14} />
            <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}
              className="border border-gray-200 rounded px-2 py-1 text-sm">
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
            </select>
          </div>
        )}
      </div>

      {tab === 'feed' ? (
        <div className="space-y-3">
          {feed.length === 0 ? (
            <div className="card text-sm text-gray-400">No advisories match the current filter.</div>
          ) : feed.map(item => (
            <div key={item.id} className="card">
              <div className="flex items-start gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={clsx('px-2 py-0.5 rounded-full text-xs font-medium', SEV_COLORS[item.severity])}>
                      {item.severity}
                    </span>
                    <span className="text-xs text-gray-400">{item.source}</span>
                    <span className="text-xs text-gray-400">{new Date(item.published).toLocaleDateString()}</span>
                  </div>
                  <h3 className="text-sm font-semibold text-gray-900">{item.title}</h3>
                  <p className="text-xs text-gray-600 mt-1">{item.description}</p>
                  <div className="flex gap-2 mt-2">
                    {item.drift_patterns.map(p => (
                      <span key={p} className="text-xs bg-drift-50 text-drift-700 px-2 py-0.5 rounded">
                        {p.replace(/_/g, ' ')}
                      </span>
                    ))}
                    {item.nist_controls.map(c => (
                      <span key={c} className="text-xs bg-blue-50 text-blue-700 px-2 py-0.5 rounded font-mono">
                        {c}
                      </span>
                    ))}
                  </div>
                  {item.recommendations.length > 0 && (
                    <div className="mt-3 border-t pt-2">
                      <div className="text-xs font-medium text-gray-700 mb-1">Recommendations</div>
                      <ul className="text-xs text-gray-600 space-y-0.5 list-disc list-inside">
                        {item.recommendations.map((r, i) => <li key={i}>{r}</li>)}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="space-y-3">
          {correlations.length === 0 ? (
            <div className="card text-sm text-gray-400">
              No threat correlations. This is a good sign — no known threat patterns match your current drift signals.
            </div>
          ) : correlations.map((c, i) => (
            <div key={i} className="card border-l-4 border-red-400">
              <div className="flex items-start gap-3">
                <div className="p-2 rounded bg-red-50 text-red-600">
                  <AlertTriangle size={20} />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={clsx('px-2 py-0.5 rounded-full text-xs font-medium',
                      c.risk_level === 'critical' ? 'bg-red-100 text-red-700' : 'bg-orange-100 text-orange-700')}>
                      {c.risk_level}
                    </span>
                    <span className="text-xs text-gray-500">{c.matching_alert_count} matching alerts</span>
                  </div>
                  <h3 className="text-sm font-semibold text-gray-900">{c.threat.title}</h3>
                  <p className="text-xs text-gray-600 mt-1">{c.threat.description}</p>
                  <div className="flex gap-2 mt-2">
                    {c.threat.drift_patterns.map(p => (
                      <span key={p} className="text-xs bg-red-50 text-red-700 px-2 py-0.5 rounded">
                        {p.replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
