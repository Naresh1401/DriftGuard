import { useEffect, useState } from 'react'
import { AlertTriangle, TrendingUp, Shield } from 'lucide-react'
import { api } from '../api'

interface Props {
  domain?: string
  horizonDays?: number
}

const LEVEL_COLORS: Record<string, string> = {
  Low: 'bg-green-50 border-green-200 text-green-800',
  Moderate: 'bg-blue-50 border-blue-200 text-blue-800',
  Elevated: 'bg-yellow-50 border-yellow-200 text-yellow-800',
  High: 'bg-orange-50 border-orange-200 text-orange-800',
  Critical: 'bg-red-50 border-red-200 text-red-800',
}

const BAR_COLORS: Record<string, string> = {
  Low: 'bg-green-500',
  Moderate: 'bg-blue-500',
  Elevated: 'bg-yellow-500',
  High: 'bg-orange-500',
  Critical: 'bg-red-500',
}

export default function RiskForecastCard({ domain = 'enterprise', horizonDays = 30 }: Props) {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.getRiskForecast>> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api
      .getRiskForecast(domain, horizonDays)
      .then((d) => {
        if (!cancelled) {
          setData(d)
          setError(null)
        }
      })
      .catch((e) => !cancelled && setError(e.message))
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
    }
  }, [domain, horizonDays])

  if (loading) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-6 animate-pulse">
        <div className="h-4 bg-gray-200 rounded w-1/3 mb-4" />
        <div className="h-8 bg-gray-200 rounded w-1/2 mb-3" />
        <div className="h-2 bg-gray-200 rounded w-full" />
      </div>
    )
  }
  if (error || !data) {
    return (
      <div className="bg-white rounded-lg border border-red-200 p-6 text-red-700 text-sm">
        Risk forecast unavailable: {error || 'no data'}
      </div>
    )
  }

  const levelClass = LEVEL_COLORS[data.risk_level] || LEVEL_COLORS.Moderate
  const barClass = BAR_COLORS[data.risk_level] || BAR_COLORS.Moderate
  const pct = data.breach_probability_pct
  const ciLow = Math.round(data.confidence_interval.low * 100 * 10) / 10
  const ciHigh = Math.round(data.confidence_interval.high * 100 * 10) / 10

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4 sm:p-6">
      <div className="flex items-start justify-between flex-wrap gap-2 mb-4">
        <div>
          <div className="flex items-center gap-2 text-sm text-gray-500 font-medium">
            <TrendingUp size={14} /> Predictive Breach Forecast
          </div>
          <div className="text-xs text-gray-400 mt-0.5">
            {data.domain} · {data.horizon_days}-day horizon · {data.active_signals} active signal{data.active_signals === 1 ? '' : 's'}
          </div>
        </div>
        <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${levelClass}`}>
          {data.risk_level}
        </span>
      </div>

      <div className="flex items-baseline gap-2 mb-2">
        <span className="text-3xl sm:text-4xl font-bold text-gray-900">{pct.toFixed(1)}%</span>
        <span className="text-sm text-gray-500">breach probability</span>
      </div>
      <div className="text-xs text-gray-500 mb-4">
        95% CI: {ciLow.toFixed(1)}% – {ciHigh.toFixed(1)}% · baseline {data.components.domain_baseline_pct}%
      </div>

      <div className="h-2 w-full bg-gray-100 rounded-full overflow-hidden mb-5">
        <div className={`h-full ${barClass} transition-all`} style={{ width: `${Math.min(100, pct)}%` }} />
      </div>

      {data.top_contributing_patterns.length > 0 && (
        <div className="mb-3">
          <div className="flex items-center gap-1 text-xs text-gray-500 font-medium mb-1.5">
            <AlertTriangle size={12} /> Top drift contributors
          </div>
          <div className="flex flex-wrap gap-1.5">
            {data.top_contributing_patterns.map((p) => (
              <span key={p.pattern} className="text-xs px-2 py-0.5 bg-gray-100 rounded text-gray-700">
                {p.pattern} · {p.contribution.toFixed(2)}
              </span>
            ))}
          </div>
        </div>
      )}

      {data.top_nist_gaps.length > 0 && (
        <div>
          <div className="flex items-center gap-1 text-xs text-gray-500 font-medium mb-1.5">
            <Shield size={12} /> NIST controls at risk
          </div>
          <div className="flex flex-wrap gap-1.5">
            {data.top_nist_gaps.map((c) => (
              <span key={c.control} className="text-xs px-2 py-0.5 bg-indigo-50 text-indigo-700 rounded font-mono">
                {c.control}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
