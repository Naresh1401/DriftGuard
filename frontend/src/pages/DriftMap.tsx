import { useEffect, useState } from 'react'
import { api } from '../api'
import type { DriftPattern, DriftHeatmap, DriftTrend, DriftSummary } from '../types'
import { LoadingSpinner, PatternTag } from '../components/Shared'
import { Map, TrendingUp } from 'lucide-react'
import clsx from 'clsx'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

const ALL_PATTERNS: DriftPattern[] = [
  'Fatigue', 'Overconfidence', 'Hurry', 'Quiet_Fear', 'Hoarding', 'Compliance_Theater',
]

const SEVERITY_COLORS = [
  'bg-gray-100',
  'bg-green-200',
  'bg-yellow-200',
  'bg-orange-300',
  'bg-red-400',
  'bg-red-600 text-white',
]

const PATTERN_DESCRIPTIONS: Record<DriftPattern, string> = {
  Fatigue: 'Sustained workload leading to reduced vigilance and mechanical compliance.',
  Overconfidence: 'Accumulated expertise bypassing safety protocols.',
  Hurry: 'Deadline pressure compressing validation into formality.',
  Quiet_Fear: 'Known issues going unreported because the cost of speaking up feels higher than silence.',
  Hoarding: 'Access and authority accumulating beyond role requirements.',
  Compliance_Theater: 'Audit scores are high but security outcomes are not changing.',
}

export default function DriftMap() {
  const [loading, setLoading] = useState(true)
  const [heatmap, setHeatmap] = useState<DriftHeatmap | null>(null)
  const [summary, setSummary] = useState<DriftSummary | null>(null)
  const [selected, setSelected] = useState<{ dept: string; pattern: DriftPattern } | null>(null)
  const [trend, setTrend] = useState<DriftTrend | null>(null)
  const [trendLoading, setTrendLoading] = useState(false)
  const [days, setDays] = useState(30)

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      try {
        const [hm, sm] = await Promise.all([
          api.getDriftHeatmap('enterprise', days),
          api.getDriftSummary(),
        ])
        if (!cancelled) { setHeatmap(hm); setSummary(sm) }
      } catch { /* empty state */ }
      finally { if (!cancelled) setLoading(false) }
    }
    load()
    return () => { cancelled = true }
  }, [days])

  useEffect(() => {
    if (!selected) { setTrend(null); return }
    let cancelled = false
    async function loadTrend() {
      setTrendLoading(true)
      try {
        const t = await api.getDriftTrend(selected!.pattern, days, selected!.dept)
        if (!cancelled) setTrend(t)
      } catch { /* ignore */ }
      finally { if (!cancelled) setTrendLoading(false) }
    }
    loadTrend()
    return () => { cancelled = true }
  }, [selected, days])

  if (loading) return <LoadingSpinner />

  const departments = heatmap?.departments || []
  const data = heatmap?.data || {}

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Drift Map</h1>
          <p className="text-sm text-gray-500 mt-1">Live organizational heatmap — drift severity by department</p>
        </div>
        <select value={days} onChange={e => setDays(Number(e.target.value))}
          className="text-sm border border-gray-300 rounded-lg px-3 py-1.5">
          <option value={7}>7 days</option>
          <option value={30}>30 days</option>
          <option value={60}>60 days</option>
          <option value={90}>90 days</option>
        </select>
      </div>

      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <SummaryCard label="Health Score" value={`${summary.health_score}/100`}
            color={summary.health_score >= 70 ? 'text-green-600' : summary.health_score >= 40 ? 'text-orange-600' : 'text-red-600'} />
          <SummaryCard label="Active Alerts" value={summary.total_active_alerts} />
          <SummaryCard label="Critical" value={summary.critical} color="text-red-600" />
          <SummaryCard label="Warnings" value={summary.warnings} color="text-orange-600" />
          <SummaryCard label="Active Patterns" value={Object.keys(summary.patterns).length} />
        </div>
      )}

      <div className="card overflow-x-auto">
        {departments.length === 0 ? (
          <div className="text-center py-12 text-gray-400">
            <Map size={48} className="mx-auto mb-3" />
            <p className="text-sm">No drift data yet. Ingest signals to populate the map.</p>
          </div>
        ) : (
          <>
            <table className="w-full">
              <thead>
                <tr>
                  <th className="text-left text-xs font-medium text-gray-500 pb-3 pr-4">Department</th>
                  {ALL_PATTERNS.map(p => (
                    <th key={p} className="text-center text-xs font-medium text-gray-500 pb-3 px-2">{p.replace(/_/g, ' ')}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {departments.map(dept => (
                  <tr key={dept} className="border-t border-gray-50">
                    <td className="py-2 pr-4 text-sm font-medium text-gray-700">{dept}</td>
                    {ALL_PATTERNS.map(pattern => {
                      const severity = Math.min(Math.max(Math.round(data[dept]?.[pattern] ?? 0), 0), 5)
                      const isSelected = selected?.dept === dept && selected?.pattern === pattern
                      return (
                        <td key={pattern} className="py-2 px-2">
                          <button
                            onClick={() => setSelected(isSelected ? null : { dept, pattern })}
                            className={clsx(
                              'w-full h-10 rounded-md transition-all flex items-center justify-center text-xs font-bold',
                              SEVERITY_COLORS[severity],
                              isSelected && 'ring-2 ring-drift-600 ring-offset-1',
                              severity > 0 && 'hover:ring-2 hover:ring-gray-300 cursor-pointer',
                            )}
                            title={`${dept} — ${pattern.replace(/_/g, ' ')}: severity ${severity}`}
                          >{severity > 0 ? severity : ''}</button>
                        </td>
                      )
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="mt-4 flex items-center gap-3 text-xs text-gray-500">
              <span>Severity:</span>
              {['None', '1', '2', '3', '4', '5'].map((label, i) => (
                <div key={i} className="flex items-center gap-1">
                  <div className={clsx('w-4 h-4 rounded', SEVERITY_COLORS[i])} /> <span>{label}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {selected && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="card border-l-4 border-l-drift-600">
            <div className="flex items-center gap-3 mb-3">
              <PatternTag pattern={selected.pattern} />
              <span className="text-sm font-medium text-gray-700">{selected.dept}</span>
              <span className="text-xs text-gray-500">Severity: {Math.round(data[selected.dept]?.[selected.pattern] ?? 0)}/5</span>
            </div>
            <p className="text-sm text-gray-700">{PATTERN_DESCRIPTIONS[selected.pattern]}</p>
            <div className="mt-3 text-xs text-gray-500">
              This is an organizational pattern observation — not an individual performance indicator.
            </div>
          </div>
          <div className="card">
            <div className="flex items-center gap-2 mb-3">
              <TrendingUp size={16} className="text-drift-600" />
              <h3 className="text-sm font-semibold text-gray-700">
                {selected.pattern.replace(/_/g, ' ')} Trend — {selected.dept}
              </h3>
            </div>
            {trendLoading ? (
              <div className="h-40 flex items-center justify-center text-gray-400 text-sm">Loading trend...</div>
            ) : trend && trend.data.length > 0 ? (
              <ResponsiveContainer width="100%" height={160}>
                <LineChart data={trend.data}>
                  <XAxis dataKey="date" tick={{ fontSize: 10 }} tickFormatter={d => new Date(d).toLocaleDateString()} />
                  <YAxis domain={[0, 5]} tick={{ fontSize: 10 }} />
                  <Tooltip labelFormatter={d => new Date(d as string).toLocaleString()} />
                  <Line type="monotone" dataKey="severity" stroke="#e03131" strokeWidth={2} dot={{ r: 3 }} />
                  <Line type="monotone" dataKey="confidence" stroke="#4263eb" strokeWidth={1} strokeDasharray="4 2" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-40 flex items-center justify-center text-gray-400 text-sm">No trend data yet.</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function SummaryCard({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="card">
      <div className="text-xs text-gray-500">{label}</div>
      <div className={clsx('text-xl font-bold', color || 'text-gray-900')}>{value}</div>
    </div>
  )
}
