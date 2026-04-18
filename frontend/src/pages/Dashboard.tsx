import { useEffect, useState } from 'react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
} from 'recharts'
import { useAuth } from '../auth'
import { AlertBadge, LoadingSpinner, PatternTag } from '../components/Shared'
import type {
  Alert,
  HealthScore,
  DriftPattern,
} from '../types'
import { api } from '../api'
import { Activity, Shield, AlertTriangle, TrendingDown } from 'lucide-react'

const PATTERN_COLORS: Record<DriftPattern, string> = {
  Fatigue: '#ff6b6b',
  Overconfidence: '#ff922b',
  Hurry: '#fcc419',
  Quiet_Fear: '#845ef7',
  Hoarding: '#339af0',
  Compliance_Theater: '#20c997',
}

// Demo data for first load / no-backend scenarios
const DEMO_HEALTH: HealthScore = {
  score: 72,
  trend: 'stable',
  active_patterns: 3,
  critical_alerts: 1,
  watch_alerts: 4,
  warning_alerts: 2,
}

const DEMO_ALERTS: Alert[] = [
  {
    alert_id: 'a1',
    drift_pattern: 'Fatigue',
    alert_level: 'Warning',
    severity: 3,
    confidence: 0.82,
    department: 'SOC Team',
    plain_language: 'Alert review cadence has dropped 40% over the past two weeks, suggesting cognitive fatigue under sustained volume.',
    nist_controls: ['AU-6', 'CA-7'],
    recommended_action: 'Rotate reviewer assignments and reduce alert volume through tuning.',
    created_at: new Date().toISOString(),
    acknowledged: false,
    resolved: false,
  },
  {
    alert_id: 'a2',
    drift_pattern: 'Compliance_Theater',
    alert_level: 'Critical',
    severity: 4,
    confidence: 0.91,
    department: 'Compliance',
    plain_language: 'Audit completion rates are 98% but breach indicators have increased 25%. Compliance activity is not producing security outcomes.',
    nist_controls: ['CA-7', 'AT-2'],
    recommended_action: 'Fundamental reassessment of whether compliance metrics measure actual security posture.',
    created_at: new Date(Date.now() - 3600000).toISOString(),
    acknowledged: false,
    resolved: false,
  },
  {
    alert_id: 'a3',
    drift_pattern: 'Overconfidence',
    alert_level: 'Watch',
    severity: 2,
    confidence: 0.74,
    department: 'Engineering',
    plain_language: 'Deployment approval bypass rate has increased from 5% to 18% this quarter.',
    nist_controls: ['AC-2'],
    recommended_action: 'Review exception patterns and reinforce approval workflow.',
    created_at: new Date(Date.now() - 7200000).toISOString(),
    acknowledged: true,
    resolved: false,
  },
]

const DEMO_TREND = Array.from({ length: 14 }, (_, i) => ({
  date: new Date(Date.now() - (13 - i) * 86400000).toISOString().split('T')[0],
  severity: Math.max(1, Math.min(5, 2.5 + Math.sin(i / 3) * 1.5 + (Math.random() - 0.5))),
  health: Math.max(40, Math.min(95, 72 + Math.sin(i / 4) * 12 + (Math.random() - 0.5) * 5)),
}))

const DEMO_PATTERN_DIST = [
  { pattern: 'Fatigue', count: 12 },
  { pattern: 'Overconfidence', count: 8 },
  { pattern: 'Hurry', count: 5 },
  { pattern: 'Quiet_Fear', count: 3 },
  { pattern: 'Hoarding', count: 2 },
  { pattern: 'Compliance_Theater', count: 7 },
]

export default function Dashboard() {
  const { role } = useAuth()
  const [health, setHealth] = useState<HealthScore>(DEMO_HEALTH)
  const [alerts, setAlerts] = useState<Alert[]>(DEMO_ALERTS)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      try {
        const [h, a] = await Promise.all([
          api.getHealthScore(),
          api.getAlerts({ limit: '5' }),
        ])
        if (!cancelled) {
          setHealth(h)
          setAlerts(a.alerts)
        }
      } catch {
        // Use demo data on failure (no backend running)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  if (loading) return <LoadingSpinner />

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">
            {role === 'compliance_officer'
              ? 'Compliance Dashboard'
              : role === 'ciso'
                ? 'CISO Dashboard'
                : role === 'ni_architect'
                  ? 'NI Calibration Dashboard'
                  : 'DriftGuard Dashboard'}
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Organizational drift detection — real-time overview
          </p>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <KPICard
          icon={<Activity size={20} />}
          label="Health Score"
          value={health.score}
          suffix="/100"
          trend={health.trend}
          color={health.score >= 70 ? 'text-green-600' : health.score >= 50 ? 'text-yellow-600' : 'text-red-600'}
        />
        <KPICard
          icon={<AlertTriangle size={20} />}
          label="Critical Alerts"
          value={health.critical_alerts}
          color="text-red-600"
        />
        <KPICard
          icon={<Shield size={20} />}
          label="Active Patterns"
          value={health.active_patterns}
          color="text-drift-700"
        />
        <KPICard
          icon={<TrendingDown size={20} />}
          label="Warning Alerts"
          value={health.warning_alerts}
          color="text-orange-500"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Trend chart */}
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-4">
            Health Score Trend (14 days)
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={DEMO_TREND}>
              <defs>
                <linearGradient id="healthGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#4263eb" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#4263eb" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="date" tick={{ fontSize: 11 }} tickFormatter={(v: string) => v.slice(5)} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
              <Tooltip />
              <Area
                type="monotone"
                dataKey="health"
                stroke="#4263eb"
                fill="url(#healthGrad)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Pattern distribution */}
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-4">
            Pattern Distribution
          </h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={DEMO_PATTERN_DIST} layout="vertical">
              <XAxis type="number" tick={{ fontSize: 11 }} />
              <YAxis
                dataKey="pattern"
                type="category"
                width={130}
                tick={{ fontSize: 11 }}
                tickFormatter={(v: string) => v.replace(/_/g, ' ')}
              />
              <Tooltip />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {DEMO_PATTERN_DIST.map((entry) => (
                  <Cell
                    key={entry.pattern}
                    fill={PATTERN_COLORS[entry.pattern as DriftPattern]}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent alerts */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-4">
          Recent Alerts
        </h3>
        <div className="divide-y divide-gray-100">
          {alerts.map((alert) => (
            <div key={alert.alert_id} className="py-3 flex items-start gap-4">
              <div className="pt-0.5">
                <AlertBadge level={alert.alert_level} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <PatternTag pattern={alert.drift_pattern} />
                  <span className="text-xs text-gray-500">{alert.department}</span>
                </div>
                <p className="text-sm text-gray-700 line-clamp-2">
                  {role === 'ciso' ? alert.plain_language : alert.plain_language}
                </p>
                {role === 'ciso' && (
                  <p className="text-xs text-gray-500 mt-1">
                    NIST: {alert.nist_controls.join(', ')} · Confidence: {(alert.confidence * 100).toFixed(0)}%
                  </p>
                )}
              </div>
              <div className="text-xs text-gray-400 whitespace-nowrap">
                {formatTimeAgo(alert.created_at)}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function KPICard({
  icon,
  label,
  value,
  suffix,
  trend,
  color,
}: {
  icon: React.ReactNode
  label: string
  value: number
  suffix?: string
  trend?: string
  color: string
}) {
  return (
    <div className="card flex items-center gap-4">
      <div className="p-2 rounded-lg bg-gray-50 text-gray-500">{icon}</div>
      <div>
        <p className="text-xs text-gray-500 font-medium">{label}</p>
        <p className={`text-2xl font-bold ${color}`}>
          {value}
          {suffix && <span className="text-sm font-normal text-gray-400">{suffix}</span>}
        </p>
        {trend && (
          <p className="text-xs text-gray-400 capitalize">{trend}</p>
        )}
      </div>
    </div>
  )
}

function formatTimeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}
