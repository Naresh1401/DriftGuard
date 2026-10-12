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
  PieChart,
  Pie,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  Legend,
} from 'recharts'
import { useAuth } from '../auth'
import type { Permission } from '../auth'
import { AlertBadge, EmptyState, LoadingSpinner, PatternTag } from '../components/Shared'
import RiskForecastCard from '../components/RiskForecastCard'
import LiveStream from '../components/LiveStream'
import type {
  Alert,
  CalibrationResponse,
  HealthScore,
  DriftPattern,
  GovernanceAction,
  UserRole,
  WeeklyReportData,
  NISTRiskData,
} from '../types'
import { api } from '../api'
import {
  Activity,
  Shield,
  AlertTriangle,
  TrendingDown,
  BookOpen,
  CheckCircle,
  Clock,
  Globe,
  Server,
  Eye,
  FileText,
  Zap,
  Lock,
} from 'lucide-react'
import clsx from 'clsx'

/* ── Shared data constants ─────────────────────────── */

const PATTERN_COLORS: Record<DriftPattern, string> = {
  Fatigue: '#ff6b6b',
  Overconfidence: '#ff922b',
  Hurry: '#fcc419',
  Quiet_Fear: '#845ef7',
  Hoarding: '#339af0',
  Compliance_Theater: '#20c997',
}

const NIST_LABELS: Record<string, string> = {
  'AC-2': 'Account Management',
  'AU-6': 'Audit Review',
  'IR-6': 'Incident Reporting',
  'CA-7': 'Continuous Monitoring',
  'AT-2': 'Awareness Training',
}

// Demo data is shown only when the dashboard API cannot be reached
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
    alert_id: 'a1', drift_pattern: 'Fatigue', alert_level: 'Warning', severity: 3, confidence: 0.82,
    department: 'SOC Team',
    plain_language: 'Alert review cadence has dropped 40% over the past two weeks, suggesting cognitive fatigue under sustained volume.',
    nist_controls: ['AU-6', 'CA-7'],
    recommended_action: 'Rotate reviewer assignments and reduce alert volume through tuning.',
    created_at: new Date().toISOString(), acknowledged: false, resolved: false,
  },
  {
    alert_id: 'a2', drift_pattern: 'Compliance_Theater', alert_level: 'Critical', severity: 4, confidence: 0.91,
    department: 'Compliance',
    plain_language: 'Audit completion rates are 98% but breach indicators have increased 25%. Compliance activity is not producing security outcomes.',
    nist_controls: ['CA-7', 'AT-2'],
    recommended_action: 'Fundamental reassessment of whether compliance metrics measure actual security posture.',
    created_at: new Date(Date.now() - 3600000).toISOString(), acknowledged: false, resolved: false,
  },
  {
    alert_id: 'a3', drift_pattern: 'Overconfidence', alert_level: 'Watch', severity: 2, confidence: 0.74,
    department: 'Engineering',
    plain_language: 'Deployment approval bypass rate has increased from 5% to 18% this quarter.',
    nist_controls: ['AC-2'],
    recommended_action: 'Review exception patterns and reinforce approval workflow.',
    created_at: new Date(Date.now() - 7200000).toISOString(), acknowledged: true, resolved: false,
  },
]

type NistRiskRow = { control: string; risk: number; label: string }

const DEMO_NIST_RISK: NistRiskRow[] = [
  { control: 'AU-6', risk: 4.1, label: 'Audit Review' },
  { control: 'CA-7', risk: 3.7, label: 'Continuous Monitoring' },
  { control: 'AC-2', risk: 3.2, label: 'Account Management' },
  { control: 'IR-6', risk: 2.8, label: 'Incident Reporting' },
  { control: 'AT-2', risk: 2.4, label: 'Awareness Training' },
]

type PatternCount = { pattern: string; count: number }

const ROLE_CONFIG: Record<UserRole, { title: string; subtitle: string; icon: React.ReactNode; accent: string }> = {
  admin: {
    title: 'Administrator Dashboard',
    subtitle: 'System health, user management, and full operational view',
    icon: <Server size={20} />,
    accent: 'border-l-purple-500',
  },
  ciso: {
    title: 'CISO Dashboard',
    subtitle: 'Technical risk analysis, NIST alignment, and executive readiness',
    icon: <Shield size={20} />,
    accent: 'border-l-red-500',
  },
  ni_architect: {
    title: 'NI Architect Dashboard',
    subtitle: 'Calibration pipeline, response quality, and approval workflow',
    icon: <BookOpen size={20} />,
    accent: 'border-l-indigo-500',
  },
  compliance_officer: {
    title: 'Compliance Dashboard',
    subtitle: 'Plain language drift reports and regulatory alignment',
    icon: <FileText size={20} />,
    accent: 'border-l-blue-500',
  },
  viewer: {
    title: 'DriftGuard Overview',
    subtitle: 'Read-only organizational health summary',
    icon: <Eye size={20} />,
    accent: 'border-l-gray-400',
  },
}

/* ── Data helpers ─────────────────────────────────── */

const loadSystemHealth = () => api.health()
const loadDomains = () => api.getDomains()
const loadPendingActions = () => api.getPendingActions()
const loadCalibration = () => api.getAllCalibrationResponses()
const loadRiskTrend = () => api.getRiskTrend('enterprise', 14)

// Loads once on mount: undefined while loading, null if the request failed
function useFetch<T>(load: () => Promise<T>): T | null | undefined {
  const [data, setData] = useState<T | null | undefined>(undefined)
  useEffect(() => {
    let cancelled = false
    load()
      .then((d) => { if (!cancelled) setData(d) })
      .catch(() => { if (!cancelled) setData(null) })
    return () => { cancelled = true }
  }, [load])
  return data
}

// Weekly report counts cover every alert; fall back to the recent alerts if it failed to load
function patternDistribution(weekly: WeeklyReportData | null, alerts: Alert[]): PatternCount[] {
  const counts: Record<string, number> = weekly
    ? weekly.pattern_distribution
    : alerts.reduce((acc: Record<string, number>, a) => { acc[a.drift_pattern] = (acc[a.drift_pattern] || 0) + 1; return acc }, {})
  return Object.entries(counts)
    .filter(([, count]) => count > 0)
    .map(([pattern, count]) => ({ pattern, count }))
    .sort((a, b) => b.count - a.count)
}

// null means the NIST report is unavailable; an empty list means nothing is at risk
function nistRiskRows(data: NISTRiskData | null, demo: boolean): NistRiskRow[] | null {
  if (!data) return demo ? DEMO_NIST_RISK : null
  return data.controls_at_risk
    .map((c) => ({
      control: c.control,
      // max_severity shares the chart's 1-5 scale; alert_count does not
      risk: Math.min(5, Math.max(0, c.risk_score ?? c.max_severity)),
      label: NIST_LABELS[c.control] ?? c.control,
    }))
    .sort((a, b) => b.risk - a.risk)
}

function patternColor(pattern: string): string {
  return PATTERN_COLORS[pattern as DriftPattern] ?? '#94a3b8'
}

/* ── Main Dashboard ─────────────────────────────── */

export default function Dashboard() {
  const { role, can } = useAuth()
  const [health, setHealth] = useState<HealthScore>(DEMO_HEALTH)
  const [alerts, setAlerts] = useState<Alert[]>(DEMO_ALERTS)
  const [weeklyData, setWeeklyData] = useState<WeeklyReportData | null>(null)
  const [nistData, setNistData] = useState<NISTRiskData | null>(null)
  const [loading, setLoading] = useState(true)
  const [demo, setDemo] = useState(false)

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      setDemo(false)
      try {
        const [h, a, weekly, nist] = await Promise.all([
          api.getHealthScore(),
          api.getAlerts({ limit: '5' }),
          api.getWeeklyReport().catch(() => null),
          api.getNISTRisk().catch(() => null),
        ])
        if (!cancelled) {
          setHealth(h)
          setAlerts(a.alerts)
          setWeeklyData(weekly)
          setNistData(nist)
        }
      } catch {
        if (!cancelled) setDemo(true)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  if (loading) return <LoadingSpinner />

  const cfg = ROLE_CONFIG[role]
  const patterns = patternDistribution(weeklyData, alerts)

  return (
    <div className="space-y-6">
      {/* Error banner */}
      {demo && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 text-sm text-yellow-800 flex items-center gap-2">
          <AlertTriangle size={16} className="shrink-0" /> Failed to load dashboard data. Showing demo data.
        </div>
      )}

      {/* Role header */}
      <div className={clsx('card border-l-4', cfg.accent)}>
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gray-50 text-gray-600">{cfg.icon}</div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">{cfg.title}</h1>
            <p className="text-sm text-gray-500 mt-0.5">{cfg.subtitle}</p>
          </div>
        </div>
      </div>

      {/* Role-specific sections */}
      {role === 'admin' && <AdminDashboard health={health} alerts={alerts} patterns={patterns} />}
      {role === 'ciso' && <CISODashboard health={health} alerts={alerts} patterns={patterns} nistData={nistData} demo={demo} />}
      {role === 'ni_architect' && <NIArchitectDashboard alerts={alerts} patterns={patterns} />}
      {role === 'compliance_officer' && <ComplianceOfficerDashboard health={health} alerts={alerts} patterns={patterns} weeklyData={weeklyData} demo={demo} />}
      {role === 'viewer' && <ViewerDashboard health={health} alerts={alerts} can={can} />}
    </div>
  )
}

/* ══════════════════════════════════════════════════════
   1. ADMINISTRATOR — Full system view + management
   ══════════════════════════════════════════════════════ */
function AdminDashboard({ health, alerts, patterns }: { health: HealthScore; alerts: Alert[]; patterns: PatternCount[] }) {
  const system = useFetch(loadSystemHealth)
  const domains = useFetch(loadDomains)
  const pending = useFetch(loadPendingActions)

  const pendingCount = (gate: GovernanceAction['gate_type']) =>
    pending ? pending.filter((p) => p.gate_type === gate).length : '–'

  return (
    <>
      {/* System KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        <KPICard icon={<Activity size={20} />} label="Health Score" value={health.score} suffix="/100"
          color={health.score >= 70 ? 'text-green-600' : 'text-red-600'} trend={health.trend} />
        <KPICard icon={<AlertTriangle size={20} />} label="Critical" value={health.critical_alerts} color="text-red-600" />
        <KPICard icon={<TrendingDown size={20} />} label="Warnings" value={health.warning_alerts} color="text-orange-500" />
        <KPICard icon={<Shield size={20} />} label="Active Patterns" value={health.active_patterns} color="text-drift-700" />
        <KPICard icon={<Eye size={20} />} label="Watch" value={health.watch_alerts} color="text-yellow-600" />
      </div>

      {/* Predictive risk forecast + Live stream (v2) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RiskForecastCard domain="enterprise" horizonDays={30} />
        <LiveStream />
      </div>

      {/* System status row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
            <Server size={16} className="text-purple-500" /> System Status
          </h3>
          <div className="space-y-3">
            {system === undefined ? (
              <SystemRow label="API Server" status="unknown" detail="Checking…" />
            ) : system === null ? (
              <SystemRow label="API Server" status="offline" detail="Unreachable" />
            ) : (
              <>
                <SystemRow label="API Server" status="online" detail="Responding" />
                <SystemRow label="Database" status={system.database === 'connected' ? 'online' : 'offline'}
                  detail={system.database === 'connected' ? 'Connected' : 'Disconnected'} />
                <SystemRow label="Vector Database" status={system.vector_db === 'connected' ? 'online' : 'warning'}
                  detail={system.vector_db === 'connected' ? 'Connected' : 'Not connected'} />
              </>
            )}
            <SystemRow label="Domain Adapters"
              status={domains === undefined ? 'unknown' : domains === null ? 'offline' : domains.length ? 'online' : 'warning'}
              detail={domains === undefined ? 'Checking…' : domains === null ? 'Unavailable' : `${domains.length} domain${domains.length === 1 ? '' : 's'} loaded`} />
            <SystemRow label="Governance Queue"
              status={pending === undefined ? 'unknown' : pending === null ? 'offline' : pending.length ? 'warning' : 'online'}
              detail={pending === undefined ? 'Checking…' : pending === null ? 'Unavailable' : pending.length ? `${pending.length} pending approval${pending.length === 1 ? '' : 's'}` : 'Nothing pending'} />
          </div>
        </div>

        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
            <Globe size={16} className="text-green-500" /> Domain Coverage
          </h3>
          {domains === undefined ? (
            <LoadingSpinner />
          ) : domains === null ? (
            <EmptyState message="Domain list is unavailable." />
          ) : domains.length === 0 ? (
            <EmptyState message="No domains loaded." />
          ) : (
            <div className="space-y-2">
              {domains.map((d) => (
                <div key={d.domain} className="flex items-center justify-between py-1">
                  <span className="text-sm text-gray-700">{d.display_name || d.domain}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-400">{d.signal_count} signals</span>
                    <SensitivityBadge level={d.sensitivity} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Charts + alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RiskTrendChart />
        <PatternDistChart data={patterns} />
      </div>

      <RecentAlerts alerts={alerts} showNIST showActions />

      {/* Governance overview */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
          <Shield size={16} className="text-yellow-500" /> Pending Governance Actions
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <MiniStat label="NI Response Approvals" value={pendingCount('ni_response')} icon={<BookOpen size={16} />} color="text-purple-600" />
          <MiniStat label="NIST Validations" value={pendingCount('nist_mapping')} icon={<Shield size={16} />} color="text-blue-600" />
          <MiniStat label="Critical Alert Reviews" value={pendingCount('critical_alert')} icon={<AlertTriangle size={16} />} color="text-red-600" />
        </div>
      </div>
    </>
  )
}

/* ══════════════════════════════════════════════════════
   2. CISO — Risk-centric with NIST + board readiness
   ══════════════════════════════════════════════════════ */
function CISODashboard({ health, alerts, patterns, nistData, demo }: {
  health: HealthScore; alerts: Alert[]; patterns: PatternCount[]; nistData: NISTRiskData | null; demo: boolean
}) {
  const nistRisk = nistRiskRows(nistData, demo)
  const highest = nistRisk?.[0]
  const nistControlsAtRisk = nistRisk ? nistRisk.filter((c) => c.risk >= 3).length : 0
  const boardReadiness = Math.max(0, Math.min(100, Math.round(health.score * 0.8 + (health.active_patterns === 0 ? 20 : 0))))

  return (
    <>
      {/* Risk KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KPICard icon={<Activity size={20} />} label="Risk Score" value={Math.round((100 - health.score) * 10) / 10} suffix="/100"
          color={health.score >= 70 ? 'text-green-600' : 'text-red-600'} />
        <KPICard icon={<AlertTriangle size={20} />} label="Critical Alerts" value={health.critical_alerts} color="text-red-600" />
        <KPICard icon={<Shield size={20} />} label="NIST Controls at Risk" value={nistControlsAtRisk} color="text-orange-500" />
        <KPICard icon={<Zap size={20} />} label="Board Readiness" value={boardReadiness} suffix="%" color="text-drift-700" />
      </div>

      {/* Predictive breach forecast + live SSE stream */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RiskForecastCard domain="enterprise" horizonDays={30} />
        <LiveStream />
      </div>

      {/* NIST radar + risk table side by side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-4 flex items-center gap-2">
            <Shield size={16} className="text-red-500" /> NIST SP 800-53 Risk Radar
          </h3>
          {nistRisk === null ? (
            <EmptyState message="NIST risk data is unavailable." />
          ) : nistRisk.length === 0 ? (
            <EmptyState message="No NIST controls are at risk." />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <RadarChart data={nistRisk}>
                <PolarGrid />
                <PolarAngleAxis dataKey="control" tick={{ fontSize: 12 }} />
                <PolarRadiusAxis domain={[0, 5]} tick={{ fontSize: 10 }} />
                <Radar name="Risk" dataKey="risk" stroke="#e03131" fill="#e03131" fillOpacity={0.2} />
              </RadarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-4">Control Risk Assessment</h3>
          {nistRisk === null ? (
            <EmptyState message="NIST risk data is unavailable." />
          ) : nistRisk.length === 0 ? (
            <EmptyState message="No NIST controls are at risk." />
          ) : (
            <div className="divide-y divide-gray-100">
              {nistRisk.map((ctrl) => (
                <div key={ctrl.control} className="py-2.5 flex items-center gap-3">
                  <span className="font-mono text-sm font-bold text-drift-700 w-14">{ctrl.control}</span>
                  <span className="text-sm text-gray-600 flex-1 min-w-0 truncate">{ctrl.label}</span>
                  <div className="w-20 sm:w-32 bg-gray-100 rounded-full h-2 shrink-0">
                    <div
                      className={clsx('h-2 rounded-full',
                        ctrl.risk >= 4 ? 'bg-red-500' : ctrl.risk >= 3 ? 'bg-orange-400' : 'bg-green-500'
                      )}
                      style={{ width: `${(ctrl.risk / 5) * 100}%` }}
                    />
                  </div>
                  <span className={clsx('text-sm font-bold w-8 text-right',
                    ctrl.risk >= 4 ? 'text-red-600' : ctrl.risk >= 3 ? 'text-orange-500' : 'text-green-600'
                  )}>{ctrl.risk.toFixed(1)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Trend + threat pattern */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RiskTrendChart />
        <PatternPieChart patterns={patterns} />
      </div>

      {/* Executive summary card */}
      <div className="card border-l-4 border-l-red-500">
        <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
          <FileText size={16} className="text-red-500" /> Executive Risk Summary
        </h3>
        <div className="text-sm text-gray-600 space-y-2">
          <p>
            <strong>Highest risk:</strong>{' '}
            {nistRisk === null
              ? 'NIST risk data is unavailable'
              : highest
                ? `${highest.control} (${highest.label}) at ${highest.risk.toFixed(1)}/5`
                : 'No NIST controls currently at risk'}.
            {health.active_patterns > 0 ? ` ${health.active_patterns} active drift pattern${health.active_patterns > 1 ? 's' : ''} detected.` : ' No active drift patterns.'}
          </p>
          <p>
            <strong>Active alerts:</strong> {health.critical_alerts} critical, {health.warning_alerts} warnings, {health.watch_alerts} watch items.
            {health.critical_alerts > 0 ? ' Immediate attention required on critical alerts.' : ' No critical items require immediate attention.'}
          </p>
          <p>
            <strong>Board readiness:</strong> {boardReadiness}% — {boardReadiness >= 80 ? 'ready for board presentation' : boardReadiness >= 60 ? 'some findings require remediation plans before board presentation' : 'significant gaps require remediation before board presentation'}.
          </p>
        </div>
      </div>

      <RecentAlerts alerts={alerts} showNIST showActions />
    </>
  )
}

/* ══════════════════════════════════════════════════════
   3. NI ARCHITECT — Calibration pipeline focus
   ══════════════════════════════════════════════════════ */
function NIArchitectDashboard({ alerts, patterns }: { alerts: Alert[]; patterns: PatternCount[] }) {
  const responses = useFetch(loadCalibration)
  const list = responses ?? []
  const countByStatus = (status: CalibrationResponse['approval_status']) =>
    list.filter((r) => r.approval_status === status).length

  const approved = countByStatus('approved')
  const pending = countByStatus('pending')
  const approvalRate = list.length ? Math.round((approved / list.length) * 100) : 0

  const coverage = (Object.keys(PATTERN_COLORS) as DriftPattern[]).map((pattern) => {
    const forPattern = list.filter((r) => r.drift_pattern === pattern)
    return {
      pattern,
      total: forPattern.length,
      approved: forPattern.filter((r) => r.approval_status === 'approved').length,
      pending: forPattern.filter((r) => r.approval_status === 'pending').length,
    }
  })

  return (
    <>
      {responses === null && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 text-sm text-yellow-800 flex items-center gap-2">
          <AlertTriangle size={16} className="shrink-0" /> Calibration data is unavailable.
        </div>
      )}

      {/* Calibration KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KPICard icon={<BookOpen size={20} />} label="Total Responses" value={list.length} color="text-indigo-600" />
        <KPICard icon={<Clock size={20} />} label="Pending Approval" value={pending} color="text-yellow-600" />
        <KPICard icon={<CheckCircle size={20} />} label="Approved" value={approved} color="text-green-600" />
        <KPICard icon={<Zap size={20} />} label="Approval Rate" value={approvalRate} suffix="%" color="text-drift-700" />
      </div>

      {/* Calibration pipeline */}
      <div className="card border-l-4 border-l-indigo-500">
        <h3 className="text-sm font-semibold text-gray-700 mb-4 flex items-center gap-2">
          <BookOpen size={16} className="text-indigo-500" /> NI Response Pipeline
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {([
            { stage: 'Pending', count: pending, color: 'bg-yellow-50 text-yellow-700 border-yellow-200' },
            { stage: 'Revision Requested', count: countByStatus('revision_requested'), color: 'bg-gray-100 text-gray-700 border-gray-200' },
            { stage: 'Approved', count: approved, color: 'bg-green-50 text-green-700 border-green-200' },
            { stage: 'Rejected', count: countByStatus('rejected'), color: 'bg-red-50 text-red-700 border-red-200' },
          ]).map((s) => (
            <div key={s.stage} className={clsx('rounded-lg border p-3 text-center', s.color)}>
              <p className="text-2xl font-bold">{s.count}</p>
              <p className="text-xs font-medium mt-0.5">{s.stage}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Pattern coverage matrix */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-4">Response Coverage by Pattern</h3>
        <div className="space-y-2">
          {coverage.map((p) => (
            <div key={p.pattern} className="flex items-center gap-3 py-1.5">
              <PatternTag pattern={p.pattern} />
              <div className="flex-1">
                <div className="flex items-center gap-1">
                  <div className="flex-1 bg-gray-100 rounded-full h-2.5">
                    <div className="bg-green-500 h-2.5 rounded-full"
                      style={{ width: `${(p.approved / Math.max(p.total, 1)) * 100}%` }} />
                  </div>
                </div>
              </div>
              <span className="text-xs text-gray-500 w-32 text-right">
                {p.approved}/{p.total} approved
                {p.pending > 0 && <span className="text-yellow-600 ml-1">({p.pending} pending)</span>}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RiskTrendChart />
        <PatternDistChart data={patterns} />
      </div>

      <RecentAlerts alerts={alerts} showNIST={false} showActions={false} />
    </>
  )
}

/* ══════════════════════════════════════════════════════
   4. COMPLIANCE OFFICER — Plain language, regulatory
   ══════════════════════════════════════════════════════ */
function ComplianceOfficerDashboard({ health, alerts, patterns, weeklyData, demo }: {
  health: HealthScore; alerts: Alert[]; patterns: PatternCount[]; weeklyData: WeeklyReportData | null; demo: boolean
}) {
  const resolvedThisWeek = weeklyData?.resolved_this_week ?? 0
  const complianceScore = health.score >= 80 ? Math.round(health.score * 0.9) : Math.round(health.score * 0.85)
  const findings = alerts
    .filter((a) => !a.resolved)
    .sort((a, b) => b.severity - a.severity)
    .slice(0, 3)
  const controlsAtRisk: string[] | null = weeklyData
    ? [...weeklyData.nist_controls_at_risk].sort()
    : demo
      ? [...new Set(alerts.flatMap((a) => a.nist_controls))].sort()
      : null
  const activePatterns = health.active_patterns

  return (
    <>
      {/* Compliance-focused KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KPICard icon={<Activity size={20} />} label="Health Score" value={health.score} suffix="/100"
          trend={health.trend}
          color={health.score >= 70 ? 'text-green-600' : health.score >= 50 ? 'text-yellow-600' : 'text-red-600'} />
        <KPICard icon={<AlertTriangle size={20} />} label="Alerts Requiring Action" value={health.critical_alerts + health.warning_alerts} color="text-red-600" />
        <KPICard icon={<CheckCircle size={20} />} label="Resolved This Week" value={resolvedThisWeek} color="text-green-600" />
        <KPICard icon={<Shield size={20} />} label="Compliance Score" value={complianceScore} suffix="%" color="text-drift-700" />
      </div>

      {/* Plain language summary */}
      <div className="card border-l-4 border-l-blue-500">
        <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
          <FileText size={16} className="text-blue-500" /> Weekly Compliance Summary
        </h3>
        <div className="text-sm text-gray-600 space-y-3">
          <p>
            {activePatterns === 0
              ? 'No organizational drift patterns are active this week.'
              : `${activePatterns} organizational drift pattern${activePatterns === 1 ? ' is' : 's are'} active this week. None require individual investigation — all patterns are department-level behavioral indicators.`}
          </p>
          <div className="bg-blue-50 rounded-lg p-3 space-y-2">
            <p className="font-medium text-blue-800">Key Findings (Plain Language):</p>
            {findings.length === 0 ? (
              <p className="text-blue-700">No open findings.</p>
            ) : (
              <ul className="list-disc list-inside space-y-1 text-blue-700">
                {findings.map((a) => <li key={a.alert_id}>{a.plain_language}</li>)}
              </ul>
            )}
          </div>
          <p className="text-xs text-gray-500 italic">
            All findings are organizational patterns. No individual employees are identified.
          </p>
        </div>
      </div>

      {/* NIST controls at risk */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">NIST SP 800-53 Controls at Risk</h3>
        {controlsAtRisk === null ? (
          <p className="text-sm text-gray-500">NIST control data is unavailable.</p>
        ) : controlsAtRisk.length === 0 ? (
          <p className="text-sm text-gray-500">No NIST controls are currently at risk.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {controlsAtRisk.map((c) => (
              <span key={c} className="inline-flex items-center gap-2 px-2.5 py-1 rounded-lg bg-orange-50 border border-orange-200 text-sm">
                <span className="font-mono font-bold text-orange-700">{c}</span>
                <span className="text-gray-600">{NIST_LABELS[c] ?? ''}</span>
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RiskTrendChart />
        <PatternDistChart data={patterns} />
      </div>

      <RecentAlerts alerts={alerts} showNIST={false} showActions />
    </>
  )
}

/* ══════════════════════════════════════════════════════
   5. VIEWER — Read-only simplified view
   ══════════════════════════════════════════════════════ */
function ViewerDashboard({ health, alerts }: { health: HealthScore; alerts: Alert[]; can: (p: Permission) => boolean }) {
  return (
    <>
      {/* Simplified KPIs */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <KPICard icon={<Activity size={20} />} label="Health Score" value={health.score} suffix="/100"
          trend={health.trend}
          color={health.score >= 70 ? 'text-green-600' : health.score >= 50 ? 'text-yellow-600' : 'text-red-600'} />
        <KPICard icon={<Shield size={20} />} label="Active Patterns" value={health.active_patterns} color="text-drift-700" />
        <KPICard icon={<AlertTriangle size={20} />} label="Open Alerts" value={health.critical_alerts + health.warning_alerts + health.watch_alerts} color="text-orange-500" />
      </div>

      {/* Read-only notice */}
      <div className="bg-gray-50 rounded-lg p-4 flex items-start gap-3 border border-gray-200">
        <Lock size={18} className="text-gray-400 mt-0.5 shrink-0" />
        <div>
          <p className="text-sm font-medium text-gray-700">Read-Only Access</p>
          <p className="text-xs text-gray-500 mt-0.5">
            You have viewer access. To acknowledge alerts, manage calibration, or access governance,
            contact your administrator for a role upgrade.
          </p>
        </div>
      </div>

      {/* Trend chart only */}
      <RiskTrendChart />

      {/* Simplified alert list */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-4">Recent Alerts</h3>
        {alerts.length === 0 ? (
          <EmptyState message="No recent alerts." />
        ) : (
          <div className="divide-y divide-gray-100">
            {alerts.map((alert) => (
              <div key={alert.alert_id} className="py-3 flex items-start gap-4">
                <div className="pt-0.5"><AlertBadge level={alert.alert_level} /></div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <PatternTag pattern={alert.drift_pattern} />
                    <span className="text-xs text-gray-500">{alert.department}</span>
                  </div>
                  <p className="text-sm text-gray-700 line-clamp-2">{alert.plain_language}</p>
                </div>
                <div className="text-xs text-gray-400 whitespace-nowrap">{formatTimeAgo(alert.created_at)}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  )
}

/* ── Shared sub-components ────────────────────────── */

function RiskTrendChart() {
  const data = useFetch(loadRiskTrend)

  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-gray-700 mb-4">Breach Risk Trend (14 days)</h3>
      {data === undefined ? (
        <LoadingSpinner />
      ) : data === null ? (
        <EmptyState message="Trend data is unavailable." />
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={data.trend}>
            <defs>
              <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#4263eb" stopOpacity={0.2} />
                <stop offset="95%" stopColor="#4263eb" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="date" tick={{ fontSize: 11 }} tickFormatter={(v: string) => v.slice(5)} />
            <YAxis domain={[0, 'auto']} tick={{ fontSize: 11 }} unit="%" />
            <Tooltip formatter={(v) => [`${v}%`, 'Breach probability']} />
            <Area type="monotone" dataKey="breach_probability_pct" stroke="#4263eb" fill="url(#riskGrad)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}

function PatternDistChart({ data }: { data: PatternCount[] }) {
  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-gray-700 mb-4">Pattern Distribution</h3>
      {data.length === 0 ? (
        <EmptyState message="No drift patterns detected." />
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={data} layout="vertical">
            <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11 }} />
            <YAxis dataKey="pattern" type="category" width={100} tick={{ fontSize: 11 }}
              tickFormatter={(v: string) => v.replace(/_/g, ' ')} />
            <Tooltip />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
              {data.map((entry) => (
                <Cell key={entry.pattern} fill={patternColor(entry.pattern)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}

function PatternPieChart({ patterns }: { patterns: PatternCount[] }) {
  const slices = patterns.map((p) => ({ name: p.pattern.replace(/_/g, ' '), value: p.count, color: patternColor(p.pattern) }))

  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-gray-700 mb-4">Threat Pattern Distribution</h3>
      {slices.length === 0 ? (
        <EmptyState message="No drift patterns detected." />
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie data={slices} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={85} paddingAngle={2}>
              {slices.map((s) => <Cell key={s.name} fill={s.color} />)}
            </Pie>
            <Legend wrapperStyle={{ fontSize: 11 }} />
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}

function RecentAlerts({ alerts, showNIST, showActions }: { alerts: Alert[]; showNIST: boolean; showActions: boolean }) {
  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-gray-700 mb-4">Recent Alerts</h3>
      {alerts.length === 0 ? (
        <EmptyState message="No recent alerts." />
      ) : (
        <div className="divide-y divide-gray-100">
          {alerts.map((alert) => (
            <div key={alert.alert_id} className="py-3 flex items-start gap-4">
              <div className="pt-0.5"><AlertBadge level={alert.alert_level} /></div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <PatternTag pattern={alert.drift_pattern} />
                  <span className="text-xs text-gray-500">{alert.department}</span>
                  {showActions && (
                    <span className="text-xs text-gray-400">
                      Severity {alert.severity}/5 · {(alert.confidence * 100).toFixed(0)}%
                    </span>
                  )}
                </div>
                <p className="text-sm text-gray-700 line-clamp-2">{alert.plain_language}</p>
                {showNIST && (
                  <p className="text-xs text-gray-500 mt-1">
                    NIST: {alert.nist_controls.join(', ') || 'none'} · {alert.recommended_action}
                  </p>
                )}
              </div>
              <div className="text-xs text-gray-400 whitespace-nowrap">{formatTimeAgo(alert.created_at)}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function KPICard({ icon, label, value, suffix, trend, color }: {
  icon: React.ReactNode; label: string; value: number; suffix?: string; trend?: string; color: string
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
        {trend && <p className="text-xs text-gray-400 capitalize">{trend}</p>}
      </div>
    </div>
  )
}

function MiniStat({ label, value, icon, color }: { label: string; value: number | string; icon: React.ReactNode; color: string }) {
  return (
    <div className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
      <div className={clsx('p-1.5 rounded', color)}>{icon}</div>
      <div>
        <p className="text-lg font-bold text-gray-900">{value}</p>
        <p className="text-xs text-gray-500">{label}</p>
      </div>
    </div>
  )
}

function SystemRow({ label, status, detail }: { label: string; status: 'online' | 'warning' | 'offline' | 'unknown'; detail: string }) {
  return (
    <div className="flex items-center gap-3 py-1.5">
      <span className={clsx('w-2 h-2 rounded-full shrink-0',
        status === 'online' && 'bg-green-500',
        status === 'warning' && 'bg-yellow-500',
        status === 'offline' && 'bg-red-500',
        status === 'unknown' && 'bg-gray-300',
      )} />
      <span className="text-sm text-gray-700 flex-1">{label}</span>
      <span className="text-xs text-gray-400">{detail}</span>
    </div>
  )
}

function SensitivityBadge({ level }: { level: string }) {
  return (
    <span className={clsx('text-xs px-1.5 py-0.5 rounded font-medium',
      level === 'conservative' && 'bg-blue-100 text-blue-700',
      level === 'balanced' && 'bg-green-100 text-green-700',
      level === 'aggressive' && 'bg-orange-100 text-orange-700',
    )}>{level}</span>
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
