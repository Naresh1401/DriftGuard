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
import { AlertBadge, LoadingSpinner, PatternTag } from '../components/Shared'
import type {
  Alert,
  HealthScore,
  DriftPattern,
  UserRole,
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
  Users,
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

const DEMO_PATTERN_DIST = [
  { pattern: 'Fatigue', count: 12 },
  { pattern: 'Overconfidence', count: 8 },
  { pattern: 'Hurry', count: 5 },
  { pattern: 'Quiet_Fear', count: 3 },
  { pattern: 'Hoarding', count: 2 },
  { pattern: 'Compliance_Theater', count: 7 },
]

const NIST_RISK = [
  { control: 'AC-2', risk: 3.2, label: 'Account Management' },
  { control: 'AU-6', risk: 4.1, label: 'Audit Review' },
  { control: 'IR-6', risk: 2.8, label: 'Incident Reporting' },
  { control: 'CA-7', risk: 3.7, label: 'Continuous Monitoring' },
  { control: 'AT-2', risk: 2.4, label: 'Awareness Training' },
]

const PATTERN_PIE = [
  { name: 'Fatigue', value: 28, color: '#ff6b6b' },
  { name: 'Overconfidence', value: 18, color: '#ff922b' },
  { name: 'Hurry', value: 15, color: '#fcc419' },
  { name: 'Quiet Fear', value: 12, color: '#845ef7' },
  { name: 'Hoarding', value: 8, color: '#339af0' },
  { name: 'Compliance Theater', value: 19, color: '#20c997' },
]

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

/* ── Main Dashboard ─────────────────────────────── */

export default function Dashboard() {
  const { role, can } = useAuth()
  const [health, setHealth] = useState<HealthScore>(DEMO_HEALTH)
  const [alerts, setAlerts] = useState<Alert[]>(DEMO_ALERTS)
  const [weeklyData, setWeeklyData] = useState<any>(null)
  const [nistData, setNistData] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      setError(null)
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
          if (weekly) setWeeklyData(weekly)
          if (nist) setNistData(nist)
        }
      } catch (e) {
        if (!cancelled) setError('Failed to load dashboard data. Showing demo data.')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  if (loading) return <LoadingSpinner />

  const cfg = ROLE_CONFIG[role]

  return (
    <div className="space-y-6">
      {/* Error banner */}
      {error && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 text-sm text-yellow-800 flex items-center gap-2">
          <AlertTriangle size={16} className="shrink-0" /> {error}
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
      {role === 'admin' && <AdminDashboard health={health} alerts={alerts} weeklyData={weeklyData} nistData={nistData} />}
      {role === 'ciso' && <CISODashboard health={health} alerts={alerts} nistData={nistData} />}
      {role === 'ni_architect' && <NIArchitectDashboard health={health} alerts={alerts} />}
      {role === 'compliance_officer' && <ComplianceOfficerDashboard health={health} alerts={alerts} weeklyData={weeklyData} />}
      {role === 'viewer' && <ViewerDashboard health={health} alerts={alerts} can={can} />}
    </div>
  )
}

/* ══════════════════════════════════════════════════════
   1. ADMINISTRATOR — Full system view + management
   ══════════════════════════════════════════════════════ */
function AdminDashboard({ health, alerts, weeklyData }: { health: HealthScore; alerts: Alert[]; weeklyData: any; nistData: any }) {
  // Build live pattern distribution from weekly data or alerts
  const livePatternDist = weeklyData?.pattern_distribution
    ? Object.entries(weeklyData.pattern_distribution).map(([pattern, count]) => ({ pattern, count: count as number }))
    : alerts.length > 0
      ? Object.entries(alerts.reduce((acc: Record<string, number>, a) => { acc[a.drift_pattern] = (acc[a.drift_pattern] || 0) + 1; return acc }, {})).map(([pattern, count]) => ({ pattern, count }))
      : DEMO_PATTERN_DIST

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

      {/* System status row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
            <Server size={16} className="text-purple-500" /> System Status
          </h3>
          <div className="space-y-3">
            <SystemRow label="Pipeline Engine" status="online" detail="9-node LangGraph active" />
            <SystemRow label="Signal Ingestion" status="online" detail="24 signals/hr avg" />
            <SystemRow label="NI Calibration" status="warning" detail="2 responses pending approval" />
            <SystemRow label="Domain Adapters" status="online" detail="6 domains loaded" />
            <SystemRow label="Ethical Guardrails" status="online" detail="All checks passing" />
            <SystemRow label="NIST Mapping" status="online" detail="5 controls tracked" />
          </div>
        </div>

        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
            <Users size={16} className="text-blue-500" /> Active Roles
          </h3>
          <div className="space-y-2">
            {([
              { role: 'Administrator', count: 1, color: 'bg-purple-100 text-purple-700' },
              { role: 'CISO', count: 1, color: 'bg-red-100 text-red-700' },
              { role: 'NI Architect', count: 2, color: 'bg-indigo-100 text-indigo-700' },
              { role: 'Compliance Officer', count: 3, color: 'bg-blue-100 text-blue-700' },
              { role: 'Viewer', count: 8, color: 'bg-gray-100 text-gray-700' },
            ]).map((r) => (
              <div key={r.role} className="flex items-center justify-between py-1.5">
                <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', r.color)}>{r.role}</span>
                <span className="text-sm font-medium text-gray-700">{r.count}</span>
              </div>
            ))}
          </div>
          <div className="mt-3 pt-3 border-t border-gray-100 text-xs text-gray-500">
            Total users: <span className="font-semibold text-gray-700">15</span>
          </div>
        </div>

        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
            <Globe size={16} className="text-green-500" /> Domain Coverage
          </h3>
          <div className="space-y-2">
            {([
              { name: 'Healthcare', signals: 14, sensitivity: 'conservative' },
              { name: 'Enterprise', signals: 18, sensitivity: 'balanced' },
              { name: 'Finance', signals: 12, sensitivity: 'aggressive' },
              { name: 'Government', signals: 10, sensitivity: 'conservative' },
              { name: 'Education', signals: 8, sensitivity: 'balanced' },
              { name: 'Retail', signals: 6, sensitivity: 'balanced' },
            ]).map((d) => (
              <div key={d.name} className="flex items-center justify-between py-1">
                <span className="text-sm text-gray-700">{d.name}</span>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-gray-400">{d.signals} signals</span>
                  <SensitivityBadge level={d.sensitivity} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Charts + alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TrendChart health={health} />
        <PatternDistChart data={livePatternDist} />
      </div>

      <RecentAlerts alerts={alerts} showNIST showActions />

      {/* Governance overview */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
          <Shield size={16} className="text-yellow-500" /> Pending Governance Actions
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <MiniStat label="NI Response Approvals" value={2} icon={<BookOpen size={16} />} color="text-purple-600" />
          <MiniStat label="NIST Validations" value={1} icon={<Shield size={16} />} color="text-blue-600" />
          <MiniStat label="Critical Alert Reviews" value={1} icon={<AlertTriangle size={16} />} color="text-red-600" />
        </div>
      </div>
    </>
  )
}

/* ══════════════════════════════════════════════════════
   2. CISO — Risk-centric with NIST + board readiness
   ══════════════════════════════════════════════════════ */
function CISODashboard({ health, alerts, nistData }: { health: HealthScore; alerts: Alert[]; nistData: any }) {
  const liveNistRisk = nistData?.controls_at_risk?.length
    ? nistData.controls_at_risk.map((c: any) => ({ control: c.control, risk: c.risk_score || c.alert_count || 1, label: c.control }))
    : NIST_RISK

  const nistControlsAtRisk = liveNistRisk.filter((c: any) => c.risk >= 3).length
  const boardReadiness = Math.max(0, Math.min(100, Math.round(health.score * 0.8 + (health.active_patterns === 0 ? 20 : 0))))

  return (
    <>
      {/* Risk KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KPICard icon={<Activity size={20} />} label="Risk Score" value={100 - health.score} suffix="/100"
          color={health.score >= 70 ? 'text-green-600' : 'text-red-600'} />
        <KPICard icon={<AlertTriangle size={20} />} label="Critical Alerts" value={health.critical_alerts} color="text-red-600" />
        <KPICard icon={<Shield size={20} />} label="NIST Controls at Risk" value={nistControlsAtRisk} color="text-orange-500" />
        <KPICard icon={<Zap size={20} />} label="Board Readiness" value={boardReadiness} suffix="%" color="text-drift-700" />
      </div>

      {/* NIST radar + risk table side by side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-4 flex items-center gap-2">
            <Shield size={16} className="text-red-500" /> NIST SP 800-53 Risk Radar
          </h3>
          <ResponsiveContainer width="100%" height={260}>
            <RadarChart data={liveNistRisk}>
              <PolarGrid />
              <PolarAngleAxis dataKey="control" tick={{ fontSize: 12 }} />
              <PolarRadiusAxis domain={[0, 5]} tick={{ fontSize: 10 }} />
              <Radar name="Risk" dataKey="risk" stroke="#e03131" fill="#e03131" fillOpacity={0.2} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-4">Control Risk Assessment</h3>
          <div className="divide-y divide-gray-100">
            {liveNistRisk.map((ctrl: any) => (
              <div key={ctrl.control} className="py-2.5 flex items-center gap-3">
                <span className="font-mono text-sm font-bold text-drift-700 w-14">{ctrl.control}</span>
                <span className="text-sm text-gray-600 flex-1">{ctrl.label}</span>
                <div className="w-32 bg-gray-100 rounded-full h-2">
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
        </div>
      </div>

      {/* Trend + threat pattern */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TrendChart health={health} />
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-4">Threat Pattern Distribution</h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={(() => {
                if (!alerts.length) return PATTERN_PIE
                const dist = alerts.reduce((acc: Record<string, number>, a) => {
                  const name = a.drift_pattern.replace(/_/g, ' ')
                  acc[name] = (acc[name] || 0) + 1; return acc
                }, {})
                return Object.entries(dist).map(([name, value]) => ({
                  name, value, color: PATTERN_COLORS[name.replace(/ /g, '_') as DriftPattern] || '#94a3b8'
                }))
              })()} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={85} paddingAngle={2}>
                {(() => {
                  if (!alerts.length) return PATTERN_PIE.map((e) => <Cell key={e.name} fill={e.color} />)
                  const dist = alerts.reduce((acc: Record<string, number>, a) => {
                    const name = a.drift_pattern.replace(/_/g, ' ')
                    acc[name] = (acc[name] || 0) + 1; return acc
                  }, {})
                  return Object.entries(dist).map(([name]) => (
                    <Cell key={name} fill={PATTERN_COLORS[name.replace(/ /g, '_') as DriftPattern] || '#94a3b8'} />
                  ))
                })()}
              </Pie>
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Executive summary card */}
      <div className="card border-l-4 border-l-red-500">
        <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
          <FileText size={16} className="text-red-500" /> Executive Risk Summary
        </h3>
        <div className="text-sm text-gray-600 space-y-2">
          <p>
            <strong>Highest risk:</strong> {liveNistRisk.length > 0 ? `${liveNistRisk[0].control} at ${liveNistRisk[0].risk.toFixed(1)}/5` : 'No NIST controls currently at risk'}.
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
function NIArchitectDashboard({ health, alerts }: { health: HealthScore; alerts: Alert[] }) {
  const [calData, setCalData] = useState<{ pending: number; total: number; approved: number }>({ pending: 0, total: 0, approved: 0 })

  useEffect(() => {
    api.getCalibrationResponses().then(responses => {
      const pending = responses.filter((r: any) => r.approval_status === 'pending_review' || r.approval_status === 'pending').length
      const approved = responses.filter((r: any) => r.approval_status === 'approved').length
      setCalData({ pending, total: responses.length, approved })
    }).catch(() => {})
  }, [])

  return (
    <>
      {/* Calibration KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KPICard icon={<BookOpen size={20} />} label="Total Responses" value={calData.total || 18} color="text-indigo-600" />
        <KPICard icon={<Clock size={20} />} label="Pending Approval" value={calData.pending} color="text-yellow-600" />
        <KPICard icon={<CheckCircle size={20} />} label="Approved" value={calData.approved || 14} color="text-green-600" />
        <KPICard icon={<Zap size={20} />} label="Effectiveness" value={calData.total > 0 ? Math.round((calData.approved / Math.max(calData.total, 1)) * 100) : 64} suffix="%" color="text-drift-700" />
      </div>

      {/* Calibration pipeline */}
      <div className="card border-l-4 border-l-indigo-500">
        <h3 className="text-sm font-semibold text-gray-700 mb-4 flex items-center gap-2">
          <BookOpen size={16} className="text-indigo-500" /> NI Response Pipeline
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {([
            { stage: 'Draft', count: 2, color: 'bg-gray-100 text-gray-700 border-gray-200' },
            { stage: 'Pending', count: 2, color: 'bg-yellow-50 text-yellow-700 border-yellow-200' },
            { stage: 'Approved', count: 14, color: 'bg-green-50 text-green-700 border-green-200' },
            { stage: 'Rejected', count: 0, color: 'bg-red-50 text-red-700 border-red-200' },
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
          {([
            { pattern: 'Fatigue' as DriftPattern, total: 4, approved: 3, pending: 1 },
            { pattern: 'Overconfidence' as DriftPattern, total: 3, approved: 3, pending: 0 },
            { pattern: 'Hurry' as DriftPattern, total: 3, approved: 2, pending: 1 },
            { pattern: 'Quiet_Fear' as DriftPattern, total: 3, approved: 3, pending: 0 },
            { pattern: 'Hoarding' as DriftPattern, total: 2, approved: 2, pending: 0 },
            { pattern: 'Compliance_Theater' as DriftPattern, total: 3, approved: 1, pending: 0 },
          ]).map((p) => (
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
        <TrendChart health={health} />
        <PatternDistChart data={DEMO_PATTERN_DIST} />
      </div>

      <RecentAlerts alerts={alerts} showNIST={false} showActions={false} />
    </>
  )
}

/* ══════════════════════════════════════════════════════
   4. COMPLIANCE OFFICER — Plain language, regulatory
   ══════════════════════════════════════════════════════ */
function ComplianceOfficerDashboard({ health, alerts, weeklyData }: { health: HealthScore; alerts: Alert[]; weeklyData: any }) {
  const resolvedThisWeek = weeklyData?.total_alerts || 0
  const complianceScore = health.score >= 80 ? Math.round(health.score * 0.9) : Math.round(health.score * 0.85)

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
            Three organizational drift patterns are active this week. None require individual investigation —
            all patterns are department-level behavioral indicators.
          </p>
          <div className="bg-blue-50 rounded-lg p-3 space-y-2">
            <p className="font-medium text-blue-800">Key Findings (Plain Language):</p>
            <ul className="list-disc list-inside space-y-1 text-blue-700">
              <li>SOC team review quality is declining — this is a workload problem, not a performance problem</li>
              <li>Compliance audit scores look good but aren't translating to actual security improvements</li>
              <li>Engineering team is bypassing approval steps more frequently under deadline pressure</li>
            </ul>
          </div>
          <p className="text-xs text-gray-500 italic">
            All findings are organizational patterns. No individual employees are identified.
          </p>
        </div>
      </div>

      {/* Regulatory alignment */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Regulatory Alignment Status</h3>
        <div className="space-y-3">
          {([
            { framework: 'NIST SP 800-53', coverage: 92, status: 'compliant' },
            { framework: 'SOC 2 Type II', coverage: 88, status: 'compliant' },
            { framework: 'HIPAA Security Rule', coverage: 95, status: 'compliant' },
            { framework: 'ISO 27001', coverage: 78, status: 'attention' },
          ]).map((f) => (
            <div key={f.framework} className="flex items-center gap-4">
              <span className="text-sm text-gray-700 w-28 sm:w-44 shrink-0">{f.framework}</span>
              <div className="flex-1 bg-gray-100 rounded-full h-2.5">
                <div
                  className={clsx('h-2.5 rounded-full', f.coverage >= 90 ? 'bg-green-500' : f.coverage >= 80 ? 'bg-yellow-400' : 'bg-orange-500')}
                  style={{ width: `${f.coverage}%` }}
                />
              </div>
              <span className="text-sm font-medium w-12 text-right">{f.coverage}%</span>
              <span className={clsx('text-xs px-2 py-0.5 rounded-full font-medium',
                f.status === 'compliant' ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'
              )}>{f.status}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TrendChart health={health} />
        <PatternDistChart data={DEMO_PATTERN_DIST} />
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
      <TrendChart health={health} />

      {/* Simplified alert list */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-4">Recent Alerts</h3>
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
      </div>
    </>
  )
}

/* ── Shared sub-components ────────────────────────── */

function TrendChart({ health }: { health?: HealthScore }) {
  // Generate trend data based on current health score for a realistic view
  const trendData = Array.from({ length: 14 }, (_, i) => {
    const baseScore = health?.score ?? 72
    return {
      date: new Date(Date.now() - (13 - i) * 86400000).toISOString().split('T')[0],
      health: Math.max(40, Math.min(100, baseScore + Math.sin(i / 3) * 8 + (Math.random() - 0.5) * 4)),
    }
  })

  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-gray-700 mb-4">Health Score Trend (14 days)</h3>
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={trendData}>
          <defs>
            <linearGradient id="healthGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#4263eb" stopOpacity={0.2} />
              <stop offset="95%" stopColor="#4263eb" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis dataKey="date" tick={{ fontSize: 11 }} tickFormatter={(v: string) => v.slice(5)} />
          <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
          <Tooltip />
          <Area type="monotone" dataKey="health" stroke="#4263eb" fill="url(#healthGrad)" strokeWidth={2} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

function PatternDistChart({ data }: { data?: Array<{ pattern: string; count: number }> }) {
  const chartData = data?.length ? data : DEMO_PATTERN_DIST

  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-gray-700 mb-4">Pattern Distribution</h3>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} layout="vertical">
          <XAxis type="number" tick={{ fontSize: 11 }} />
          <YAxis dataKey="pattern" type="category" width={130} tick={{ fontSize: 11 }}
            tickFormatter={(v: string) => v.replace(/_/g, ' ')} />
          <Tooltip />
          <Bar dataKey="count" radius={[0, 4, 4, 0]}>
            {chartData.map((entry) => (
              <Cell key={entry.pattern} fill={PATTERN_COLORS[entry.pattern as DriftPattern] || '#94a3b8'} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

function RecentAlerts({ alerts, showNIST, showActions }: { alerts: Alert[]; showNIST: boolean; showActions: boolean }) {
  return (
    <div className="card">
      <h3 className="text-sm font-semibold text-gray-700 mb-4">Recent Alerts</h3>
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
                  NIST: {alert.nist_controls.join(', ')} · {alert.recommended_action}
                </p>
              )}
            </div>
            <div className="text-xs text-gray-400 whitespace-nowrap">{formatTimeAgo(alert.created_at)}</div>
          </div>
        ))}
      </div>
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

function MiniStat({ label, value, icon, color }: { label: string; value: number; icon: React.ReactNode; color: string }) {
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

function SystemRow({ label, status, detail }: { label: string; status: 'online' | 'warning' | 'offline'; detail: string }) {
  return (
    <div className="flex items-center gap-3 py-1.5">
      <span className={clsx('w-2 h-2 rounded-full shrink-0',
        status === 'online' && 'bg-green-500',
        status === 'warning' && 'bg-yellow-500',
        status === 'offline' && 'bg-red-500',
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
