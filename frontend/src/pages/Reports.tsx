import { useState } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts'
import { useAuth } from '../auth'
import clsx from 'clsx'
import { BarChart3, FileText, Shield, Users } from 'lucide-react'

const NIST_RISK = [
  { control: 'AC-2', risk: 3.2, label: 'Account Management' },
  { control: 'AU-6', risk: 4.1, label: 'Audit Review' },
  { control: 'IR-6', risk: 2.8, label: 'Incident Reporting' },
  { control: 'CA-7', risk: 3.7, label: 'Continuous Monitoring' },
  { control: 'AT-2', risk: 2.4, label: 'Awareness Training' },
]

const DEPT_RISK = [
  { department: 'SOC', risk_score: 68 },
  { department: 'Engineering', risk_score: 55 },
  { department: 'Compliance', risk_score: 42 },
  { department: 'Clinical IT', risk_score: 72 },
  { department: 'Finance', risk_score: 48 },
  { department: 'HR', risk_score: 35 },
]

const PATTERN_PIE = [
  { name: 'Fatigue', value: 28, color: '#ff6b6b' },
  { name: 'Overconfidence', value: 18, color: '#ff922b' },
  { name: 'Hurry', value: 15, color: '#fcc419' },
  { name: 'Quiet Fear', value: 12, color: '#845ef7' },
  { name: 'Hoarding', value: 8, color: '#339af0' },
  { name: 'Compliance Theater', value: 19, color: '#20c997' },
]

const WEEKLY_SUMMARY = {
  period: 'Dec 30, 2024 — Jan 5, 2025',
  health_score: 72,
  total_alerts: 14,
  critical: 2,
  warning: 5,
  watch: 7,
  calibrations_delivered: 8,
  effectiveness_rate: 64,
}

type ReportTab = 'weekly' | 'nist' | 'board'

export default function Reports() {
  const { role, can } = useAuth()
  const [tab, setTab] = useState<ReportTab>('weekly')

  const tabs = [
    { key: 'weekly' as const, label: 'Weekly Summary', icon: BarChart3, perm: 'view_reports_weekly' as const },
    { key: 'nist' as const, label: 'NIST Risk Matrix', icon: Shield, perm: 'view_reports_nist' as const },
    { key: 'board' as const, label: 'Board Summary', icon: FileText, perm: 'view_reports_board' as const },
  ].filter(({ perm }) => can(perm))

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Reports</h1>
        <p className="text-sm text-gray-500 mt-1">
          {role === 'compliance_officer'
            ? 'Plain language compliance reports — no technical jargon'
            : role === 'ciso'
              ? 'Technical risk analysis, NIST alignment, and board-ready executive summaries'
              : role === 'ni_architect'
                ? 'Calibration effectiveness and pattern coverage metrics'
                : role === 'admin'
                  ? 'Complete organizational reports across all categories'
                  : 'Weekly organizational health summary'}
        </p>
      </div>

      {/* Report tabs */}
      <div className="flex gap-1 bg-gray-100 p-1 rounded-lg w-fit">
        {tabs.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={clsx(
              'px-4 py-2 rounded-md text-sm font-medium transition-colors flex items-center gap-1.5',
              tab === key ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600 hover:text-gray-900'
            )}
          >
            <Icon size={14} /> {label}
          </button>
        ))}
      </div>

      {tab === 'weekly' && <WeeklyReport />}
      {tab === 'nist' && <NISTReport />}
      {tab === 'board' && <BoardSummary role={role} />}
    </div>
  )
}

function WeeklyReport() {
  const s = WEEKLY_SUMMARY
  const { role } = useAuth()
  return (
    <div className="space-y-6">
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-4">
          Week of {s.period}
        </h3>
        {role === 'compliance_officer' ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Stat label="Compliance Health" value={`${s.health_score}/100`} />
            <Stat label="Issues Requiring Review" value={s.critical + s.warning} color="text-orange-600" />
            <Stat label="Resolved This Week" value={s.calibrations_delivered} />
            <Stat label="Effectiveness Rate" value={`${s.effectiveness_rate}%`} />
          </div>
        ) : role === 'ni_architect' ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Stat label="Calibrations Delivered" value={s.calibrations_delivered} />
            <Stat label="Effectiveness Rate" value={`${s.effectiveness_rate}%`} />
            <Stat label="Active Patterns" value={PATTERN_PIE.length} />
            <Stat label="Alerts Triggered" value={s.total_alerts} />
          </div>
        ) : role === 'viewer' ? (
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            <Stat label="Health Score" value={`${s.health_score}/100`} />
            <Stat label="Total Alerts" value={s.total_alerts} />
            <Stat label="Critical" value={s.critical} color="text-red-600" />
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Stat label="Health Score" value={`${s.health_score}/100`} />
            <Stat label="Total Alerts" value={s.total_alerts} />
            <Stat label="Critical" value={s.critical} color="text-red-600" />
            <Stat label="Calibrations Delivered" value={s.calibrations_delivered} />
          </div>
        )}
      </div>

      {/* Compliance officer: plain-language narrative */}
      {role === 'compliance_officer' && (
        <div className="card border-l-4 border-blue-500">
          <h3 className="text-sm font-semibold text-blue-800 mb-2">Plain Language Summary</h3>
          <p className="text-sm text-gray-700">
            This week, the organization scored <strong>{s.health_score} out of 100</strong> on overall security health.
            There were <strong>{s.critical} critical</strong> and <strong>{s.warning} moderate</strong> issues detected.
            {s.calibrations_delivered} corrective actions were delivered with a <strong>{s.effectiveness_rate}%</strong> success rate.
            The most common issue was staff fatigue in the SOC team. No regulatory violations were detected.
          </p>
        </div>
      )}

      {/* NI Architect: calibration effectiveness breakdown */}
      {role === 'ni_architect' && (
        <div className="card border-l-4 border-indigo-500">
          <h3 className="text-sm font-semibold text-indigo-800 mb-3">Calibration Effectiveness Breakdown</h3>
          <div className="space-y-2">
            {[
              { pattern: 'Fatigue', delivered: 3, effective: 2 },
              { pattern: 'Overconfidence', delivered: 2, effective: 2 },
              { pattern: 'Compliance Theater', delivered: 2, effective: 1 },
              { pattern: 'Hurry', delivered: 1, effective: 1 },
            ].map(({ pattern, delivered, effective }) => (
              <div key={pattern} className="flex items-center gap-3">
                <span className="text-sm text-gray-700 w-40">{pattern}</span>
                <div className="flex-1 bg-gray-100 rounded-full h-2">
                  <div
                    className="h-2 rounded-full bg-indigo-500"
                    style={{ width: `${(effective / delivered) * 100}%` }}
                  />
                </div>
                <span className="text-xs text-gray-500 w-16 text-right">{effective}/{delivered}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Department risk — not shown to viewer */}
        {role !== 'viewer' && (
          <div className="card">
            <h3 className="text-sm font-semibold text-gray-700 mb-4">
              {role === 'compliance_officer' ? 'Compliance Risk by Department' : 'Department Risk Scores'}
            </h3>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={DEPT_RISK}>
                <XAxis dataKey="department" tick={{ fontSize: 11 }} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="risk_score" fill={role === 'compliance_officer' ? '#2563eb' : '#4263eb'} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Pattern distribution pie */}
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-4">
            {role === 'ni_architect' ? 'Calibration Targets by Pattern' : 'Alert Distribution by Pattern'}
          </h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={PATTERN_PIE}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={90}
                paddingAngle={2}
              >
                {PATTERN_PIE.map((entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ))}
              </Pie>
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}

function NISTReport() {
  return (
    <div className="space-y-6">
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-4">NIST SP 800-53 Control Risk Assessment</h3>
        <ResponsiveContainer width="100%" height={300}>
          <RadarChart data={NIST_RISK}>
            <PolarGrid />
            <PolarAngleAxis dataKey="control" tick={{ fontSize: 12 }} />
            <PolarRadiusAxis domain={[0, 5]} tick={{ fontSize: 10 }} />
            <Radar name="Risk Score" dataKey="risk" stroke="#e03131" fill="#e03131" fillOpacity={0.2} />
          </RadarChart>
        </ResponsiveContainer>
      </div>

      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-4">Control Detail</h3>
        <div className="divide-y divide-gray-100">
          {NIST_RISK.map((ctrl) => (
            <div key={ctrl.control} className="py-3 flex items-center gap-4">
              <span className="font-mono text-sm font-bold text-drift-700 w-16">{ctrl.control}</span>
              <span className="text-sm text-gray-700 flex-1">{ctrl.label}</span>
              <div className="w-48 bg-gray-100 rounded-full h-2">
                <div
                  className={clsx(
                    'h-2 rounded-full transition-all',
                    ctrl.risk >= 4 ? 'bg-red-500' : ctrl.risk >= 3 ? 'bg-orange-400' : 'bg-green-500'
                  )}
                  style={{ width: `${(ctrl.risk / 5) * 100}%` }}
                />
              </div>
              <span className="text-sm font-medium w-12 text-right">{ctrl.risk.toFixed(1)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function BoardSummary({ role }: { role: string }) {
  return (
    <div className="space-y-6">
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <Users size={20} className="text-drift-700" />
          <h3 className="text-sm font-semibold text-gray-700">
            {role === 'ciso' ? 'CISO Executive Briefing' : 'Board-Level Executive Summary'}
          </h3>
        </div>

        <div className="prose prose-sm max-w-none text-gray-700">
          <h4>Organizational Health: Moderate (72/100)</h4>
          <p>
            The organization is operating with three active drift patterns: Fatigue (SOC operations),
            Compliance Theater (compliance department), and Overconfidence (engineering). Two critical
            alerts are pending human review.
          </p>

          <h4>Key Findings</h4>
          <ul>
            <li>
              <strong>SOC Fatigue:</strong> Alert review quality has declined under sustained volume.
              This is a capacity problem, not a personnel problem. Recommended: reviewer rotation and
              alert volume optimization.
            </li>
            <li>
              <strong>Compliance Divergence:</strong> Audit completion rates (98%) are not producing
              corresponding security outcomes. This is the most significant finding — the compliance
              program requires structural reassessment.
            </li>
            <li>
              <strong>Engineering Bypass Rate:</strong> Deployment approval exceptions have risen from
              5% to 18%. Currently at Watch level. Monitoring for acceleration.
            </li>
          </ul>

          <h4>NIST Control Status</h4>
          <p>
            AU-6 (Audit Review) is the highest-risk control at 4.1/5, driven by the Compliance Theater
            pattern. CA-7 (Continuous Monitoring) follows at 3.7/5. All other controls within acceptable
            thresholds.
          </p>

          {/* CISO-specific: risk trend & strategic recommendations */}
          {role === 'ciso' && (
            <>
              <h4>Risk Trend (30-Day)</h4>
              <p>
                Overall risk posture has <strong>increased 8%</strong> since the previous reporting period,
                driven primarily by the SOC fatigue pattern (contributing 4.2 points) and the compliance
                divergence finding (contributing 3.1 points). Engineering bypass patterns are stabilizing.
              </p>
              <h4>Strategic Recommendations</h4>
              <ol>
                <li>Escalate SOC staffing review to VP-level — fatigue pattern shows acceleration trajectory</li>
                <li>Commission third-party compliance program audit to validate DriftGuard findings</li>
                <li>Present the compliance divergence finding to the audit committee with quantified risk exposure</li>
                <li>Establish quarterly board cadence for Neuro-Informed risk reporting</li>
              </ol>
            </>
          )}

          {/* Admin-specific: full board actions + system recommendations */}
          {role === 'admin' && (
            <>
              <h4>Recommended Board Actions</h4>
              <ol>
                <li>Authorize SOC staffing review to address capacity constraints</li>
                <li>Commission compliance program effectiveness assessment</li>
                <li>Review engineering deployment governance framework</li>
              </ol>
              <h4>System Administration Notes</h4>
              <p>
                Current domain configuration: Healthcare (primary). 5 integrations active.
                Alert processing latency: 1.2s average. Storage utilization: 34%.
                Next scheduled maintenance: January 15, 2025.
              </p>
            </>
          )}

          {/* Compliance officer gets simplified, non-technical actions */}
          {role === 'compliance_officer' && (
            <>
              <h4>What This Means for Compliance</h4>
              <p>
                The audit completion rates look good on paper (98%), but DriftGuard has detected that these
                audits are not translating into actual security improvements. This is called &quot;Compliance Theater&quot; —
                where teams follow the process without achieving the intended outcome. <strong>This is the most
                important finding for your team this week.</strong>
              </p>
              <h4>Recommended Next Steps</h4>
              <ol>
                <li>Review audit procedures for effectiveness, not just completion</li>
                <li>Schedule a meeting with the SOC team to understand workload pressures</li>
                <li>Document the compliance divergence finding for the next regulatory review</li>
              </ol>
            </>
          )}
        </div>

        <div className="mt-6 p-3 bg-drift-50 rounded-lg text-xs text-drift-800">
          All DriftGuard observations are organizational-level pattern analyses. No individual employees
          are identified, profiled, or targeted in any report. This is a non-negotiable ethical constraint
          of the system.
        </div>
      </div>
    </div>
  )
}

function Stat({ label, value, color = 'text-gray-900' }: { label: string; value: string | number; color?: string }) {
  return (
    <div>
      <p className="text-xs text-gray-500">{label}</p>
      <p className={clsx('text-xl font-bold', color)}>{value}</p>
    </div>
  )
}
