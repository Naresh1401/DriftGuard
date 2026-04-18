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
  const { role } = useAuth()
  const [tab, setTab] = useState<ReportTab>('weekly')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Reports</h1>
        <p className="text-sm text-gray-500 mt-1">
          {role === 'compliance_officer'
            ? 'Plain language compliance reports'
            : role === 'ciso'
              ? 'Technical risk analysis and NIST alignment'
              : 'Organizational drift reports and metrics'}
        </p>
      </div>

      {/* Report tabs */}
      <div className="flex gap-1 bg-gray-100 p-1 rounded-lg w-fit">
        {([
          { key: 'weekly', label: 'Weekly Summary', icon: BarChart3 },
          { key: 'nist', label: 'NIST Risk Matrix', icon: Shield },
          { key: 'board', label: 'Board Summary', icon: FileText },
        ] as const).map(({ key, label, icon: Icon }) => (
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
  return (
    <div className="space-y-6">
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-4">
          Week of {s.period}
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Stat label="Health Score" value={`${s.health_score}/100`} />
          <Stat label="Total Alerts" value={s.total_alerts} />
          <Stat label="Critical" value={s.critical} color="text-red-600" />
          <Stat label="Calibrations Delivered" value={s.calibrations_delivered} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Department risk */}
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-4">Department Risk Scores</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={DEPT_RISK}>
              <XAxis dataKey="department" tick={{ fontSize: 11 }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
              <Tooltip />
              <Bar dataKey="risk_score" fill="#4263eb" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Pattern distribution pie */}
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-4">Alert Distribution by Pattern</h3>
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
          <h3 className="text-sm font-semibold text-gray-700">Board-Level Executive Summary</h3>
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

          {role !== 'compliance_officer' && (
            <>
              <h4>Recommended Board Actions</h4>
              <ol>
                <li>Authorize SOC staffing review to address capacity constraints</li>
                <li>Commission compliance program effectiveness assessment</li>
                <li>Review engineering deployment governance framework</li>
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
