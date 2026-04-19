import { useEffect, useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { LoadingSpinner } from '../components/Shared'
import type { WeeklyReportData, NISTRiskData, BoardSummaryData } from '../types'
import {
  Tooltip, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  PieChart, Pie, Cell, Legend,
} from 'recharts'
import { BarChart3, FileText, Shield, Users, Download } from 'lucide-react'
import clsx from 'clsx'

const PIE_COLORS = ['#ff6b6b', '#ff922b', '#fcc419', '#845ef7', '#339af0', '#20c997']

const NIST_LABELS: Record<string, string> = {
  'AC-2': 'Account Management', 'AU-6': 'Audit Review', 'IR-6': 'Incident Reporting',
  'CA-7': 'Continuous Monitoring', 'AT-2': 'Awareness Training',
}

type Tab = 'weekly' | 'nist' | 'board'

export default function Reports() {
  const { can } = useAuth()
  const [tab, setTab] = useState<Tab>('weekly')

  const tabs = [
    { key: 'weekly' as const, label: 'Weekly Summary', icon: BarChart3, perm: 'view_reports_weekly' as const },
    { key: 'nist' as const, label: 'NIST Risk Matrix', icon: Shield, perm: 'view_reports_nist' as const },
    { key: 'board' as const, label: 'Board Summary', icon: FileText, perm: 'view_reports_board' as const },
  ].filter(({ perm }) => can(perm))

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Reports</h1>
        <p className="text-sm text-gray-500 mt-1">Live organizational reports powered by real drift data</p>
      </div>
      <div className="flex gap-1 bg-gray-100 p-1 rounded-lg w-fit">
        {tabs.map(({ key, label, icon: Icon }) => (
          <button key={key} onClick={() => setTab(key)}
            className={clsx('px-4 py-2 rounded-md text-sm font-medium transition-colors flex items-center gap-1.5',
              tab === key ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600 hover:text-gray-900')}>
            <Icon size={14} /> {label}
          </button>
        ))}
      </div>
      {tab === 'weekly' && <WeeklyReport />}
      {tab === 'nist' && <NISTReport />}
      {tab === 'board' && <BoardSummary />}
    </div>
  )
}

function WeeklyReport() {
  const { role } = useAuth()
  const [data, setData] = useState<WeeklyReportData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let c = false
    api.getWeeklyReport().then(d => { if (!c) setData(d) }).catch(() => {}).finally(() => { if (!c) setLoading(false) })
    return () => { c = true }
  }, [])

  if (loading) return <LoadingSpinner />
  if (!data) return <div className="card text-sm text-gray-400">No report data available.</div>

  const patternPie = Object.entries(data.pattern_distribution).map(([name, value], i) => ({
    name: name.replace(/_/g, ' '), value, color: PIE_COLORS[i % PIE_COLORS.length],
  }))

  const exportCsv = () => {
    const rows = [
      ['Metric', 'Value'],
      ['Health Score', String(data.health_score)],
      ['Total Alerts', String(data.total_alerts)],
      ['Critical', String(data.critical_count)],
      ['Warning', String(data.warning_count)],
      ['Watch', String(data.watch_count)],
      ...Object.entries(data.pattern_distribution).map(([k, v]) => [`Pattern: ${k}`, String(v)]),
    ]
    const csv = rows.map(r => r.join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'weekly_report.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-gray-700">Weekly Summary — {data.domain}</h3>
          <button onClick={exportCsv} className="btn-secondary text-xs flex items-center gap-1">
            <Download size={12} /> Export CSV
          </button>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <Stat label="Health Score" value={`${data.health_score}/100`} />
          <Stat label="Total Alerts" value={data.total_alerts} />
          <Stat label="Critical" value={data.critical_count} color="text-red-600" />
          <Stat label="Warning" value={data.warning_count} color="text-orange-600" />
          <Stat label="Watch" value={data.watch_count} />
        </div>
      </div>

      {role === 'compliance_officer' && (
        <div className="card border-l-4 border-blue-500">
          <h3 className="text-sm font-semibold text-blue-800 mb-2">Plain Language Summary</h3>
          <p className="text-sm text-gray-700">
            This week, the organization scored <strong>{data.health_score} out of 100</strong>.
            There were <strong>{data.critical_count} critical</strong> and <strong>{data.warning_count} warning</strong> issues.
            {data.nist_controls_at_risk.length > 0 &&
              <> NIST controls at risk: <strong>{data.nist_controls_at_risk.join(', ')}</strong>.</>}
          </p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {data.nist_controls_at_risk.length > 0 && (
          <div className="card">
            <h3 className="text-sm font-semibold text-gray-700 mb-4">NIST Controls at Risk</h3>
            <div className="space-y-2">
              {data.nist_controls_at_risk.map(ctrl => (
                <div key={ctrl} className="flex items-center gap-3 text-sm">
                  <span className="font-mono font-bold text-drift-700 w-12">{ctrl}</span>
                  <span className="text-gray-600">{NIST_LABELS[ctrl] || ctrl}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {patternPie.length > 0 && (
          <div className="card">
            <h3 className="text-sm font-semibold text-gray-700 mb-4">Alert Distribution by Pattern</h3>
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={patternPie} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={90} paddingAngle={2}>
                  {patternPie.map(e => <Cell key={e.name} fill={e.color} />)}
                </Pie>
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  )
}

function NISTReport() {
  const [data, setData] = useState<NISTRiskData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let c = false
    api.getNISTRisk().then(d => { if (!c) setData(d) }).catch(() => {}).finally(() => { if (!c) setLoading(false) })
    return () => { c = true }
  }, [])

  if (loading) return <LoadingSpinner />
  if (!data || data.controls_at_risk.length === 0) {
    return <div className="card text-sm text-gray-400">No NIST risk data. Ingest signals to generate risk assessments.</div>
  }

  const radarData = data.controls_at_risk.map(c => ({
    control: c.control, risk: c.risk_score ?? c.max_severity, label: NIST_LABELS[c.control] || c.control,
  }))

  return (
    <div className="space-y-6">
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-700 mb-4">NIST SP 800-53 Control Risk Assessment</h3>
        <ResponsiveContainer width="100%" height={300}>
          <RadarChart data={radarData}>
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
          {data.controls_at_risk.map(ctrl => {
            const risk = ctrl.risk_score ?? ctrl.max_severity
            return (
              <div key={ctrl.control} className="py-3 flex items-center gap-4">
                <span className="font-mono text-sm font-bold text-drift-700 w-16">{ctrl.control}</span>
                <span className="text-sm text-gray-700 flex-1">{NIST_LABELS[ctrl.control] || ctrl.control}</span>
                <span className="text-xs text-gray-500 w-24">{ctrl.alert_count} alerts</span>
                <div className="w-48 bg-gray-100 rounded-full h-2">
                  <div className={clsx('h-2 rounded-full', risk >= 4 ? 'bg-red-500' : risk >= 3 ? 'bg-orange-400' : 'bg-green-500')}
                    style={{ width: `${(risk / 5) * 100}%` }} />
                </div>
                <span className="text-sm font-medium w-12 text-right">{risk.toFixed ? risk.toFixed(1) : risk}</span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function BoardSummary() {
  const { role } = useAuth()
  const [data, setData] = useState<BoardSummaryData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let c = false
    api.getBoardSummary().then(d => { if (!c) setData(d) }).catch(() => {}).finally(() => { if (!c) setLoading(false) })
    return () => { c = true }
  }, [])

  if (loading) return <LoadingSpinner />
  if (!data) return <div className="card text-sm text-gray-400">No board data available.</div>

  const es = data.executive_summary
  const trendColor = es.trend === 'improving' ? 'text-green-600' : es.trend === 'degrading' ? 'text-red-600' : 'text-gray-600'

  return (
    <div className="space-y-6">
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <Users size={20} className="text-drift-700" />
          <h3 className="text-sm font-semibold text-gray-700">
            {role === 'ciso' ? 'CISO Executive Briefing' : 'Board-Level Executive Summary'}
          </h3>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <Stat label="Health Score" value={`${es.health_score}/100`}
            color={es.health_score >= 70 ? 'text-green-600' : es.health_score >= 40 ? 'text-orange-600' : 'text-red-600'} />
          <Stat label="Trend" value={es.trend.charAt(0).toUpperCase() + es.trend.slice(1)} color={trendColor} />
          <Stat label="Active Critical" value={es.active_critical} color="text-red-600" />
          <Stat label="Active Warnings" value={es.active_warnings} color="text-orange-600" />
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
          <Stat label="Calibrations Delivered" value={es.calibration_responses_delivered} />
          <Stat label="Calibrations Acted Upon" value={es.calibration_acted_upon} />
        </div>
        <div className={clsx(
          'p-4 rounded-lg text-sm',
          es.health_score >= 70 ? 'bg-green-50 text-green-800' :
          es.health_score >= 40 ? 'bg-yellow-50 text-yellow-800' :
          'bg-red-50 text-red-800'
        )}>
          <strong>Recommendation:</strong> {data.recommendation}
        </div>
      </div>
      <div className="card bg-drift-50/30 text-xs text-drift-800 p-3 rounded-lg">
        DriftGuard detects organizational patterns — never individual behavior.
        No employee is identified, profiled, or targeted.
        Report generated {new Date().toLocaleString()}.
      </div>
    </div>
  )
}

function Stat({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div>
      <div className="text-xs text-gray-500">{label}</div>
      <div className={clsx('text-lg font-bold', color || 'text-gray-900')}>{value}</div>
    </div>
  )
}
