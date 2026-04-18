import { useEffect, useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { AlertBadge, PatternTag, SeverityDot, LoadingSpinner, EmptyState } from '../components/Shared'
import type { Alert, AlertLevel } from '../types'
import { CheckCircle, Eye, Filter } from 'lucide-react'
import clsx from 'clsx'

const DEMO_ALERTS: Alert[] = [
  {
    alert_id: 'a1', drift_pattern: 'Fatigue', alert_level: 'Warning', severity: 3, confidence: 0.82,
    department: 'SOC Team', plain_language: 'Alert review cadence has dropped 40% over the past two weeks.',
    nist_controls: ['AU-6', 'CA-7'], recommended_action: 'Rotate reviewer assignments.',
    created_at: new Date().toISOString(), acknowledged: false, resolved: false,
  },
  {
    alert_id: 'a2', drift_pattern: 'Compliance_Theater', alert_level: 'Critical', severity: 4, confidence: 0.91,
    department: 'Compliance', plain_language: 'Audit scores are high but breach indicators are rising.',
    nist_controls: ['CA-7', 'AT-2'], recommended_action: 'Reassess compliance measurement.',
    created_at: new Date(Date.now() - 3600000).toISOString(), acknowledged: false, resolved: false,
  },
  {
    alert_id: 'a3', drift_pattern: 'Overconfidence', alert_level: 'Watch', severity: 2, confidence: 0.74,
    department: 'Engineering', plain_language: 'Deployment bypass rate increased from 5% to 18%.',
    nist_controls: ['AC-2'], recommended_action: 'Review exception patterns.',
    created_at: new Date(Date.now() - 7200000).toISOString(), acknowledged: true, resolved: false,
  },
  {
    alert_id: 'a4', drift_pattern: 'Quiet_Fear', alert_level: 'Warning', severity: 3, confidence: 0.78,
    department: 'Incident Response', plain_language: 'Incident escalation rate dropped 60% despite unchanged threat volume.',
    nist_controls: ['IR-6'], recommended_action: 'Create anonymous escalation channel.',
    created_at: new Date(Date.now() - 14400000).toISOString(), acknowledged: false, resolved: false,
  },
  {
    alert_id: 'a5', drift_pattern: 'Hurry', alert_level: 'Watch', severity: 2, confidence: 0.71,
    department: 'DevOps', plain_language: 'QA validation steps being compressed ahead of release deadline.',
    nist_controls: ['CA-7'], recommended_action: 'Extend validation window or reduce scope.',
    created_at: new Date(Date.now() - 28800000).toISOString(), acknowledged: false, resolved: false,
  },
]

export default function AlertCenter() {
  const { role, can } = useAuth()
  const [alerts, setAlerts] = useState<Alert[]>(DEMO_ALERTS)
  const [filter, setFilter] = useState<AlertLevel | 'all'>('all')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      try {
        const data = await api.getAlerts({ limit: '50' })
        if (!cancelled) setAlerts(data.alerts)
      } catch {
        // demo data
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  const filtered = filter === 'all' ? alerts : alerts.filter((a) => a.alert_level === filter)

  async function handleAcknowledge(id: string) {
    try {
      await api.acknowledgeAlert(id)
    } catch { /* offline */ }
    setAlerts((prev) =>
      prev.map((a) => (a.alert_id === id ? { ...a, acknowledged: true } : a))
    )
  }

  async function handleResolve(id: string) {
    try {
      await api.resolveAlert(id)
    } catch { /* offline */ }
    setAlerts((prev) =>
      prev.map((a) => (a.alert_id === id ? { ...a, resolved: true } : a))
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Alert Center</h1>
          <p className="text-sm text-gray-500 mt-1">
            {role === 'ciso'
              ? 'Technical alert analysis with NIST controls and recommended actions'
              : role === 'admin'
                ? 'Full alert management — acknowledge, resolve, and monitor all drift signals'
                : role === 'compliance_officer'
                  ? 'Drift alerts requiring compliance review and remediation'
                  : role === 'ni_architect'
                    ? 'Pattern alerts informing calibration priorities'
                    : 'Real-time organizational drift alerts (read-only)'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Filter size={16} className="text-gray-400" />
          {(['all', 'Critical', 'Warning', 'Watch'] as const).map((level) => (
            <button
              key={level}
              onClick={() => setFilter(level)}
              className={clsx(
                'px-3 py-1.5 rounded-lg text-xs font-medium transition-colors',
                filter === level ? 'bg-drift-700 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              )}
            >
              {level === 'all' ? 'All' : level}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <LoadingSpinner />
      ) : filtered.length === 0 ? (
        <EmptyState message="No alerts matching this filter." />
      ) : (
        <div className="space-y-3">
          {filtered.map((alert) => (
            <div
              key={alert.alert_id}
              className={clsx(
                'card transition-all',
                alert.resolved && 'opacity-60',
                alert.alert_level === 'Critical' && !alert.resolved && 'border-l-4 border-l-red-500'
              )}
            >
              <div className="flex items-start gap-4">
                <div className="pt-0.5 flex flex-col items-center gap-1">
                  <AlertBadge level={alert.alert_level} />
                  <SeverityDot severity={alert.severity} />
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1.5">
                    <PatternTag pattern={alert.drift_pattern} />
                    <span className="text-xs text-gray-500">{alert.department}</span>
                    <span className="text-xs text-gray-400">
                      Severity {alert.severity}/5 · {(alert.confidence * 100).toFixed(0)}% confidence
                    </span>
                  </div>

                  <p className="text-sm text-gray-800">{alert.plain_language}</p>

                  {(role === 'ciso' || role === 'admin') && (
                    <div className="mt-2 text-xs text-gray-500 space-y-1">
                      <p><strong>NIST Controls:</strong> {alert.nist_controls.join(', ')}</p>
                      <p><strong>Recommended:</strong> {alert.recommended_action}</p>
                    </div>
                  )}
                  {role === 'compliance_officer' && (
                    <div className="mt-2 text-xs text-blue-600 bg-blue-50 rounded p-2">
                      <p><strong>Recommended Action:</strong> {alert.recommended_action}</p>
                    </div>
                  )}
                  {role === 'ni_architect' && (
                    <div className="mt-2 text-xs text-indigo-600 bg-indigo-50 rounded p-2">
                      <p><strong>Calibration relevance:</strong> Pattern "{alert.drift_pattern.replace(/_/g, ' ')}" at severity {alert.severity}/5 — check NI response coverage</p>
                    </div>
                  )}
                </div>

                <div className="flex flex-col gap-2 shrink-0">
                  {!alert.acknowledged && !alert.resolved && can('acknowledge_alert') && (
                    <button
                      onClick={() => handleAcknowledge(alert.alert_id)}
                      className="btn-secondary flex items-center gap-1.5 text-xs"
                    >
                      <Eye size={14} /> Acknowledge
                    </button>
                  )}
                  {!alert.resolved && can('resolve_alert') && (
                    <button
                      onClick={() => handleResolve(alert.alert_id)}
                      className="btn-primary flex items-center gap-1.5 text-xs"
                    >
                      <CheckCircle size={14} /> Resolve
                    </button>
                  )}
                  {alert.resolved && (
                    <span className="text-xs text-green-600 font-medium">Resolved</span>
                  )}
                  {!can('acknowledge_alert') && !alert.resolved && (
                    <span className="text-xs text-gray-400 italic">View only</span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
