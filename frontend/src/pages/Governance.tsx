import { useEffect, useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { LoadingSpinner, EmptyState } from '../components/Shared'
import type { GovernanceAction } from '../types'
import { Shield, CheckCircle, XCircle, Clock, FileText, Lock } from 'lucide-react'
import clsx from 'clsx'

const GATE_LABELS: Record<string, string> = {
  ni_response: 'NI Response Approval',
  nist_mapping: 'NIST Mapping Validation',
  critical_alert: 'Critical Alert Human Review',
}

const DEMO_ACTIONS: GovernanceAction[] = [
  {
    action_id: 'g1', gate_type: 'critical_alert', status: 'pending',
    submitted_at: new Date().toISOString(),
    details: { alert_id: 'a2', pattern: 'Compliance_Theater', severity: 4, department: 'Compliance' },
  },
  {
    action_id: 'g2', gate_type: 'ni_response', status: 'approved',
    submitted_at: new Date(Date.now() - 86400000).toISOString(),
    reviewed_at: new Date(Date.now() - 82800000).toISOString(),
    reviewer: 'NI Architect',
    details: { response_id: 'r1', pattern: 'Fatigue', context: 'healthcare' },
  },
  {
    action_id: 'g3', gate_type: 'nist_mapping', status: 'pending',
    submitted_at: new Date(Date.now() - 43200000).toISOString(),
    details: { control: 'AU-6', mappings_count: 3, validation_score: 0.87 },
  },
  {
    action_id: 'g4', gate_type: 'critical_alert', status: 'rejected',
    submitted_at: new Date(Date.now() - 172800000).toISOString(),
    reviewed_at: new Date(Date.now() - 169200000).toISOString(),
    reviewer: 'CISO',
    details: { alert_id: 'a0', pattern: 'Hoarding', severity: 5, reason: 'Insufficient evidence — requires additional signal corroboration' },
  },
]

const DEMO_AUDIT = [
  { timestamp: new Date().toISOString(), action: 'Alert Created', actor: 'system', details: 'Compliance_Theater Critical alert generated' },
  { timestamp: new Date(Date.now() - 3600000).toISOString(), action: 'NI Response Approved', actor: 'NI Architect', details: 'Fatigue response for healthcare context approved' },
  { timestamp: new Date(Date.now() - 7200000).toISOString(), action: 'Signal Ingested', actor: 'system', details: 'Batch of 24 signals from Splunk connector' },
  { timestamp: new Date(Date.now() - 86400000).toISOString(), action: 'Critical Alert Rejected', actor: 'CISO', details: 'Hoarding alert — insufficient evidence' },
  { timestamp: new Date(Date.now() - 172800000).toISOString(), action: 'Domain Config Updated', actor: 'admin', details: 'Healthcare domain YAML updated' },
]

export default function Governance() {
  const { can } = useAuth()
  const [actions, setActions] = useState<GovernanceAction[]>(DEMO_ACTIONS)
  const [auditLog, setAuditLog] = useState<Array<{ timestamp: string; action: string; actor: string | null; details: string | Record<string, unknown> }>>(DEMO_AUDIT)
  const [loading, setLoading] = useState(true)
  const [acting, setActing] = useState<string | null>(null)
  const [tab, setTab] = useState<'gates' | 'audit'>('gates')
  const [error, setError] = useState<string | null>(null)

  const loadActions = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await api.getPendingActions()
      setActions(data)
    } catch { setError('Failed to load governance actions.') }
    finally { setLoading(false) }
  }

  const loadAudit = async () => {
    try {
      const data = await api.getAuditLog()
      if (data?.entries?.length) setAuditLog(data.entries)
    } catch { /* audit log non-critical */ }
  }

  useEffect(() => {
    loadActions()
    loadAudit()
  }, [])

  const handleApprove = async (action: GovernanceAction) => {
    setActing(action.action_id)
    try {
      await api.approveGovernanceAction(action.gate_type, action.action_id)
      setActions(prev => prev.map(a => a.action_id === action.action_id
        ? { ...a, status: 'approved', reviewed_at: new Date().toISOString(), reviewer: 'Current User' } : a))
      loadAudit()
    } catch { /* keep current state */ }
    finally { setActing(null) }
  }

  const handleReject = async (action: GovernanceAction) => {
    setActing(action.action_id)
    try {
      await api.rejectGovernanceAction(action.gate_type, action.action_id)
      setActions(prev => prev.map(a => a.action_id === action.action_id
        ? { ...a, status: 'rejected', reviewed_at: new Date().toISOString(), reviewer: 'Current User' } : a))
      loadAudit()
    } catch { /* keep current state */ }
    finally { setActing(null) }
  }

  if (!can('view_governance')) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-gray-400">
        <Lock size={48} className="mb-4" />
        <h2 className="text-lg font-semibold text-gray-600">Access Restricted</h2>
        <p className="text-sm mt-1">Governance requires Compliance Officer, NI Architect, CISO, or Administrator access.</p>
      </div>
    )
  }

  if (loading) return <LoadingSpinner />

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 text-sm text-yellow-800">
          {error}
        </div>
      )}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Governance</h1>
        <p className="text-sm text-gray-500 mt-1">
          Approval gates, NIST validation, and immutable audit log
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-100 p-1 rounded-lg w-fit">
        <button
          onClick={() => setTab('gates')}
          className={clsx(
            'px-4 py-2 rounded-md text-sm font-medium transition-colors',
            tab === 'gates' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600 hover:text-gray-900'
          )}
        >
          <Shield size={14} className="inline mr-1.5" />
          Approval Gates
        </button>
        <button
          onClick={() => setTab('audit')}
          className={clsx(
            'px-4 py-2 rounded-md text-sm font-medium transition-colors',
            tab === 'audit' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600 hover:text-gray-900'
          )}
        >
          <FileText size={14} className="inline mr-1.5" />
          Audit Log
        </button>
      </div>

      {tab === 'gates' ? (
        <div className="space-y-3">
          {actions.length === 0 ? (
            <EmptyState message="No governance actions." />
          ) : (
            actions.map((action) => (
              <div
                key={action.action_id}
                className={clsx(
                  'card',
                  action.status === 'pending' && 'border-l-4 border-l-yellow-500'
                )}
              >
                <div className="flex items-center gap-3 mb-2">
                  <GateIcon type={action.gate_type} />
                  <span className="font-medium text-gray-900 text-sm">
                    {GATE_LABELS[action.gate_type] || action.gate_type}
                  </span>
                  <div className="flex-1" />
                  <StatusPill status={action.status} />
                </div>
                <div className="text-xs text-gray-500 space-y-1">
                  <p>Submitted: {new Date(action.submitted_at).toLocaleString()}</p>
                  {action.reviewed_at && <p>Reviewed: {new Date(action.reviewed_at).toLocaleString()} by {action.reviewer}</p>}
                  <p className="text-gray-600 mt-1">
                    {Object.entries(action.details)
                      .map(([k, v]) => `${k.replace(/_/g, ' ')}: ${v}`)
                      .join(' · ')}
                  </p>
                </div>
                {action.status === 'pending' && can('approve_governance') && (
                  <div className="mt-3 flex gap-2">
                    <button onClick={() => handleApprove(action)} disabled={acting === action.action_id}
                      className="btn-primary text-xs flex items-center gap-1">
                      <CheckCircle size={14} /> {acting === action.action_id ? 'Processing…' : 'Approve'}
                    </button>
                    <button onClick={() => handleReject(action)} disabled={acting === action.action_id}
                      className="btn-secondary text-xs flex items-center gap-1 text-red-600">
                      <XCircle size={14} /> Reject
                    </button>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      ) : (
        <div className="card">
          <div className="text-xs text-gray-400 mb-3 font-medium uppercase tracking-wider">
            Immutable Audit Log
          </div>
          <div className="divide-y divide-gray-100">
            {auditLog.map((entry, i) => (
              <div key={i} className="py-3 flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-4">
                <div className="text-xs text-gray-400 whitespace-nowrap sm:w-40">
                  {new Date(entry.timestamp).toLocaleString()}
                </div>
                <div className="flex items-center gap-2 sm:contents">
                  <div className="text-xs font-medium text-gray-700 sm:w-32">{entry.action}</div>
                  <div className="text-xs text-gray-500 sm:w-20">{entry.actor}</div>
                </div>
                <div className="text-xs text-gray-600 flex-1">{typeof entry.details === 'string' ? entry.details : JSON.stringify(entry.details)}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function GateIcon({ type }: { type: string }) {
  const colors: Record<string, string> = {
    ni_response: 'text-purple-500 bg-purple-50',
    nist_mapping: 'text-blue-500 bg-blue-50',
    critical_alert: 'text-red-500 bg-red-50',
  }
  return (
    <div className={clsx('p-1.5 rounded', colors[type] || 'text-gray-500 bg-gray-50')}>
      <Shield size={16} />
    </div>
  )
}

function StatusPill({ status }: { status: string }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium',
        status === 'approved' && 'bg-green-100 text-green-700',
        status === 'pending' && 'bg-yellow-100 text-yellow-700',
        status === 'rejected' && 'bg-red-100 text-red-700'
      )}
    >
      {status === 'pending' && <Clock size={12} />}
      {status === 'approved' && <CheckCircle size={12} />}
      {status === 'rejected' && <XCircle size={12} />}
      {status}
    </span>
  )
}
