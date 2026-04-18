import { useEffect, useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { LoadingSpinner, PatternTag } from '../components/Shared'
import type { CalibrationResponse } from '../types'
import { CheckCircle, XCircle, BookOpen, Eye, Lock } from 'lucide-react'
import clsx from 'clsx'

const DEMO_RESPONSES: CalibrationResponse[] = [
  {
    response_id: 'r1',
    drift_pattern: 'Fatigue',
    severity_range: [1, 5],
    organizational_context: 'healthcare',
    response_text: 'The review cadence has exceeded sustainable rhythm. Reduce volume, increase depth, rotate reviewer assignments.',
    approval_status: 'approved',
    is_placeholder: true,
  },
  {
    response_id: 'r2',
    drift_pattern: 'Compliance_Theater',
    severity_range: [3, 5],
    organizational_context: 'enterprise',
    response_text: 'Audit scores are high. Breach indicators are also high. The compliance process has become a performance. The response is a fundamental reassessment.',
    approval_status: 'pending',
    is_placeholder: true,
  },
  {
    response_id: 'r3',
    drift_pattern: 'Quiet_Fear',
    severity_range: [1, 5],
    organizational_context: 'government',
    response_text: 'The silence in incident reporting is itself the signal. Before investigating the technical gap, address the reporting culture.',
    approval_status: 'approved',
    is_placeholder: true,
  },
  {
    response_id: 'r4',
    drift_pattern: 'Overconfidence',
    severity_range: [3, 5],
    organizational_context: 'finance',
    response_text: 'The pattern of exceptions has normalized risk. A governance reset is required before access decisions return to standard flow.',
    approval_status: 'rejected',
    is_placeholder: true,
  },
]

export default function Calibration() {
  const { can } = useAuth()
  const [responses, setResponses] = useState<CalibrationResponse[]>(DEMO_RESPONSES)
  const [loading, setLoading] = useState(false)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      try {
        const data = await api.getCalibrationResponses()
        if (!cancelled) setResponses(data)
      } catch {
        // demo data
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  const canApprove = can('approve_calibration')

  if (!can('view_calibration')) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-gray-400">
        <Lock size={48} className="mb-4" />
        <h2 className="text-lg font-semibold text-gray-600">Access Restricted</h2>
        <p className="text-sm mt-1">NI Calibration requires a non-viewer role.</p>
      </div>
    )
  }

  async function handleApprove(id: string) {
    try { await api.approveCalibration(id) } catch { /* offline */ }
    setResponses((prev) =>
      prev.map((r) => (r.response_id === id ? { ...r, approval_status: 'approved' } : r))
    )
  }

  async function handleReject(id: string) {
    try { await api.rejectCalibration(id) } catch { /* offline */ }
    setResponses((prev) =>
      prev.map((r) => (r.response_id === id ? { ...r, approval_status: 'rejected' } : r))
    )
  }

  if (loading) return <LoadingSpinner />

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">NI Calibration</h1>
        <p className="text-sm text-gray-500 mt-1">
          Narrative Intelligence response library — content owned by framework team
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard label="Total Responses" value={responses.length} icon={<BookOpen size={18} />} />
        <StatCard
          label="Pending Approval"
          value={responses.filter((r) => r.approval_status === 'pending').length}
          icon={<Eye size={18} />}
          color="text-yellow-600"
        />
        <StatCard
          label="Approved"
          value={responses.filter((r) => r.approval_status === 'approved').length}
          icon={<CheckCircle size={18} />}
          color="text-green-600"
        />
      </div>

      {/* Response list */}
      <div className="space-y-3">
        {responses.map((resp) => (
          <div
            key={resp.response_id}
            className={clsx(
              'card cursor-pointer transition-all',
              resp.approval_status === 'rejected' && 'opacity-60'
            )}
            onClick={() => setExpandedId(expandedId === resp.response_id ? null : resp.response_id)}
          >
            <div className="flex items-center gap-3">
              <PatternTag pattern={resp.drift_pattern} />
              <span className="text-xs text-gray-500">
                Severity {resp.severity_range[0]}-{resp.severity_range[1]}
              </span>
              <span className="text-xs text-gray-500">{resp.organizational_context}</span>
              <div className="flex-1" />
              <StatusBadge status={resp.approval_status} />
              {resp.is_placeholder && (
                <span className="text-xs text-gray-400 bg-gray-100 px-2 py-0.5 rounded">
                  Placeholder
                </span>
              )}
            </div>

            {expandedId === resp.response_id && (
              <div className="mt-4 pt-4 border-t border-gray-100">
                <p className="text-sm text-gray-700 leading-relaxed whitespace-pre-line">
                  {resp.response_text}
                </p>
                {canApprove && resp.approval_status === 'pending' && (
                  <div className="mt-4 flex items-center gap-3">
                    <button
                      onClick={(e) => { e.stopPropagation(); handleApprove(resp.response_id) }}
                      className="btn-primary flex items-center gap-1.5 text-xs"
                    >
                      <CheckCircle size={14} /> Approve
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleReject(resp.response_id) }}
                      className="btn-secondary flex items-center gap-1.5 text-xs text-red-600"
                    >
                      <XCircle size={14} /> Reject
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium',
        status === 'approved' && 'bg-green-100 text-green-700',
        status === 'pending' && 'bg-yellow-100 text-yellow-700',
        status === 'rejected' && 'bg-red-100 text-red-700'
      )}
    >
      {status}
    </span>
  )
}

function StatCard({
  label,
  value,
  icon,
  color = 'text-gray-900',
}: {
  label: string
  value: number
  icon: React.ReactNode
  color?: string
}) {
  return (
    <div className="card flex items-center gap-3">
      <div className="p-2 rounded-lg bg-gray-50 text-gray-500">{icon}</div>
      <div>
        <p className="text-xs text-gray-500">{label}</p>
        <p className={clsx('text-xl font-bold', color)}>{value}</p>
      </div>
    </div>
  )
}
