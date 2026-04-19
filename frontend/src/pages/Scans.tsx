import { useEffect, useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { LoadingSpinner } from '../components/Shared'
import type { ScanRecord, ScanSchedule } from '../types'
import { Play, Clock, RotateCw, Calendar, CheckCircle, XCircle, Loader } from 'lucide-react'
import clsx from 'clsx'

export default function Scans() {
  const { can } = useAuth()
  const [history, setHistory] = useState<ScanRecord[]>([])
  const [schedules, setSchedules] = useState<ScanSchedule[]>([])
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState<'scans' | 'schedules'>('scans')

  const load = async () => {
    try {
      const [histRes, schedRes, statusRes] = await Promise.all([
        api.getScanHistory(),
        api.getScanSchedules(),
        api.getScanStatus(),
      ])
      setHistory(histRes.scans)
      setSchedules(schedRes.schedules)
      if (statusRes.active) setScanning(true)
    } catch {}
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  const triggerScan = async (scope: string) => {
    setScanning(true)
    setScanResult(null)
    try {
      const res = await api.triggerScan('enterprise', scope)
      setScanResult(res.message)
      // Poll for completion
      const poll = setInterval(async () => {
        const status = await api.getScanStatus()
        if (!status.active) {
          clearInterval(poll)
          setScanning(false)
          load()
        }
      }, 2000)
    } catch (e: unknown) {
      setScanResult(e instanceof Error ? e.message : 'Scan failed')
      setScanning(false)
    }
  }

  if (loading) return <LoadingSpinner />

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Drift Scans</h1>
        <p className="text-sm text-gray-500 mt-1">Trigger on-demand scans or manage scheduled scanning</p>
      </div>

      {/* Quick actions */}
      {can('trigger_scan') && (
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-700 mb-3">Run Scan</h3>
          <div className="flex gap-3">
            <button onClick={() => triggerScan('quick')} disabled={scanning}
              className="btn-secondary text-sm flex items-center gap-1.5">
              <Play size={14} /> Quick Scan
            </button>
            <button onClick={() => triggerScan('full')} disabled={scanning}
              className="btn-primary text-sm flex items-center gap-1.5">
              {scanning ? <Loader size={14} className="animate-spin" /> : <RotateCw size={14} />}
              {scanning ? 'Scanning…' : 'Full Scan'}
            </button>
          </div>
          {scanResult && (
            <p className="text-xs text-green-700 mt-2 bg-green-50 p-2 rounded">{scanResult}</p>
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-100 p-1 rounded-lg w-fit">
        <button onClick={() => setTab('scans')}
          className={clsx('px-4 py-2 rounded-md text-sm font-medium transition-colors',
            tab === 'scans' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600')}>
          <Clock size={14} className="inline mr-1.5" /> History
        </button>
        <button onClick={() => setTab('schedules')}
          className={clsx('px-4 py-2 rounded-md text-sm font-medium transition-colors',
            tab === 'schedules' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600')}>
          <Calendar size={14} className="inline mr-1.5" /> Schedules
        </button>
      </div>

      {tab === 'scans' ? (
        <div className="card">
          <div className="text-xs text-gray-400 mb-3 font-medium uppercase tracking-wider">Scan History</div>
          {history.length === 0 ? (
            <p className="text-sm text-gray-400">No scans yet. Trigger a scan above.</p>
          ) : (
            <div className="divide-y divide-gray-100">
              {history.map(scan => (
                <div key={scan.scan_id} className="py-3 flex items-center gap-4">
                  <StatusIcon status={scan.status} />
                  <div className="flex-1">
                    <div className="text-sm font-medium text-gray-900">
                      {scan.scope.charAt(0).toUpperCase() + scan.scope.slice(1)} scan — {scan.domain}
                    </div>
                    <div className="text-xs text-gray-500">
                      {new Date(scan.started_at).toLocaleString()} · by {scan.triggered_by}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-semibold text-gray-900">{scan.signals_processed} signals</div>
                    <div className="text-xs text-gray-500">{scan.alerts_generated} alerts</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : (
        <div className="card">
          <div className="text-xs text-gray-400 mb-3 font-medium uppercase tracking-wider">Scheduled Scans</div>
          {schedules.length === 0 ? (
            <p className="text-sm text-gray-400">No schedules configured.</p>
          ) : (
            <div className="divide-y divide-gray-100">
              {schedules.map(s => (
                <div key={s.schedule_id} className="py-3 flex items-center gap-4">
                  <Calendar size={16} className={s.enabled ? 'text-green-500' : 'text-gray-400'} />
                  <div className="flex-1">
                    <div className="text-sm font-medium text-gray-900">{s.domain} — {s.scope}</div>
                    <div className="text-xs text-gray-500 font-mono">{s.cron_expression}</div>
                  </div>
                  <span className={clsx('text-xs px-2 py-0.5 rounded-full font-medium',
                    s.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500')}>
                    {s.enabled ? 'Active' : 'Paused'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function StatusIcon({ status }: { status: string }) {
  if (status === 'completed') return <CheckCircle size={16} className="text-green-500" />
  if (status === 'failed') return <XCircle size={16} className="text-red-500" />
  return <Loader size={16} className="text-blue-500 animate-spin" />
}
