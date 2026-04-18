import { useEffect, useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { LoadingSpinner } from '../components/Shared'
import type { DomainConfig } from '../types'
import { Globe, Activity, Upload, Lock } from 'lucide-react'
import clsx from 'clsx'

const SENSITIVITY_COLORS: Record<string, string> = {
  conservative: 'bg-blue-100 text-blue-700',
  balanced: 'bg-green-100 text-green-700',
  aggressive: 'bg-orange-100 text-orange-700',
}

export default function Domains() {
  const { can } = useAuth()
  const [domains, setDomains] = useState<DomainConfig[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      try {
        const data = await api.getDomains()
        if (!cancelled) setDomains(data)
      } catch (err) {
        console.error('Failed to load domains:', err)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  if (!can('view_domains')) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-gray-400">
        <Lock size={48} className="mb-4" />
        <h2 className="text-lg font-semibold text-gray-600">Access Restricted</h2>
        <p className="text-sm mt-1">Domain configuration requires Administrator or CISO access.</p>
      </div>
    )
  }

  if (loading) return <LoadingSpinner />

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Domain Configuration</h1>
          <p className="text-sm text-gray-500 mt-1">
            YAML-driven domain adapters — configure signal mappings per vertical
          </p>
        </div>
        {can('manage_domains') && (
          <button className="btn-primary flex items-center gap-2">
            <Upload size={16} /> Upload YAML
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {domains.map((domain) => (
          <div
            key={domain.domain}
            className="card transition-all hover:shadow-md border-l-4 border-l-drift-500"
          >
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2 rounded-lg bg-drift-50">
                <Globe size={20} className="text-drift-700" />
              </div>
              <div>
                <h3 className="font-semibold text-gray-900">{domain.display_name}</h3>
                <span className={clsx(
                  'inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded font-medium',
                  SENSITIVITY_COLORS[domain.sensitivity] || 'bg-gray-100 text-gray-600'
                )}>
                  {domain.sensitivity}
                </span>
              </div>
            </div>

            <p className="text-sm text-gray-600 mb-4">{domain.description}</p>

            <div className="flex items-center gap-2 text-sm text-gray-500">
              <Activity size={14} />
              <span>{domain.signal_count} signal types configured</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
