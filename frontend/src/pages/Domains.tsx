import { useEffect, useState, useRef } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { LoadingSpinner } from '../components/Shared'
import type { DomainConfig } from '../types'
import { Globe, Activity, Upload, Lock, X, ChevronDown, ChevronUp, CheckCircle, AlertCircle } from 'lucide-react'
import clsx from 'clsx'

const SENSITIVITY_COLORS: Record<string, string> = {
  conservative: 'bg-blue-100 text-blue-700',
  balanced: 'bg-green-100 text-green-700',
  aggressive: 'bg-orange-100 text-orange-700',
}

const SAMPLE_YAML = `domain: my_custom_domain
display_name: My Custom Domain
description: Description of your domain vertical
alert_sensitivity: balanced  # conservative | balanced | aggressive
signals:
  - type: login_attempts
    maps_to: [Fatigue, Overconfidence]
    nist_controls: [AC-2, AU-6]
    description: Track login patterns and failures
    source_connector: custom`

export default function Domains() {
  const { can } = useAuth()
  const [domains, setDomains] = useState<DomainConfig[]>([])
  const [loading, setLoading] = useState(true)
  const [showUpload, setShowUpload] = useState(false)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [expandedDetail, setExpandedDetail] = useState<DomainConfig | null>(null)

  const loadDomains = async () => {
    setLoading(true)
    try {
      const data = await api.getDomains()
      setDomains(data)
    } catch (err) {
      console.error('Failed to load domains:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadDomains()
  }, [])

  const handleExpand = async (domainName: string) => {
    if (expanded === domainName) {
      setExpanded(null)
      setExpandedDetail(null)
      return
    }
    setExpanded(domainName)
    try {
      const detail = await api.getDomain(domainName)
      setExpandedDetail(detail)
    } catch {
      setExpandedDetail(null)
    }
  }

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
          <button onClick={() => setShowUpload(true)} className="btn-primary flex items-center gap-2">
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

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm text-gray-500">
                <Activity size={14} />
                <span>{domain.signal_count} signal types configured</span>
              </div>
              <button
                onClick={() => handleExpand(domain.domain)}
                className="text-xs text-drift-600 hover:text-drift-800 flex items-center gap-1"
              >
                {expanded === domain.domain ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                {expanded === domain.domain ? 'Less' : 'Details'}
              </button>
            </div>

            {expanded === domain.domain && expandedDetail && (
              <div className="mt-4 pt-4 border-t border-gray-100 space-y-3">
                {expandedDetail.signals?.map((sig) => (
                  <div key={sig.type} className="text-xs space-y-1">
                    <div className="font-medium text-gray-800">{sig.type.replace(/_/g, ' ')}</div>
                    <p className="text-gray-500">{sig.description}</p>
                    <div className="flex flex-wrap gap-1">
                      {sig.maps_to.map((p) => (
                        <span key={p} className="px-1.5 py-0.5 bg-purple-50 text-purple-700 rounded text-[10px]">
                          {p}
                        </span>
                      ))}
                      {sig.nist_controls.map((c) => (
                        <span key={c} className="px-1.5 py-0.5 bg-red-50 text-red-700 rounded font-mono text-[10px]">
                          {c}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {showUpload && (
        <UploadModal
          onClose={() => setShowUpload(false)}
          onUploaded={() => {
            setShowUpload(false)
            loadDomains()
          }}
        />
      )}
    </div>
  )
}

function UploadModal({ onClose, onUploaded }: { onClose: () => void; onUploaded: () => void }) {
  const [yaml, setYaml] = useState('')
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const text = await file.text()
    setYaml(text)
    setResult(null)
  }

  const handleUpload = async () => {
    if (!yaml.trim()) return
    setUploading(true)
    setResult(null)
    try {
      const res = await api.uploadDomainYaml(yaml)
      setResult({ ok: true, message: `Domain "${res.domain}" uploaded successfully.` })
      setTimeout(onUploaded, 1200)
    } catch (err) {
      setResult({ ok: false, message: err instanceof Error ? err.message : 'Upload failed' })
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Upload Domain Configuration</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X size={20} />
          </button>
        </div>

        <div className="p-4 space-y-4 flex-1 overflow-auto">
          <p className="text-sm text-gray-600">
            Paste YAML content below or upload a <code>.yaml</code> file. The domain will be registered immediately.
          </p>

          <div className="flex gap-2">
            <input
              ref={fileRef}
              type="file"
              accept=".yaml,.yml"
              onChange={handleFileSelect}
              className="hidden"
            />
            <button
              onClick={() => fileRef.current?.click()}
              className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Choose File
            </button>
            <button
              onClick={() => { setYaml(SAMPLE_YAML); setResult(null) }}
              className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 text-gray-600"
            >
              Load Sample
            </button>
          </div>

          <textarea
            value={yaml}
            onChange={(e) => { setYaml(e.target.value); setResult(null) }}
            placeholder="Paste YAML domain configuration here..."
            className="w-full h-64 font-mono text-sm p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-drift-500 focus:border-drift-500 resize-none"
            spellCheck={false}
          />

          {result && (
            <div className={clsx(
              'flex items-center gap-2 p-3 rounded-lg text-sm',
              result.ok ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800'
            )}>
              {result.ok ? <CheckCircle size={16} /> : <AlertCircle size={16} />}
              {result.message}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-3 p-4 border-t border-gray-200">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-600 hover:text-gray-800">
            Cancel
          </button>
          <button
            onClick={handleUpload}
            disabled={!yaml.trim() || uploading}
            className="btn-primary flex items-center gap-2 disabled:opacity-50"
          >
            {uploading ? 'Uploading...' : 'Upload Domain'}
          </button>
        </div>
      </div>
    </div>
  )
}
