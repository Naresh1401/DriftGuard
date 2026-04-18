import { useEffect, useState, useRef } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { LoadingSpinner } from '../components/Shared'
import type { DomainConfig, BreachAnalysis } from '../types'
import { Globe, Activity, Upload, Lock, X, ChevronDown, ChevronUp, CheckCircle, AlertCircle, Search, Shield, ShieldAlert, ShieldCheck, ExternalLink } from 'lucide-react'
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
  const [analyzeUrl, setAnalyzeUrl] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [analysis, setAnalysis] = useState<BreachAnalysis | null>(null)
  const [analyzeError, setAnalyzeError] = useState<string | null>(null)

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

  const handleAnalyze = async () => {
    let url = analyzeUrl.trim()
    if (!url) return
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url
    setAnalyzing(true)
    setAnalysis(null)
    setAnalyzeError(null)
    try {
      const result = await api.analyzeUrl(url)
      setAnalysis(result)
    } catch (err) {
      setAnalyzeError(err instanceof Error ? err.message : 'Analysis failed')
    } finally {
      setAnalyzing(false)
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

      {/* ── Breach Analyzer ──────────────────────────────── */}
      <div className="card border border-gray-200">
        <div className="flex items-center gap-3 mb-3">
          <div className="p-2 rounded-lg bg-red-50">
            <ShieldAlert size={20} className="text-red-600" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Website Breach Analyzer</h2>
            <p className="text-xs text-gray-500">Enter a URL to analyze its security posture — SSL, headers, cookies, NIST mapping</p>
          </div>
        </div>

        <div className="flex gap-2">
          <div className="flex-1 relative">
            <input
              type="text"
              value={analyzeUrl}
              onChange={(e) => setAnalyzeUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAnalyze()}
              placeholder="https://example.com"
              className="w-full px-4 py-2.5 pr-10 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-drift-500 focus:border-drift-500"
            />
            <Globe size={16} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400" />
          </div>
          <button
            onClick={handleAnalyze}
            disabled={!analyzeUrl.trim() || analyzing}
            className="btn-primary flex items-center gap-2 disabled:opacity-50 whitespace-nowrap"
          >
            {analyzing ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Search size={16} /> Analyze
              </>
            )}
          </button>
        </div>

        {analyzeError && (
          <div className="mt-3 flex items-center gap-2 p-3 rounded-lg bg-red-50 text-red-800 text-sm">
            <AlertCircle size={16} />
            {analyzeError}
          </div>
        )}

        {analysis && <BreachReport analysis={analysis} />}
      </div>

      {/* ── Domain Cards ─────────────────────────────────── */}

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

/* ═══════════════════════════════════════════════════════
   BREACH ANALYSIS REPORT
   ═══════════════════════════════════════════════════════ */

const GRADE_COLORS: Record<string, string> = {
  A: 'bg-green-500',
  B: 'bg-green-400',
  C: 'bg-yellow-400',
  D: 'bg-orange-500',
  F: 'bg-red-500',
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
}

function BreachReport({ analysis }: { analysis: BreachAnalysis }) {
  const [showAllFindings, setShowAllFindings] = useState(false)
  const visibleFindings = showAllFindings ? analysis.findings : analysis.findings.slice(0, 5)

  return (
    <div className="mt-6 space-y-5">
      {/* Score + Summary bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 p-4 bg-gray-50 rounded-xl border border-gray-200">
        <div className="flex items-center gap-4">
          <div className={clsx(
            'w-16 h-16 rounded-xl flex items-center justify-center text-white text-2xl font-bold shadow-sm',
            GRADE_COLORS[analysis.grade] || 'bg-gray-400'
          )}>
            {analysis.grade}
          </div>
          <div>
            <div className="text-2xl font-bold text-gray-900">{analysis.security_score}<span className="text-sm font-normal text-gray-500">/100</span></div>
            <p className="text-xs text-gray-500">Security Score</p>
          </div>
        </div>

        <div className="flex-1 grid grid-cols-2 sm:grid-cols-4 gap-3 sm:ml-6">
          <MiniStat label="Critical" value={analysis.summary.critical} color="text-red-600" />
          <MiniStat label="High" value={analysis.summary.high} color="text-orange-600" />
          <MiniStat label="Medium" value={analysis.summary.medium} color="text-yellow-600" />
          <MiniStat label="Low" value={analysis.summary.low} color="text-blue-600" />
        </div>

        <div className="text-right text-xs text-gray-400 sm:ml-4 shrink-0">
          <a href={analysis.url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-drift-600 hover:text-drift-800 mb-1">
            {analysis.hostname} <ExternalLink size={12} />
          </a>
          <div>HTTP {analysis.status_code}</div>
          <div>{new Date(analysis.analyzed_at).toLocaleString()}</div>
        </div>
      </div>

      {/* SSL Certificate */}
      {analysis.ssl && (
        <div className="card">
          <div className="flex items-center gap-2 mb-3">
            {analysis.ssl.valid
              ? <ShieldCheck size={18} className="text-green-600" />
              : <ShieldAlert size={18} className="text-red-600" />
            }
            <h3 className="text-sm font-semibold text-gray-800">SSL / TLS Certificate</h3>
          </div>
          {analysis.ssl.valid ? (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              <div>
                <span className="text-gray-500 block">Protocol</span>
                <span className="font-medium text-gray-800">{analysis.ssl.protocol}</span>
              </div>
              <div>
                <span className="text-gray-500 block">Issuer</span>
                <span className="font-medium text-gray-800">{analysis.ssl.issuer}</span>
              </div>
              <div>
                <span className="text-gray-500 block">Expires</span>
                <span className="font-medium text-gray-800">
                  {analysis.ssl.expires ? new Date(analysis.ssl.expires).toLocaleDateString() : '—'}
                </span>
              </div>
              <div>
                <span className="text-gray-500 block">Days Remaining</span>
                <span className={clsx(
                  'font-medium',
                  (analysis.ssl.days_remaining ?? 0) > 30 ? 'text-green-700' : 'text-orange-600'
                )}>
                  {analysis.ssl.days_remaining}
                </span>
              </div>
            </div>
          ) : (
            <p className="text-sm text-red-700">{analysis.ssl.error || 'Certificate is invalid'}</p>
          )}
        </div>
      )}

      {/* Security Headers */}
      <div className="card">
        <div className="flex items-center gap-2 mb-3">
          <Shield size={18} className="text-drift-700" />
          <h3 className="text-sm font-semibold text-gray-800">Security Headers</h3>
          <span className="ml-auto text-xs text-gray-400">
            {analysis.headers.filter(h => h.present).length}/{analysis.headers.length} present
          </span>
        </div>
        <div className="divide-y divide-gray-100">
          {analysis.headers.map((h) => (
            <div key={h.header} className="py-2 flex items-center gap-3">
              {h.present
                ? <CheckCircle size={14} className="text-green-500 shrink-0" />
                : <AlertCircle size={14} className="text-red-400 shrink-0" />
              }
              <span className="text-sm text-gray-800 flex-1">{h.header}</span>
              {h.present && h.value && (
                <span className="text-xs text-gray-500 truncate max-w-48 hidden md:block font-mono">{h.value}</span>
              )}
              <span className={clsx(
                'text-[10px] px-1.5 py-0.5 rounded border font-medium shrink-0',
                SEVERITY_BADGE[h.severity]
              )}>
                {h.severity}
              </span>
              <span className="text-[10px] font-mono text-gray-400 w-10 text-right shrink-0">{h.nist_control}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Findings */}
      {analysis.findings.length > 0 && (
        <div className="card">
          <div className="flex items-center gap-2 mb-3">
            <ShieldAlert size={18} className="text-red-600" />
            <h3 className="text-sm font-semibold text-gray-800">Findings ({analysis.findings.length})</h3>
          </div>
          <div className="space-y-2">
            {visibleFindings.map((f, i) => (
              <div key={i} className="p-3 rounded-lg bg-gray-50 border border-gray-100">
                <div className="flex items-start justify-between gap-2 mb-1">
                  <h4 className="text-sm font-medium text-gray-900">{f.title}</h4>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <span className={clsx(
                      'text-[10px] px-1.5 py-0.5 rounded border font-medium',
                      SEVERITY_BADGE[f.severity]
                    )}>
                      {f.severity}
                    </span>
                    <span className="text-[10px] font-mono text-gray-400">{f.nist_control}</span>
                  </div>
                </div>
                <p className="text-xs text-gray-600 mb-1">{f.description}</p>
                <p className="text-xs text-drift-700">
                  <strong>Fix:</strong> {f.recommendation}
                </p>
              </div>
            ))}
          </div>
          {analysis.findings.length > 5 && (
            <button
              onClick={() => setShowAllFindings(!showAllFindings)}
              className="mt-3 text-xs text-drift-600 hover:text-drift-800"
            >
              {showAllFindings ? 'Show less' : `Show all ${analysis.findings.length} findings`}
            </button>
          )}
        </div>
      )}
    </div>
  )
}

function MiniStat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="text-center">
      <div className={clsx('text-lg font-bold', color)}>{value}</div>
      <div className="text-[10px] text-gray-500">{label}</div>
    </div>
  )
}
