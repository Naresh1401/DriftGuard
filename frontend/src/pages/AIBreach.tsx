import { useEffect, useState } from 'react'
import {
  Bot,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Info,
  Zap,
  BookOpen,
  TrendingUp,
  Link2,
} from 'lucide-react'

const API_BASE = (import.meta.env.VITE_API_URL || '/api/v1').replace(/\/$/, '')

interface Pattern {
  pattern: string
  display_name: string
  description: string
  owasp_llm_id: string
  nist_ai_rmf_function: string
  nist_controls_at_risk: string[]
  signal_indicators: string[]
  failure_modes: string[]
  plain_language_summary: string
  base_severity: number
  mitigation_repo_path: string
}

interface Detection {
  id: string
  pattern: string
  display_name: string
  owasp_llm_id: string
  nist_ai_rmf_function: string
  nist_controls_at_risk: string[]
  confidence: number
  severity: number
  risk_score: number
  reasoning: string
  plain_language_summary: string
  mitigation_repo_path: string
  requires_human_review: boolean
  detected_at: string
}

interface RiskResponse {
  overall_risk_score: number
  alert_level: 'Watch' | 'Warning' | 'Critical'
  active_patterns: number
  patterns: Detection[]
}

interface PlaybookStep {
  order: number
  action: string
  owner_role: string
  automatable: boolean
}

interface Playbook {
  pattern: string
  mitre_atlas_ids: string[]
  expected_dwell_reduction_hours: number
  immediate_steps: PlaybookStep[]
  short_term_steps: PlaybookStep[]
  long_term_steps: PlaybookStep[]
}

interface ForecastPoint {
  timestamp: string
  forecast: number
  lower_bound: number
  upper_bound: number
}

interface ForecastResponse {
  samples: number
  current_ewma: number
  forecast: ForecastPoint[]
  seeded?: boolean
}

const LEVEL_COLOR: Record<string, string> = {
  Watch: 'bg-emerald-100 text-emerald-700 border-emerald-300',
  Warning: 'bg-amber-100 text-amber-700 border-amber-300',
  Critical: 'bg-rose-100 text-rose-700 border-rose-300',
}

const SEV_COLOR: Record<number, string> = {
  1: 'bg-slate-100 text-slate-700',
  2: 'bg-blue-100 text-blue-700',
  3: 'bg-amber-100 text-amber-700',
  4: 'bg-orange-100 text-orange-700',
  5: 'bg-rose-100 text-rose-700',
}

export default function AIBreach() {
  const [patterns, setPatterns] = useState<Pattern[]>([])
  const [risk, setRisk] = useState<RiskResponse | null>(null)
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [forecast, setForecast] = useState<ForecastResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [openPlaybook, setOpenPlaybook] = useState<string | null>(null)
  const [audit, setAudit] = useState<{ length: number; head: string; intact: boolean } | null>(null)
  const [quarantine, setQuarantine] = useState<{ count: number; threshold: number; window_minutes: number } | null>(null)

  async function loadGovernance() {
    try {
      const [v, q] = await Promise.all([
        fetch(`${API_BASE}/ai-breach/audit/verify`).then((r) => r.json()),
        fetch(`${API_BASE}/ai-breach/quarantine`).then((r) => r.json()),
      ])
      setAudit({ length: v.length, head: v.head, intact: v.intact })
      setQuarantine({ count: q.count, threshold: q.threshold, window_minutes: q.window_minutes })
    } catch {
      /* governance is best-effort; silently ignore */
    }
  }

  async function loadAll() {
    setLoading(true)
    try {
      const [pr, pb, fc] = await Promise.all([
        fetch(`${API_BASE}/ai-breach/patterns`).then((r) => r.json()),
        fetch(`${API_BASE}/ai-breach/playbooks`).then((r) => r.json()),
        fetch(`${API_BASE}/ai-breach/forecast`).then((r) => r.json()),
      ])
      setPatterns(pr.patterns)
      setPlaybooks(pb.playbooks)
      setForecast(fc)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  async function runDemoScan() {
    setScanning(true)
    setError(null)
    try {
      const r = await fetch(`${API_BASE}/ai-breach/demo`)
      if (!r.ok) throw new Error(`demo ${r.status}`)
      setRisk(await r.json())
      const fc = await fetch(`${API_BASE}/ai-breach/forecast`).then((r) => r.json())
      setForecast(fc)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setScanning(false)
    }
  }

  useEffect(() => {
    loadAll()
    runDemoScan()
    loadGovernance()
  }, [])

  const playbookByPattern = playbooks.reduce<Record<string, Playbook>>((acc, p) => {
    acc[p.pattern] = p
    return acc
  }, {})

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-violet-100">
              <Bot className="w-6 h-6 text-violet-700" />
            </div>
            <h1 className="text-2xl font-bold text-slate-900">AI Breach Surface</h1>
          </div>
          <p className="text-sm text-slate-600 mt-2 max-w-3xl">
            Heuristic, explainable detection across the seven AI-era breach classes mapped to
            NIST AI RMF, OWASP LLM Top 10 (2025), the UK NCSC December 2025 prompt-injection
            guidance and MITRE ATLAS v4.7. DriftGuard audits AI behavior — it is not itself
            an opaque model.
          </p>
        </div>
        <button
          onClick={runDemoScan}
          disabled={scanning}
          className="flex items-center gap-2 px-4 py-2 bg-violet-600 text-white rounded-lg hover:bg-violet-700 disabled:opacity-50"
        >
          {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
          Run Demo Scan
        </button>
      </div>

      {error && (
        <div className="p-4 bg-rose-50 border border-rose-200 rounded-lg text-rose-700 text-sm">
          {error}
        </div>
      )}

      {/* Risk gauge */}
      {risk && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-6 bg-white rounded-xl border border-slate-200 shadow-sm">
            <div className="text-xs uppercase tracking-wide text-slate-500">Overall AI Risk</div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-4xl font-bold text-slate-900">
                {risk.overall_risk_score.toFixed(0)}
              </span>
              <span className="text-sm text-slate-500">/ 100</span>
            </div>
            <div className="mt-3 h-2 w-full bg-slate-100 rounded-full overflow-hidden">
              <div
                className={
                  'h-full ' +
                  (risk.overall_risk_score >= 70
                    ? 'bg-rose-500'
                    : risk.overall_risk_score >= 40
                    ? 'bg-amber-500'
                    : 'bg-emerald-500')
                }
                style={{ width: `${Math.min(risk.overall_risk_score, 100)}%` }}
              />
            </div>
          </div>
          <div className="p-6 bg-white rounded-xl border border-slate-200 shadow-sm">
            <div className="text-xs uppercase tracking-wide text-slate-500">Alert Level</div>
            <div className="mt-2">
              <span
                className={
                  'px-3 py-1.5 rounded-md border text-sm font-semibold ' +
                  (LEVEL_COLOR[risk.alert_level] || '')
                }
              >
                {risk.alert_level}
              </span>
            </div>
            <div className="text-xs text-slate-500 mt-3">
              Watch &lt; 40 · Warning 40-69 · Critical ≥ 70
            </div>
          </div>
          <div className="p-6 bg-white rounded-xl border border-slate-200 shadow-sm">
            <div className="text-xs uppercase tracking-wide text-slate-500">Active Patterns</div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-4xl font-bold text-slate-900">{risk.active_patterns}</span>
              <span className="text-sm text-slate-500">/ 7</span>
            </div>
          </div>
        </div>
      )}

      {/* Forecast strip */}
      {forecast && forecast.forecast.length > 0 && (
        <div className="p-5 bg-white rounded-xl border border-slate-200 shadow-sm">
          <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2 mb-3">
            <TrendingUp className="w-4 h-4 text-violet-600" />
            24-Hour AI Risk Forecast
            <span className="text-xs font-normal text-slate-500">
              (EWMA · {forecast.samples} samples · current {forecast.current_ewma.toFixed(0)})
            </span>
          </h2>
          <div className="flex items-end gap-1 h-24">
            {forecast.forecast.map((p, i) => {
              const h = Math.max(4, p.forecast)
              const colour =
                p.forecast >= 70
                  ? 'bg-rose-400'
                  : p.forecast >= 40
                  ? 'bg-amber-400'
                  : 'bg-emerald-400'
              return (
                <div
                  key={i}
                  className="flex-1 flex flex-col items-center gap-1"
                  title={`t+${i + 1}h: ${p.forecast} (${p.lower_bound}–${p.upper_bound})`}
                >
                  <div className={`w-full rounded-t ${colour}`} style={{ height: `${h}%` }} />
                </div>
              )
            })}
          </div>
          <div className="text-xs text-slate-500 mt-2">
            Forecast widens by √t; numeric values on hover. Updated each scan.
          </div>
        </div>
      )}

      {/* Detections */}
      {risk && risk.patterns.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-lg font-semibold text-slate-900 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rose-600" />
            Active Detections
          </h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {risk.patterns.map((d) => (
              <div key={d.id} className="p-5 bg-white rounded-xl border border-slate-200 shadow-sm">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="font-semibold text-slate-900">{d.display_name}</h3>
                      <span className="text-xs px-2 py-0.5 rounded bg-violet-100 text-violet-700 font-mono">
                        {d.owasp_llm_id}
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded bg-slate-100 text-slate-700">
                        {d.nist_ai_rmf_function}
                      </span>
                      <span className={'text-xs px-2 py-0.5 rounded ' + SEV_COLOR[d.severity]}>
                        Severity {d.severity}
                      </span>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-2xl font-bold text-slate-900">
                      {d.risk_score.toFixed(0)}
                    </div>
                    <div className="text-xs text-slate-500">risk</div>
                  </div>
                </div>
                <p className="mt-3 text-sm text-slate-700">{d.reasoning}</p>
                <div className="mt-3 flex items-center gap-2 text-xs text-slate-500 flex-wrap">
                  <span>Confidence {Math.round(d.confidence * 100)}%</span>
                  <span>·</span>
                  <span>NIST: {d.nist_controls_at_risk.join(', ')}</span>
                  {d.requires_human_review && (
                    <>
                      <span>·</span>
                      <span className="text-amber-700 font-semibold flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3" /> Needs human review
                      </span>
                    </>
                  )}
                </div>
                {playbookByPattern[d.pattern] && (
                  <button
                    onClick={() =>
                      setOpenPlaybook(openPlaybook === d.pattern ? null : d.pattern)
                    }
                    className="mt-3 text-xs flex items-center gap-1 text-violet-700 hover:text-violet-900 font-semibold"
                  >
                    <BookOpen className="w-3 h-3" />
                    {openPlaybook === d.pattern ? 'Hide' : 'Show'} mitigation playbook · saves
                    est. {playbookByPattern[d.pattern].expected_dwell_reduction_hours}h dwell
                  </button>
                )}
                {openPlaybook === d.pattern && playbookByPattern[d.pattern] && (
                  <PlaybookView pb={playbookByPattern[d.pattern]} />
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {risk && risk.patterns.length === 0 && (
        <div className="p-6 bg-emerald-50 border border-emerald-200 rounded-xl flex items-center gap-3 text-emerald-800">
          <CheckCircle2 className="w-5 h-5" />
          No AI breach patterns detected in the last scan window.
        </div>
      )}

      {/* Governance: tamper-evident audit chain + agent quarantine */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-5 bg-white rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between">
            <div className="text-xs uppercase tracking-wide text-slate-500">Tamper-Evident Audit Chain</div>
            {audit && (
              <span className={`text-xs px-2 py-0.5 rounded-full ${audit.intact ? 'bg-emerald-100 text-emerald-700' : 'bg-rose-100 text-rose-700'}`}>
                {audit.intact ? 'INTACT' : 'BROKEN'}
              </span>
            )}
          </div>
          <div className="mt-3 text-3xl font-bold text-slate-900">{audit?.length ?? 0}</div>
          <div className="text-xs text-slate-500">hash-linked detections</div>
          {audit && (
            <div className="mt-2 text-[10px] font-mono text-slate-400 truncate" title={audit.head}>
              head: {audit.head.slice(0, 32)}…
            </div>
          )}
          <p className="mt-3 text-xs text-slate-600">
            Every AI-breach detection is appended to a SHA-256 chain. Backs NIST AI RMF GOVERN-1.4
            and the EU AI Act Art. 12 logging obligation for high-risk systems.
          </p>
        </div>
        <div className="p-5 bg-white rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between">
            <div className="text-xs uppercase tracking-wide text-slate-500">Agent Circuit Breaker</div>
            {quarantine && (
              <span className={`text-xs px-2 py-0.5 rounded-full ${quarantine.count > 0 ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-600'}`}>
                {quarantine.count} quarantined
              </span>
            )}
          </div>
          <div className="mt-3 text-3xl font-bold text-slate-900">{quarantine?.count ?? 0}</div>
          <div className="text-xs text-slate-500">
            {quarantine ? `threshold ${quarantine.threshold} risk / ${quarantine.window_minutes}m window` : 'rolling per-actor budget'}
          </div>
          <p className="mt-3 text-xs text-slate-600">
            When an actor's cumulative AI-breach risk crosses the budget the circuit breaker trips
            a structured kill-switch record. Action stays with the human-review gate by design.
          </p>
        </div>
      </div>

      {/* Pattern catalogue */}
      <div className="space-y-3">
        <h2 className="text-lg font-semibold text-slate-900 flex items-center gap-2">
          <Info className="w-5 h-5 text-slate-600" />
          AI Breach Pattern Catalogue
        </h2>
        {loading && <div className="text-sm text-slate-500">Loading patterns…</div>}
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {patterns.map((p) => (
            <div key={p.pattern} className="p-4 bg-white rounded-xl border border-slate-200 shadow-sm">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="font-semibold text-slate-900">{p.display_name}</h3>
                <span className="text-xs px-2 py-0.5 rounded bg-violet-100 text-violet-700 font-mono">
                  {p.owasp_llm_id}
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-slate-100 text-slate-700">
                  {p.nist_ai_rmf_function}
                </span>
              </div>
              <p className="mt-2 text-sm text-slate-700">{p.plain_language_summary}</p>
              <div className="mt-3 text-xs text-slate-500">
                <div>
                  <span className="font-semibold text-slate-600">Indicators:</span>{' '}
                  {p.signal_indicators.slice(0, 3).join(' · ')}
                </div>
                <div className="mt-1">
                  <span className="font-semibold text-slate-600">NIST controls:</span>{' '}
                  {p.nist_controls_at_risk.join(', ')}
                </div>
                <div className="mt-1">
                  <span className="font-semibold text-slate-600">Mitigation:</span>{' '}
                  <code className="text-violet-700">{p.mitigation_repo_path}</code>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="text-xs text-slate-500 italic">
        Sources: NIST AI RMF 1.0 + Generative AI Profile (NIST AI 600-1) · OWASP Top 10 for LLM
        Applications (2025) · UK NCSC December 2025 prompt-injection guidance · MITRE ATLAS v4.7.
      </div>
    </div>
  )
}

function PlaybookView({ pb }: { pb: Playbook }) {
  return (
    <div className="mt-3 p-3 rounded-lg bg-violet-50 border border-violet-200 space-y-3">
      <div className="flex items-center gap-2 flex-wrap text-xs">
        <Link2 className="w-3 h-3 text-violet-700" />
        <span className="font-semibold text-violet-900">MITRE ATLAS:</span>
        {pb.mitre_atlas_ids.map((id) => (
          <span
            key={id}
            className="px-1.5 py-0.5 rounded bg-white border border-violet-300 font-mono text-violet-800"
          >
            {id}
          </span>
        ))}
      </div>
      <PlaybookSteps title="Immediate (0-1h)" steps={pb.immediate_steps} />
      <PlaybookSteps title="Short-term (1-7d)" steps={pb.short_term_steps} />
      <PlaybookSteps title="Long-term (>7d)" steps={pb.long_term_steps} />
    </div>
  )
}

function PlaybookSteps({ title, steps }: { title: string; steps: PlaybookStep[] }) {
  return (
    <div>
      <div className="text-xs font-semibold text-violet-900 mb-1">{title}</div>
      <ol className="space-y-1">
        {steps.map((s) => (
          <li key={s.order} className="text-xs text-slate-700 flex items-start gap-2">
            <span className="w-4 h-4 rounded-full bg-violet-200 text-violet-900 text-[10px] font-bold flex items-center justify-center flex-shrink-0 mt-0.5">
              {s.order}
            </span>
            <div className="flex-1">
              <div>{s.action}</div>
              <div className="text-[10px] text-slate-500 mt-0.5">
                {s.owner_role.replace('_', ' ')}
                {s.automatable && <span className="ml-1 text-emerald-700">· automatable</span>}
              </div>
            </div>
          </li>
        ))}
      </ol>
    </div>
  )
}
