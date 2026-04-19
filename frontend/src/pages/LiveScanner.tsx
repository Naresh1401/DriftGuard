import { useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import type { LiveScanResult } from '../types'
import {
  Scan, Shield, Lock, Globe, Server, Wifi, Cookie, Code2,
  CheckCircle, XCircle, AlertTriangle, AlertCircle, Info, Clock,
  ChevronDown,
} from 'lucide-react'
import clsx from 'clsx'

const SEV = {
  critical: { bg: 'bg-red-100 text-red-800', dot: 'bg-red-500' },
  high:     { bg: 'bg-orange-100 text-orange-800', dot: 'bg-orange-500' },
  medium:   { bg: 'bg-yellow-100 text-yellow-800', dot: 'bg-yellow-500' },
  low:      { bg: 'bg-blue-100 text-blue-700', dot: 'bg-blue-400' },
  info:     { bg: 'bg-gray-100 text-gray-600', dot: 'bg-gray-400' },
} as const

const GRADE_STYLE: Record<string, string> = {
  A: 'from-green-500 to-green-600', B: 'from-green-400 to-green-500',
  C: 'from-yellow-400 to-yellow-500', D: 'from-orange-400 to-orange-500',
  F: 'from-red-500 to-red-600',
}

const CATEGORY_ICONS: Record<string, typeof Shield> = {
  transport: Lock, certificate: Shield, headers: Server,
  cookies: Cookie, dns: Globe, ports: Wifi, disclosure: Code2,
}

export default function LiveScanner() {
  const { can } = useAuth()
  const [url, setUrl] = useState('')
  const [scanPorts, setScanPorts] = useState(true)
  const [scanDns, setScanDns] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<LiveScanResult | null>(null)

  if (!can('view_domains')) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-gray-400">
        <Lock size={48} className="mb-4" />
        <h2 className="text-lg font-semibold text-gray-600">Access Restricted</h2>
      </div>
    )
  }

  const scan = async () => {
    if (!url.trim()) return
    setLoading(true); setError(null); setResult(null)
    try {
      setResult(await api.liveScan(url.trim(), scanPorts, scanDns))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Live Security Scanner</h1>
        <p className="text-sm text-gray-500 mt-1">
          Real-time security analysis of any website — SSL, headers, DNS, ports, cookies, and technology fingerprinting. All data is fetched live.
        </p>
      </div>

      {/* Input bar */}
      <div className="card border border-gray-200">
        <div className="flex flex-col sm:flex-row gap-3 sm:items-end">
          <div className="flex-1">
            <label className="text-xs text-gray-500 block mb-1">Target URL</label>
            <input
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && scan()}
              placeholder="https://example.com"
              className="w-full px-4 py-2.5 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-drift-500 focus:border-drift-500 font-mono"
              disabled={loading}
            />
          </div>
          <div className="flex flex-wrap items-center gap-4 pb-0.5">
            <label className="flex items-center gap-1.5 text-xs text-gray-600 cursor-pointer">
              <input type="checkbox" checked={scanPorts} onChange={e => setScanPorts(e.target.checked)} className="rounded" disabled={loading} />
              Port Scan
            </label>
            <label className="flex items-center gap-1.5 text-xs text-gray-600 cursor-pointer">
              <input type="checkbox" checked={scanDns} onChange={e => setScanDns(e.target.checked)} className="rounded" disabled={loading} />
              DNS Analysis
            </label>
            <button
              onClick={scan}
              disabled={!url.trim() || loading}
              className="btn-primary flex items-center gap-2 disabled:opacity-50 whitespace-nowrap"
            >
              <Scan size={14} className={loading ? 'animate-spin' : ''} />
              {loading ? 'Scanning...' : 'Scan Now'}
            </button>
          </div>
        </div>
      </div>

      {loading && <ScanProgress />}
      {error && <div className="flex items-center gap-2 p-3 rounded-lg bg-red-50 text-red-800 text-sm"><AlertCircle size={16} /> {error}</div>}
      {result && <ScanResults data={result} />}
    </div>
  )
}


function ScanProgress() {
  return (
    <div className="card border border-drift-200 bg-drift-50/30">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-full bg-drift-100 flex items-center justify-center animate-pulse">
          <Scan size={16} className="text-drift-700 animate-spin" />
        </div>
        <div>
          <p className="text-sm font-medium text-gray-800">Scanning target...</p>
          <p className="text-xs text-gray-500">Checking SSL, headers, DNS records, open ports, and technologies</p>
        </div>
      </div>
    </div>
  )
}


function ScanResults({ data }: { data: LiveScanResult }) {
  return (
    <div className="space-y-4">
      {/* Top summary bar */}
      <div className="card border border-gray-200">
        <div className="flex items-center gap-6 flex-wrap">
          {/* Grade circle */}
          <div className={clsx(
            'w-20 h-20 rounded-2xl bg-gradient-to-br flex items-center justify-center text-white text-3xl font-black shadow-lg',
            GRADE_STYLE[data.grade] || 'from-gray-400 to-gray-500'
          )}>
            {data.grade}
          </div>

          {/* Score + meta */}
          <div className="flex-1 min-w-0">
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold text-gray-900">{data.security_score}</span>
              <span className="text-sm text-gray-400">/100</span>
            </div>
            <div className="flex items-center gap-3 mt-1 text-xs text-gray-500 flex-wrap">
              <span className="font-mono">{data.hostname}</span>
              <span>HTTP {data.status_code}</span>
              <span className="flex items-center gap-1"><Clock size={10} /> {data.duration_ms}ms</span>
              <span>{new Date(data.scanned_at).toLocaleString()}</span>
            </div>
            {data.redirect_chain.length > 0 && (
              <div className="text-[10px] text-gray-400 mt-1">
                Redirects: {data.redirect_chain.join(' → ')}
              </div>
            )}
          </div>

          {/* Severity pills */}
          <div className="flex gap-2">
            {data.summary.critical > 0 && <SevPill sev="critical" count={data.summary.critical} />}
            {data.summary.high > 0 && <SevPill sev="high" count={data.summary.high} />}
            {data.summary.medium > 0 && <SevPill sev="medium" count={data.summary.medium} />}
            {data.summary.low > 0 && <SevPill sev="low" count={data.summary.low} />}
            {data.summary.info > 0 && <SevPill sev="info" count={data.summary.info} />}
          </div>
        </div>
      </div>

      {/* Grid of sections */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SSLSection ssl={data.ssl} />
        <HeadersSection headers={data.headers} />
        {data.dns && <DNSSection dns={data.dns} />}
        {data.open_ports.length > 0 && <PortsSection ports={data.open_ports} />}
        {data.cookies.length > 0 && <CookiesSection cookies={data.cookies} />}
        {data.technologies.length > 0 && <TechSection techs={data.technologies} />}
      </div>

      {/* Findings table */}
      <FindingsSection findings={data.findings} />

      {/* IP / Network info */}
      {data.ip_addresses.length > 0 && (
        <div className="card border border-gray-200">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Resolved IP Addresses</h3>
          <div className="flex gap-2 flex-wrap">
            {data.ip_addresses.map(ip => (
              <span key={ip} className="px-2 py-1 bg-gray-50 rounded font-mono text-xs text-gray-700">{ip}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}


function SevPill({ sev, count }: { sev: string; count: number }) {
  const style = SEV[sev as keyof typeof SEV] || SEV.info
  return (
    <span className={clsx('px-2.5 py-1 rounded-full text-xs font-semibold', style.bg)}>
      {count} {sev}
    </span>
  )
}


/* ── SSL Section ───────────────────────────────────── */

function SSLSection({ ssl }: { ssl: LiveScanResult['ssl'] }) {
  if (!ssl) {
    return (
      <div className="card border-l-4 border-red-500">
        <div className="flex items-center gap-2 mb-2">
          <Lock size={16} className="text-red-500" />
          <h3 className="text-sm font-semibold text-gray-800">SSL / TLS</h3>
        </div>
        <p className="text-sm text-red-600">No HTTPS — connection is unencrypted</p>
      </div>
    )
  }

  const borderColor = ssl.valid ? (ssl.expiring_soon ? 'border-yellow-400' : 'border-green-500') : 'border-red-500'

  return (
    <div className={clsx('card border-l-4', borderColor)}>
      <div className="flex items-center gap-2 mb-3">
        <Lock size={16} className={ssl.valid ? 'text-green-600' : 'text-red-500'} />
        <h3 className="text-sm font-semibold text-gray-800">SSL / TLS Certificate</h3>
        {ssl.valid
          ? <CheckCircle size={14} className="text-green-500" />
          : <XCircle size={14} className="text-red-500" />}
      </div>

      {ssl.error ? (
        <p className="text-sm text-red-600">{ssl.error}</p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5 text-xs">
          <Row label="Protocol" value={ssl.protocol || '—'} />
          <Row label="Cipher" value={ssl.cipher ? `${ssl.cipher} (${ssl.cipher_bits}‑bit)` : '—'} />
          <Row label="Issuer" value={`${ssl.issuer_org} (${ssl.issuer_cn})`} />
          <Row label="Subject" value={ssl.subject_cn || '—'} />
          <Row label="Valid From" value={ssl.not_before ? new Date(ssl.not_before).toLocaleDateString() : '—'} />
          <Row label="Expires" value={ssl.expires ? `${new Date(ssl.expires).toLocaleDateString()} (${ssl.days_remaining}d)` : '—'} />
          {ssl.san && ssl.san.length > 0 && (
            <div className="col-span-2 mt-1">
              <span className="text-gray-500">SANs:</span>
              <span className="ml-1 text-gray-700">{ssl.san.slice(0, 5).join(', ')}{ssl.san.length > 5 ? ` +${ssl.san.length - 5} more` : ''}</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}


/* ── Headers Section ───────────────────────────────── */

function HeadersSection({ headers }: { headers: LiveScanResult['headers'] }) {
  const present = headers.filter(h => h.present).length

  return (
    <div className="card border-l-4 border-gray-300">
      <div className="flex items-center gap-2 mb-3">
        <Server size={16} className="text-gray-600" />
        <h3 className="text-sm font-semibold text-gray-800">Security Headers</h3>
        <span className="text-xs text-gray-500 ml-auto">{present}/{headers.length} present</span>
      </div>
      <div className="space-y-1.5">
        {headers.map(h => (
          <div key={h.key} className="flex items-center gap-2 text-xs">
            {h.present
              ? <CheckCircle size={12} className="text-green-500 shrink-0" />
              : <XCircle size={12} className="text-red-400 shrink-0" />}
            <span className={clsx('font-medium', h.present ? 'text-gray-800' : 'text-gray-500')}>{h.header}</span>
            {h.present && h.value && (
              <span className="text-gray-400 truncate max-w-[200px] ml-auto" title={h.value}>{h.value}</span>
            )}
            <span className="text-[10px] text-gray-400 shrink-0">{h.nist_control}</span>
          </div>
        ))}
      </div>
    </div>
  )
}


/* ── DNS Section ───────────────────────────────────── */

function DNSSection({ dns }: { dns: NonNullable<LiveScanResult['dns']> }) {
  const spfOk = !!dns.spf
  const dmarcOk = !!dns.dmarc

  return (
    <div className="card border-l-4 border-indigo-300">
      <div className="flex items-center gap-2 mb-3">
        <Globe size={16} className="text-indigo-600" />
        <h3 className="text-sm font-semibold text-gray-800">DNS & Email Security</h3>
      </div>

      <div className="space-y-3 text-xs">
        {/* SPF */}
        <div className="flex items-start gap-2">
          {spfOk ? <CheckCircle size={12} className="text-green-500 mt-0.5 shrink-0" /> : <XCircle size={12} className="text-red-400 mt-0.5 shrink-0" />}
          <div>
            <span className="font-medium text-gray-800">SPF</span>
            {dns.spf ? (
              <p className="text-gray-500 font-mono text-[10px] break-all mt-0.5">{dns.spf}</p>
            ) : (
              <p className="text-red-500 mt-0.5">Not configured — email spoofing possible</p>
            )}
          </div>
        </div>

        {/* DMARC */}
        <div className="flex items-start gap-2">
          {dmarcOk ? <CheckCircle size={12} className="text-green-500 mt-0.5 shrink-0" /> : <XCircle size={12} className="text-red-400 mt-0.5 shrink-0" />}
          <div>
            <span className="font-medium text-gray-800">DMARC</span>
            {dns.dmarc ? (
              <p className="text-gray-500 font-mono text-[10px] break-all mt-0.5">{dns.dmarc}</p>
            ) : (
              <p className="text-red-500 mt-0.5">Not configured — no email authentication policy</p>
            )}
          </div>
        </div>

        {/* MX Records */}
        {dns.mx_records.length > 0 && (
          <div>
            <span className="font-medium text-gray-800">MX Records</span>
            <div className="mt-1 space-y-0.5">
              {dns.mx_records.map((mx, i) => (
                <div key={i} className="font-mono text-[10px] text-gray-600">
                  <span className="text-gray-400">{mx.priority}</span> {mx.exchange}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* A / AAAA */}
        {dns.a_records.length > 0 && (
          <div>
            <span className="font-medium text-gray-800">A Records</span>
            <span className="ml-2 text-gray-500 font-mono">{dns.a_records.join(', ')}</span>
          </div>
        )}
        {dns.aaaa_records.length > 0 && (
          <div>
            <span className="font-medium text-gray-800">AAAA</span>
            <span className="ml-2 text-gray-500 font-mono text-[10px]">{dns.aaaa_records.join(', ')}</span>
          </div>
        )}
      </div>
    </div>
  )
}


/* ── Ports Section ─────────────────────────────────── */

function PortsSection({ ports }: { ports: LiveScanResult['open_ports'] }) {
  return (
    <div className="card border-l-4 border-orange-300">
      <div className="flex items-center gap-2 mb-3">
        <Wifi size={16} className="text-orange-600" />
        <h3 className="text-sm font-semibold text-gray-800">Open Ports</h3>
        <span className="text-xs text-gray-500 ml-auto">{ports.length} found</span>
      </div>
      <div className="flex flex-wrap gap-2">
        {ports.map(p => (
          <div key={p.port} className={clsx(
            'px-3 py-1.5 rounded-lg text-xs font-medium border',
            p.risk === 'high' ? 'bg-red-50 border-red-200 text-red-700' :
            p.risk === 'medium' ? 'bg-yellow-50 border-yellow-200 text-yellow-700' :
            'bg-gray-50 border-gray-200 text-gray-700'
          )}>
            <span className="font-mono font-bold">{p.port}</span>
            <span className="text-gray-400 mx-1">/</span>
            {p.service}
          </div>
        ))}
      </div>
    </div>
  )
}


/* ── Cookies Section ───────────────────────────────── */

function CookiesSection({ cookies }: { cookies: LiveScanResult['cookies'] }) {
  const insecure = cookies.filter(c => !c.secure).length

  return (
    <div className="card border-l-4 border-amber-300">
      <div className="flex items-center gap-2 mb-3">
        <Cookie size={16} className="text-amber-600" />
        <h3 className="text-sm font-semibold text-gray-800">Cookies</h3>
        <span className="text-xs text-gray-500 ml-auto">
          {cookies.length} total{insecure > 0 && <span className="text-red-500 ml-1">· {insecure} insecure</span>}
        </span>
      </div>
      <div className="space-y-2">
        {cookies.map((c, i) => (
          <div key={i} className="flex items-center gap-2 text-xs">
            {c.secure
              ? <CheckCircle size={12} className="text-green-500 shrink-0" />
              : <AlertTriangle size={12} className="text-amber-500 shrink-0" />}
            <span className="font-mono font-medium text-gray-800">{c.name}</span>
            <div className="flex gap-1 ml-auto">
              <FlagPill ok={c.flags.secure} label="Secure" />
              <FlagPill ok={c.flags.httponly} label="HttpOnly" />
              <FlagPill ok={c.flags.samesite} label="SameSite" />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function FlagPill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={clsx(
      'px-1.5 py-0.5 rounded text-[10px] font-medium',
      ok ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-600'
    )}>
      {ok ? '✓' : '✗'} {label}
    </span>
  )
}


/* ── Technologies Section ──────────────────────────── */

function TechSection({ techs }: { techs: LiveScanResult['technologies'] }) {
  return (
    <div className="card border-l-4 border-purple-300">
      <div className="flex items-center gap-2 mb-3">
        <Code2 size={16} className="text-purple-600" />
        <h3 className="text-sm font-semibold text-gray-800">Technologies Detected</h3>
      </div>
      <div className="flex flex-wrap gap-2">
        {techs.map((t, i) => (
          <div key={i} className="px-3 py-1.5 bg-purple-50 border border-purple-200 rounded-lg text-xs">
            <span className="font-medium text-purple-800">{t.name}</span>
            <span className="text-purple-400 text-[10px] ml-1.5">via {t.source}</span>
          </div>
        ))}
      </div>
    </div>
  )
}


/* ── All Findings ──────────────────────────────────── */

function FindingsSection({ findings }: { findings: LiveScanResult['findings'] }) {
  const [open, setOpen] = useState(true)

  return (
    <div className="card border border-gray-200">
      <button onClick={() => setOpen(!open)} className="flex items-center gap-2 w-full text-left">
        <AlertTriangle size={16} className="text-gray-600" />
        <h3 className="text-sm font-semibold text-gray-800">
          All Findings ({findings.length})
        </h3>
        <ChevronDown size={14} className={clsx('text-gray-400 ml-auto transition-transform', open && 'rotate-180')} />
      </button>

      {open && (
        <div className="mt-3 space-y-2">
          {findings.map((f, i) => {
            const s = SEV[f.severity as keyof typeof SEV] || SEV.info
            const CatIcon = CATEGORY_ICONS[f.category] || Info
            return (
              <div key={i} className="flex items-start gap-3 p-2.5 rounded-lg bg-gray-50">
                <div className={clsx('w-2 h-2 rounded-full mt-1.5 shrink-0', s.dot)} />
                <CatIcon size={14} className="text-gray-400 mt-0.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-gray-900">{f.title}</span>
                    <span className={clsx('text-[10px] px-1.5 py-0.5 rounded font-medium', s.bg)}>{f.severity}</span>
                  </div>
                  <p className="text-xs text-gray-500 mt-0.5">{f.description}</p>
                </div>
                <span className="text-[10px] font-mono text-gray-400 shrink-0 mt-0.5">{f.nist_control}</span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}


/* ── Tiny helpers ──────────────────────────────────── */

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-1">
      <span className="text-gray-500">{label}:</span>
      <span className="text-gray-800">{value}</span>
    </div>
  )
}
