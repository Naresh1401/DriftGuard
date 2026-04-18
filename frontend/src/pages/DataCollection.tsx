import { useState, useRef } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import type { IngestResult, EmailAnalysis, SIEMResult, WebhookRegistration } from '../types'
import {
  FileSpreadsheet, Braces, FileText, Mail, Database, Webhook,
  Upload, Search, CheckCircle, AlertCircle, Lock, Copy, ShieldAlert, Shield,
  ChevronDown,
} from 'lucide-react'
import clsx from 'clsx'

type CollectorTab = 'csv' | 'json' | 'logs' | 'email' | 'siem' | 'webhook'

const TABS: { key: CollectorTab; label: string; icon: typeof FileSpreadsheet; desc: string }[] = [
  { key: 'csv', label: 'CSV / Excel', icon: FileSpreadsheet, desc: 'Upload structured tabular data' },
  { key: 'json', label: 'JSON', icon: Braces, desc: 'Paste or upload JSON array / objects' },
  { key: 'logs', label: 'Raw Logs', icon: FileText, desc: 'Syslog, Apache, JSON-lines, or plain text' },
  { key: 'email', label: 'Email Headers', icon: Mail, desc: 'Analyze email headers for phishing' },
  { key: 'siem', label: 'SIEM Query', icon: Database, desc: 'Query Splunk, Sentinel, or CloudTrail' },
  { key: 'webhook', label: 'Webhooks', icon: Webhook, desc: 'Register inbound webhook endpoints' },
]

export default function DataCollection() {
  const { can } = useAuth()
  const [tab, setTab] = useState<CollectorTab>('csv')

  if (!can('view_domains')) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-gray-400">
        <Lock size={48} className="mb-4" />
        <h2 className="text-lg font-semibold text-gray-600">Access Restricted</h2>
        <p className="text-sm mt-1">Data collection requires appropriate access.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Data Collection</h1>
        <p className="text-sm text-gray-500 mt-1">
          Ingest data from multiple sources — DriftGuard auto-detects signal types and runs the analysis pipeline
        </p>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 bg-gray-100 p-1 rounded-lg overflow-x-auto">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={clsx(
              'px-3 py-2 rounded-md text-sm font-medium transition-colors flex items-center gap-1.5 whitespace-nowrap',
              tab === key ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600 hover:text-gray-900'
            )}
          >
            <Icon size={14} /> {label}
          </button>
        ))}
      </div>

      {/* Tab description */}
      <p className="text-xs text-gray-500">{TABS.find(t => t.key === tab)?.desc}</p>

      {/* Tab content */}
      {tab === 'csv' && <CSVCollector />}
      {tab === 'json' && <JSONCollector />}
      {tab === 'logs' && <LogCollector />}
      {tab === 'email' && <EmailCollector />}
      {tab === 'siem' && <SIEMCollector />}
      {tab === 'webhook' && <WebhookCollector />}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════
   1. CSV COLLECTOR
   ═══════════════════════════════════════════════════════ */

const SAMPLE_CSV = `timestamp,user,action,ip_address,status,department
2026-04-18T10:00:00Z,user_001,login,10.0.1.1,success,SOC
2026-04-18T10:05:00Z,user_002,login_failed,10.0.1.2,failure,Engineering
2026-04-18T10:10:00Z,user_003,access_denied,10.0.1.3,failure,Finance
2026-04-18T10:15:00Z,user_004,approval_bypass,10.0.1.4,success,Engineering
2026-04-18T10:20:00Z,user_005,audit_skip,10.0.1.5,success,Compliance`

function CSVCollector() {
  const [text, setText] = useState('')
  const [result, setResult] = useState<IngestResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setText(await file.text())
    setResult(null); setError(null)
  }

  const submit = async () => {
    if (!text.trim()) return
    setLoading(true); setResult(null); setError(null)
    try {
      setResult(await api.uploadCsv(text))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <input ref={fileRef} type="file" accept=".csv,.tsv,.txt" onChange={handleFile} className="hidden" />
        <button onClick={() => fileRef.current?.click()} className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 flex items-center gap-1.5">
          <Upload size={14} /> Choose File
        </button>
        <button onClick={() => { setText(SAMPLE_CSV); setResult(null); setError(null) }} className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 text-gray-600">
          Load Sample
        </button>
      </div>

      <textarea
        value={text}
        onChange={e => { setText(e.target.value); setResult(null); setError(null) }}
        placeholder="Paste CSV data here... (header row required)"
        className="w-full h-48 font-mono text-xs p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-drift-500 focus:border-drift-500 resize-none"
        spellCheck={false}
      />

      <button onClick={submit} disabled={!text.trim() || loading} className="btn-primary flex items-center gap-2 disabled:opacity-50">
        {loading ? 'Processing...' : 'Ingest CSV Data'}
      </button>

      <IngestResultDisplay result={result} error={error} />
    </div>
  )
}

/* ═══════════════════════════════════════════════════════
   2. JSON COLLECTOR
   ═══════════════════════════════════════════════════════ */

const SAMPLE_JSON = `[
  {"timestamp": "2026-04-18T10:00:00Z", "user": "user_101", "action": "login_failed", "ip": "192.168.1.10", "attempts": 5},
  {"timestamp": "2026-04-18T10:02:00Z", "user": "user_102", "action": "approval_override", "resource": "deployment_pipeline", "department": "Engineering"},
  {"timestamp": "2026-04-18T10:05:00Z", "user": "user_103", "action": "audit_review_skip", "audit_id": "AUD-2847", "department": "Compliance"}
]`

function JSONCollector() {
  const [text, setText] = useState('')
  const [result, setResult] = useState<IngestResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setText(await file.text())
    setResult(null); setError(null)
  }

  const submit = async () => {
    if (!text.trim()) return
    // Validate JSON first
    try { JSON.parse(text) } catch { setError('Invalid JSON syntax'); return }
    setLoading(true); setResult(null); setError(null)
    try {
      setResult(await api.uploadJson(text))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <input ref={fileRef} type="file" accept=".json" onChange={handleFile} className="hidden" />
        <button onClick={() => fileRef.current?.click()} className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 flex items-center gap-1.5">
          <Upload size={14} /> Choose File
        </button>
        <button onClick={() => { setText(SAMPLE_JSON); setResult(null); setError(null) }} className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 text-gray-600">
          Load Sample
        </button>
      </div>

      <textarea
        value={text}
        onChange={e => { setText(e.target.value); setResult(null); setError(null) }}
        placeholder='Paste JSON data here... (array of objects or single object)'
        className="w-full h-48 font-mono text-xs p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-drift-500 focus:border-drift-500 resize-none"
        spellCheck={false}
      />

      <button onClick={submit} disabled={!text.trim() || loading} className="btn-primary flex items-center gap-2 disabled:opacity-50">
        {loading ? 'Processing...' : 'Ingest JSON Data'}
      </button>

      <IngestResultDisplay result={result} error={error} />
    </div>
  )
}

/* ═══════════════════════════════════════════════════════
   3. RAW LOG COLLECTOR
   ═══════════════════════════════════════════════════════ */

const SAMPLE_LOGS = `Apr 18 10:02:33 webserver01 sshd[12345]: Failed password for user_admin from 10.0.1.50 port 22
Apr 18 10:02:35 webserver01 sshd[12345]: Failed password for user_admin from 10.0.1.50 port 22
Apr 18 10:05:01 dbserver02 audit[8821]: access_review skipped by compliance_team user_id=4102
192.168.1.100 - admin [18/Apr/2026:10:15:30 +0000] "POST /admin/delete-logs HTTP/1.1" 200 1024
192.168.1.101 - - [18/Apr/2026:10:16:02 +0000] "GET /api/export?table=users&format=csv HTTP/1.1" 200 524288
{"timestamp":"2026-04-18T10:20:00Z","event":"firewall_rule_change","user":"user_3044","action":"outbound_allow_all"}`

function LogCollector() {
  const [text, setText] = useState('')
  const [format, setFormat] = useState('auto')
  const [result, setResult] = useState<IngestResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setText(await file.text())
    setResult(null); setError(null)
  }

  const submit = async () => {
    if (!text.trim()) return
    setLoading(true); setResult(null); setError(null)
    try {
      setResult(await api.uploadLogs(text, format))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2 items-center">
        <input ref={fileRef} type="file" accept=".log,.txt" onChange={handleFile} className="hidden" />
        <button onClick={() => fileRef.current?.click()} className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 flex items-center gap-1.5">
          <Upload size={14} /> Choose File
        </button>
        <button onClick={() => { setText(SAMPLE_LOGS); setResult(null); setError(null) }} className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 text-gray-600">
          Load Sample
        </button>
        <select value={format} onChange={e => setFormat(e.target.value)} className="text-sm border border-gray-300 rounded-lg px-2 py-1.5">
          <option value="auto">Auto-detect format</option>
          <option value="syslog">Syslog</option>
          <option value="apache">Apache / Access Logs</option>
          <option value="json_lines">JSON Lines</option>
          <option value="custom">Custom / Unknown</option>
        </select>
      </div>

      <textarea
        value={text}
        onChange={e => { setText(e.target.value); setResult(null); setError(null) }}
        placeholder="Paste raw log lines here..."
        className="w-full h-48 font-mono text-xs p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-drift-500 focus:border-drift-500 resize-none"
        spellCheck={false}
      />

      <button onClick={submit} disabled={!text.trim() || loading} className="btn-primary flex items-center gap-2 disabled:opacity-50">
        {loading ? 'Parsing...' : 'Ingest Logs'}
      </button>

      <IngestResultDisplay result={result} error={error} />
    </div>
  )
}

/* ═══════════════════════════════════════════════════════
   4. EMAIL HEADER ANALYZER
   ═══════════════════════════════════════════════════════ */

const SAMPLE_EMAIL_HEADERS = `Return-Path: <suspicious@phishing-domain.xyz>
Received: from mail-evil.phishing-domain.xyz (10.0.99.5) by mail.company.com
Received: from localhost (127.0.0.1) by mail-evil.phishing-domain.xyz
From: "IT Support" <support@company.com>
Reply-To: credentials-harvest@phishing-domain.xyz
To: employee@company.com
Subject: Urgent: Verify Your Account Now
Date: Fri, 18 Apr 2026 09:30:00 -0500
Message-ID: <fake-msg-id@phishing-domain.xyz>
X-Mailer: PHPMailer 6.5.0
Authentication-Results: mx.company.com; spf=fail smtp.mailfrom=phishing-domain.xyz; dkim=fail; dmarc=fail`

function EmailCollector() {
  const [text, setText] = useState('')
  const [result, setResult] = useState<EmailAnalysis | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const submit = async () => {
    if (!text.trim()) return
    setLoading(true); setResult(null); setError(null)
    try {
      setResult(await api.analyzeEmailHeaders(text))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <button onClick={() => { setText(SAMPLE_EMAIL_HEADERS); setResult(null); setError(null) }} className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 text-gray-600">
        Load Phishing Sample
      </button>

      <textarea
        value={text}
        onChange={e => { setText(e.target.value); setResult(null); setError(null) }}
        placeholder="Paste raw email headers here (From, To, Received, Authentication-Results, etc.)"
        className="w-full h-48 font-mono text-xs p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-drift-500 focus:border-drift-500 resize-none"
        spellCheck={false}
      />

      <button onClick={submit} disabled={!text.trim() || loading} className="btn-primary flex items-center gap-2 disabled:opacity-50">
        <Search size={14} /> {loading ? 'Analyzing...' : 'Analyze Headers'}
      </button>

      {error && <ErrorBanner message={error} />}
      {result && <EmailResultDisplay result={result} />}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════
   5. SIEM QUERY
   ═══════════════════════════════════════════════════════ */

const SIEM_SAMPLES: Record<string, string> = {
  splunk: 'index=security sourcetype=audit action=login_failed | stats count by user',
  sentinel: 'SecurityEvent | where EventID == 4625 | summarize count() by Account | top 10 by count_',
  cloudtrail: 'eventName=ConsoleLogin AND responseElements.ConsoleLogin=Failure',
}

function SIEMCollector() {
  const [siem, setSiem] = useState('splunk')
  const [query, setQuery] = useState('')
  const [timeRange, setTimeRange] = useState('24h')
  const [result, setResult] = useState<SIEMResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const submit = async () => {
    if (!query.trim()) return
    setLoading(true); setResult(null); setError(null)
    try {
      setResult(await api.querySiem(siem, query, timeRange))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2 flex-wrap items-center">
        <select value={siem} onChange={e => { setSiem(e.target.value); setResult(null) }} className="text-sm border border-gray-300 rounded-lg px-3 py-2">
          <option value="splunk">Splunk</option>
          <option value="sentinel">Microsoft Sentinel</option>
          <option value="cloudtrail">AWS CloudTrail</option>
        </select>
        <select value={timeRange} onChange={e => setTimeRange(e.target.value)} className="text-sm border border-gray-300 rounded-lg px-3 py-2">
          <option value="1h">Last 1 hour</option>
          <option value="4h">Last 4 hours</option>
          <option value="24h">Last 24 hours</option>
          <option value="7d">Last 7 days</option>
          <option value="30d">Last 30 days</option>
        </select>
        <button onClick={() => { setQuery(SIEM_SAMPLES[siem] || ''); setResult(null); setError(null) }} className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 text-gray-600">
          Load Sample Query
        </button>
      </div>

      <textarea
        value={query}
        onChange={e => { setQuery(e.target.value); setResult(null); setError(null) }}
        placeholder={`Enter ${siem === 'splunk' ? 'SPL' : siem === 'sentinel' ? 'KQL' : 'CloudTrail filter'} query...`}
        className="w-full h-32 font-mono text-xs p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-drift-500 focus:border-drift-500 resize-none"
        spellCheck={false}
      />

      <button onClick={submit} disabled={!query.trim() || loading} className="btn-primary flex items-center gap-2 disabled:opacity-50">
        <Database size={14} /> {loading ? 'Querying...' : 'Execute Query'}
      </button>

      {error && <ErrorBanner message={error} />}
      {result && <SIEMResultDisplay result={result} />}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════
   6. WEBHOOK REGISTRATION
   ═══════════════════════════════════════════════════════ */

function WebhookCollector() {
  const [name, setName] = useState('')
  const [signalType, setSignalType] = useState('custom')
  const [registration, setRegistration] = useState<WebhookRegistration | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState<string | null>(null)

  const submit = async () => {
    if (!name.trim()) return
    setLoading(true); setRegistration(null); setError(null)
    try {
      setRegistration(await api.registerWebhook(name, signalType))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed')
    } finally {
      setLoading(false)
    }
  }

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    setCopied(label)
    setTimeout(() => setCopied(null), 2000)
  }

  return (
    <div className="space-y-4">
      <div className="card border border-gray-200">
        <h3 className="text-sm font-semibold text-gray-800 mb-3">Register New Webhook</h3>
        <p className="text-xs text-gray-500 mb-4">
          Create a webhook endpoint that external systems (CI/CD, SIEM, monitoring tools) can push data to.
          DriftGuard will ingest and analyze incoming payloads automatically.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label className="text-xs text-gray-600 block mb-1">Webhook Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g. github-actions, splunk-forwarder"
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-drift-500 focus:border-drift-500"
            />
          </div>
          <div>
            <label className="text-xs text-gray-600 block mb-1">Signal Type</label>
            <select value={signalType} onChange={e => setSignalType(e.target.value)} className="w-full text-sm border border-gray-300 rounded-lg px-3 py-2">
              <option value="custom">Custom</option>
              <option value="access_log">Access Log</option>
              <option value="audit_review">Audit Review</option>
              <option value="incident_response">Incident Response</option>
              <option value="approval_workflow">Approval Workflow</option>
              <option value="communication">Communication</option>
              <option value="training_completion">Training Completion</option>
            </select>
          </div>
          <div className="flex items-end">
            <button onClick={submit} disabled={!name.trim() || loading} className="btn-primary flex items-center gap-2 disabled:opacity-50 w-full justify-center">
              <Webhook size={14} /> {loading ? 'Creating...' : 'Create Webhook'}
            </button>
          </div>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}

      {registration && (
        <div className="card border-l-4 border-green-500 space-y-3">
          <div className="flex items-center gap-2">
            <CheckCircle size={16} className="text-green-600" />
            <h3 className="text-sm font-semibold text-green-800">Webhook Created: {registration.name}</h3>
          </div>

          <div className="space-y-2">
            <CopyRow label="Endpoint URL" value={`${window.location.origin}${registration.endpoint}`} onCopy={copyToClipboard} copied={copied} />
            <CopyRow label="Webhook Secret" value={registration.secret} onCopy={copyToClipboard} copied={copied} />
            <CopyRow label="Webhook ID" value={registration.webhook_id} onCopy={copyToClipboard} copied={copied} />
          </div>

          <div className="mt-3 p-3 bg-gray-50 rounded-lg">
            <p className="text-xs text-gray-600 font-medium mb-1">Example cURL:</p>
            <pre className="text-[10px] text-gray-700 font-mono overflow-x-auto whitespace-pre-wrap">{`curl -X POST ${window.location.origin}${registration.endpoint} \\
  -H "Content-Type: application/json" \\
  -d '{"event": "deploy", "status": "success", "user": "ci-bot"}'`}</pre>
          </div>
        </div>
      )}
    </div>
  )
}


/* ═══════════════════════════════════════════════════════
   SHARED RESULT COMPONENTS
   ═══════════════════════════════════════════════════════ */

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-800', high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800', low: 'bg-blue-100 text-blue-800',
  info: 'bg-green-100 text-green-700',
}

const GRADE_COLOR: Record<string, string> = {
  A: 'bg-green-500', B: 'bg-green-400', C: 'bg-yellow-400', D: 'bg-orange-500', F: 'bg-red-500',
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-2 p-3 rounded-lg bg-red-50 text-red-800 text-sm">
      <AlertCircle size={16} /> {message}
    </div>
  )
}

function IngestResultDisplay({ result, error }: { result: IngestResult | null; error: string | null }) {
  if (error) return <ErrorBanner message={error} />
  if (!result) return null

  const typeCounts: Record<string, number> = {}
  result.results.forEach(r => { typeCounts[r.signal_type] = (typeCounts[r.signal_type] || 0) + 1 })

  return (
    <div className="card border-l-4 border-green-500">
      <div className="flex items-center gap-2 mb-3">
        <CheckCircle size={16} className="text-green-600" />
        <h3 className="text-sm font-semibold text-green-800">
          {result.signals_parsed} signals ingested successfully
        </h3>
      </div>

      <div className="flex flex-wrap gap-2 mb-3">
        {Object.entries(typeCounts).map(([type, count]) => (
          <span key={type} className="px-2 py-1 bg-drift-50 text-drift-800 rounded text-xs font-medium">
            {type.replace(/_/g, ' ')} ({count})
          </span>
        ))}
      </div>

      <details className="text-xs">
        <summary className="cursor-pointer text-gray-500 hover:text-gray-700 flex items-center gap-1">
          <ChevronDown size={12} /> View signal IDs
        </summary>
        <div className="mt-2 space-y-1 max-h-32 overflow-y-auto">
          {result.results.map((r, i) => (
            <div key={i} className="flex items-center gap-2 text-gray-600 font-mono">
              <span className="text-gray-400">{i + 1}.</span>
              <span>{r.signal_id.slice(0, 8)}...</span>
              <span className="px-1.5 py-0.5 bg-gray-100 rounded text-[10px]">{r.signal_type}</span>
              {r.anonymized && <span className="text-green-600 text-[10px]">anonymized</span>}
            </div>
          ))}
        </div>
      </details>
    </div>
  )
}

function EmailResultDisplay({ result }: { result: EmailAnalysis }) {
  return (
    <div className="space-y-4">
      {/* Score bar */}
      <div className="card flex items-center gap-4">
        <div className={clsx(
          'w-14 h-14 rounded-xl flex items-center justify-center text-white text-xl font-bold',
          GRADE_COLOR[result.grade] || 'bg-gray-400'
        )}>
          {result.grade}
        </div>
        <div>
          <div className="text-xl font-bold text-gray-900">{result.security_score}<span className="text-sm text-gray-500">/100</span></div>
          <p className="text-xs text-gray-500">Email Security Score</p>
        </div>
        <div className="ml-auto text-right text-xs text-gray-500 space-y-0.5">
          {result.metadata.from && <div><strong>From:</strong> {result.metadata.from}</div>}
          {result.metadata.subject && <div><strong>Subject:</strong> {result.metadata.subject}</div>}
          {result.metadata.date && <div><strong>Date:</strong> {result.metadata.date}</div>}
          <div><strong>Hops:</strong> {result.metadata.received_hops}</div>
        </div>
      </div>

      {/* Findings */}
      <div className="card">
        <div className="flex items-center gap-2 mb-3">
          <ShieldAlert size={16} className="text-red-600" />
          <h3 className="text-sm font-semibold text-gray-800">Findings ({result.findings.length})</h3>
        </div>
        <div className="space-y-2">
          {result.findings.map((f, i) => (
            <div key={i} className="flex items-start gap-3 p-2 rounded-lg bg-gray-50">
              {f.severity === 'info'
                ? <CheckCircle size={14} className="text-green-500 mt-0.5 shrink-0" />
                : <AlertCircle size={14} className="text-red-400 mt-0.5 shrink-0" />}
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-gray-900">{f.title}</span>
                  <span className={clsx('text-[10px] px-1.5 py-0.5 rounded font-medium', SEV_BADGE[f.severity])}>{f.severity}</span>
                </div>
                <p className="text-xs text-gray-600">{f.description}</p>
              </div>
              <span className="text-[10px] font-mono text-gray-400 shrink-0">{f.nist_control}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Metadata */}
      {result.metadata.reply_to && (
        <div className="card border-l-4 border-orange-400">
          <div className="flex items-center gap-2 mb-1">
            <Shield size={14} className="text-orange-600" />
            <span className="text-xs font-semibold text-orange-800">Reply-To Analysis</span>
          </div>
          <p className="text-xs text-gray-700">
            Reply-To is set to <code className="bg-gray-100 px-1 rounded">{result.metadata.reply_to}</code> which differs from the From address.
            This is a common phishing indicator.
          </p>
        </div>
      )}
    </div>
  )
}

function SIEMResultDisplay({ result }: { result: SIEMResult }) {
  return (
    <div className="space-y-4">
      <div className="card">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Database size={16} className="text-drift-700" />
            <h3 className="text-sm font-semibold text-gray-800">{result.siem}</h3>
          </div>
          <div className="flex items-center gap-2 text-xs text-gray-500">
            <span>{result.events_returned} events</span>
            <span className="px-2 py-0.5 bg-gray-100 rounded">{result.time_range}</span>
            {result.mode === 'demo' && <span className="px-2 py-0.5 bg-yellow-100 text-yellow-800 rounded">Demo Mode</span>}
          </div>
        </div>

        {result.message && (
          <p className="text-xs text-yellow-700 bg-yellow-50 p-2 rounded-lg mb-3">{result.message}</p>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-200 text-left text-gray-500">
                <th className="pb-2 pr-3">Time</th>
                <th className="pb-2 pr-3">Event</th>
                <th className="pb-2 pr-3">User</th>
                <th className="pb-2 pr-3">Details</th>
                <th className="pb-2">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {result.events.map((e, i) => (
                <tr key={i}>
                  <td className="py-2 pr-3 font-mono text-gray-500 whitespace-nowrap">{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td className="py-2 pr-3 font-medium text-gray-800">{e.event_type.replace(/_/g, ' ')}</td>
                  <td className="py-2 pr-3 text-gray-600">{e.user}</td>
                  <td className="py-2 pr-3 text-gray-600 max-w-xs truncate">{e.details}</td>
                  <td className="py-2">
                    <span className={clsx('text-[10px] px-1.5 py-0.5 rounded font-medium', SEV_BADGE[e.severity])}>{e.severity}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function CopyRow({ label, value, onCopy, copied }: { label: string; value: string; onCopy: (v: string, l: string) => void; copied: string | null }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-gray-500 w-28 shrink-0">{label}:</span>
      <code className="flex-1 text-xs bg-gray-50 px-2 py-1 rounded font-mono text-gray-800 truncate">{value}</code>
      <button onClick={() => onCopy(value, label)} className="text-gray-400 hover:text-gray-600 shrink-0">
        {copied === label ? <CheckCircle size={14} className="text-green-500" /> : <Copy size={14} />}
      </button>
    </div>
  )
}
