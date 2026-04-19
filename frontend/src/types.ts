// DriftGuard Frontend Types — mirrors backend Pydantic models

export type DriftPattern =
  | 'Fatigue'
  | 'Overconfidence'
  | 'Hurry'
  | 'Quiet_Fear'
  | 'Hoarding'
  | 'Compliance_Theater'

export type AlertLevel = 'Watch' | 'Warning' | 'Critical'

export type NISTControl = 'AC-2' | 'AU-6' | 'IR-6' | 'CA-7' | 'AT-2'

export type UserRole = 'compliance_officer' | 'ciso' | 'ni_architect' | 'admin' | 'viewer'

export interface Alert {
  alert_id: string
  drift_pattern: DriftPattern
  alert_level: AlertLevel
  severity: number
  confidence: number
  department: string
  plain_language: string
  nist_controls: NISTControl[]
  recommended_action: string
  created_at: string
  acknowledged: boolean
  resolved: boolean
}

export interface DriftReport {
  report_id: string
  department: string
  patterns_detected: PatternDetection[]
  overall_severity: number
  alert_level: AlertLevel
  nist_controls_affected: NISTControl[]
  timestamp: string
  plain_language_summary: string
}

export interface PatternDetection {
  pattern: DriftPattern
  confidence: number
  severity: number
  signal_count: number
  trend: 'rising' | 'stable' | 'declining'
}

export interface HealthScore {
  score: number
  trend: 'improving' | 'stable' | 'declining'
  active_patterns: number
  critical_alerts: number
  watch_alerts: number
  warning_alerts: number
}

export interface CalibrationResponse {
  response_id: string
  drift_pattern: DriftPattern
  severity_range: [number, number]
  organizational_context: string
  response_text: string
  approval_status: 'pending' | 'approved' | 'rejected'
  is_placeholder: boolean
}

export interface DomainConfig {
  domain: string
  display_name: string
  description: string
  signal_count: number
  sensitivity: string
  signals?: { type: string; maps_to: string[]; nist_controls: string[]; description: string; source_connector: string }[]
}

export interface GovernanceAction {
  action_id: string
  gate_type: 'ni_response' | 'nist_mapping' | 'critical_alert'
  status: 'pending' | 'approved' | 'rejected'
  submitted_at: string
  reviewed_at?: string
  reviewer?: string
  details: Record<string, unknown>
}

export interface TrendDataPoint {
  date: string
  severity: number
  pattern: DriftPattern
  weight: number
}

export interface WeeklyReport {
  period: string
  health_score: number
  alerts_by_level: Record<AlertLevel, number>
  patterns_by_type: Record<DriftPattern, number>
  nist_risk_summary: Record<NISTControl, number>
  top_departments: { department: string; risk_score: number }[]
}

export interface OnboardingStep {
  step: number
  title: string
  description: string
  completed: boolean
}

export interface BreachAnalysis {
  url: string
  hostname: string
  status_code: number
  analyzed_at: string
  security_score: number
  grade: string
  ssl: {
    valid: boolean
    issuer?: string
    subject?: string
    not_before?: string
    expires?: string
    days_remaining?: number
    protocol?: string
    expired?: boolean
    expiring_soon?: boolean
    error?: string
  } | null
  headers: {
    header: string
    present: boolean
    value: string | null
    severity: string
    nist_control: string
  }[]
  findings: {
    category: string
    severity: string
    title: string
    description: string
    nist_control: string
    recommendation: string
  }[]
  summary: {
    total_findings: number
    critical: number
    high: number
    medium: number
    low: number
  }
}

export interface IngestResult {
  status: string
  signals_parsed: number
  results: { signal_id: string; signal_type: string; anonymized: boolean; source?: string }[]
  filename?: string
  format_detected?: string
}

export interface EmailAnalysis {
  security_score: number
  grade: string
  risk_score: number
  metadata: {
    from: string | null
    to: string | null
    subject: string | null
    date: string | null
    reply_to: string | null
    message_id: string | null
    x_mailer: string | null
    received_hops: number
  }
  findings: {
    severity: string
    title: string
    description: string
    nist_control: string
    category: string
  }[]
}

export interface SIEMResult {
  siem: string
  query: string
  time_range: string
  mode: string
  events_returned: number
  events: {
    timestamp: string
    event_type: string
    user: string
    details: string
    severity: string
    source_ip?: string
  }[]
  message?: string
}

export interface WebhookRegistration {
  webhook_id: string
  endpoint: string
  secret: string
  signal_type: string
  domain: string
  name: string
}

export interface WebhookInfo {
  webhook_id: string
  name: string
  signal_type: string
  domain: string
  description: string
}

// ── Live Scanner ────────────────────────────────────
export interface LiveScanResult {
  url: string
  hostname: string
  ip_addresses: string[]
  status_code: number
  redirect_chain: string[]
  scanned_at: string
  duration_ms: number
  security_score: number
  grade: string
  ssl: {
    valid: boolean
    protocol?: string
    cipher?: string
    cipher_bits?: number
    issuer_org?: string
    issuer_cn?: string
    subject_cn?: string
    san?: string[]
    not_before?: string
    expires?: string
    days_remaining?: number
    expired?: boolean
    expiring_soon?: boolean
    key_weak?: boolean
    error?: string
  } | null
  headers: {
    header: string
    key: string
    present: boolean
    value: string | null
    nist_control: string
  }[]
  cookies: {
    name: string
    flags: { secure: boolean; httponly: boolean; samesite: boolean }
    issues: string[]
    secure: boolean
  }[]
  dns: {
    a_records: string[]
    aaaa_records: string[]
    mx_records: { priority: number; exchange: string }[]
    spf: string | null
    dmarc: string | null
    findings: { severity: string; title: string; description: string; nist_control: string }[]
  } | null
  open_ports: { port: number; service: string; risk: string }[]
  technologies: { name: string; source: string; detail: string }[]
  findings: {
    severity: string
    title: string
    description: string
    nist_control: string
    category: string
  }[]
  summary: {
    total_findings: number
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
}

// ── Drift Map ───────────────────────────────────────
export interface DriftHeatmap {
  domain: string
  days: number
  departments: string[]
  patterns: string[]
  data: Record<string, Record<DriftPattern, number>>
}

export interface DriftTrend {
  pattern: string
  days: number
  team_id: string | null
  data: { date: string; severity: number; confidence: number; alert_level: string }[]
}

export interface DriftSummary {
  domain: string
  health_score: number
  total_active_alerts: number
  critical: number
  warnings: number
  patterns: Record<string, { count: number; max_severity: number }>
}

// ── Enhanced Reports ────────────────────────────────
export interface WeeklyReportData {
  period: string
  domain: string
  health_score: number
  total_alerts: number
  critical_count: number
  warning_count: number
  watch_count: number
  pattern_distribution: Record<string, number>
  nist_controls_at_risk: string[]
}

export interface NISTRiskData {
  domain: string
  controls_at_risk: {
    control: string
    alert_count: number
    max_severity: number
    patterns: string[]
    risk_score?: number
  }[]
}

export interface BoardSummaryData {
  domain: string
  executive_summary: {
    health_score: number
    trend: 'improving' | 'stable' | 'degrading'
    active_critical: number
    active_warnings: number
    calibration_responses_delivered: number
    calibration_acted_upon: number
  }
  recommendation: string
}

// ── Audit ───────────────────────────────────────────
export interface AuditLogEntry {
  id: string
  timestamp: string
  action: string
  actor: string | null
  resource_type: string
  resource_id: string | null
  details: Record<string, unknown>
  ip_address: string | null
}

// ── Threat Intelligence ──
export interface ThreatIntelItem {
  id: string
  source: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  drift_patterns: string[]
  nist_controls: string[]
  published: string
  recommendations: string[]
}

export interface ThreatCorrelation {
  threat: ThreatIntelItem
  matching_alert_count: number
  alert_ids: string[]
  risk_level: string
}

// ── Scans ──
export interface ScanRecord {
  scan_id: string
  domain: string
  scope: string
  status: 'running' | 'completed' | 'failed'
  started_at: string
  completed_at: string | null
  signals_processed: number
  alerts_generated: number
  triggered_by: string
}

export interface ScanSchedule {
  schedule_id: string
  domain: string
  scope: string
  cron_expression: string
  enabled: boolean
  created_at: string
  created_by: string
  last_run: string | null
  next_run: string | null
}
