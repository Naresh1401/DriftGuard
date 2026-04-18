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
