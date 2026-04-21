const API_HOST = import.meta.env.VITE_API_URL || ''
const BASE = `${API_HOST}/api/v1`

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = localStorage.getItem('driftguard_token')
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options?.headers as Record<string, string> ?? {}),
  }
  const res = await fetch(`${BASE}${path}`, { ...options, headers })
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/auth/')) {
      localStorage.removeItem('driftguard_token')
      localStorage.removeItem('driftguard_role')
      window.location.href = '/login'
      throw new Error('Session expired')
    }
    const body = await res.text()
    throw new Error(`API ${res.status}: ${body}`)
  }
  return res.json()
}

export const api = {
  // Auth
  login: (email: string, password: string) =>
    request<{ access_token: string; role: string; email: string; full_name: string; expires_in: number }>('/auth/login', {
      method: 'POST', body: JSON.stringify({ email, password }),
    }),
  register: (email: string, password: string, full_name: string, organization?: string) =>
    request<{ access_token: string; role: string; email: string; full_name: string; expires_in: number }>('/auth/register', {
      method: 'POST', body: JSON.stringify({ email, password, full_name, organization: organization || '', role: 'viewer' }),
    }),
  getMe: () => request<{ email: string; full_name: string; role: string; organization: string }>('/auth/me'),

  // Health
  health: () => request<{ status: string }>('/health'),

  // Alerts
  getAlerts: async (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    const raw = await request<{ alerts: any[]; total: number }>(`/alerts${qs}`)
    return {
      total: raw.total,
      alerts: raw.alerts.map((a: any) => ({
        alert_id: a.id || a.alert_id,
        drift_pattern: a.drift_patterns?.[0]?.pattern || a.drift_pattern || 'Unknown',
        alert_level: a.alert_level,
        severity: typeof a.severity_score === 'number' ? a.severity_score : (a.severity ?? 1),
        confidence: a.confidence_score ?? a.confidence ?? 0,
        department: a.team_id || a.department || 'organization',
        plain_language: a.plain_language_explanation || a.plain_language || '',
        nist_controls: (a.nist_controls_at_risk || a.nist_controls || []).map((c: any) => typeof c === 'string' ? c : c?.value || c),
        recommended_action: a.calibration_recommendation || a.recommended_action || 'Review and assess',
        created_at: a.created_at,
        acknowledged: a.status === 'acknowledged' || a.acknowledged || false,
        resolved: a.status === 'resolved' || a.resolved || false,
      })) as import('./types').Alert[],
    }
  },
  acknowledgeAlert: (id: string) =>
    request(`/alerts/${id}/action`, { method: 'POST', body: JSON.stringify({ action: 'acknowledge' }) }),
  resolveAlert: (id: string) =>
    request(`/alerts/${id}/action`, { method: 'POST', body: JSON.stringify({ action: 'resolve' }) }),
  getHealthScore: (domain = 'enterprise') =>
    request<import('./types').HealthScore>(`/alerts/health-score/${domain}`),

  // Signals
  ingestSignal: (signal: Record<string, unknown>) =>
    request('/signals/ingest', { method: 'POST', body: JSON.stringify(signal) }),
  uploadCsv: (csvContent: string, domain?: string) =>
    request<import('./types').IngestResult>('/signals/upload/csv', {
      method: 'POST', body: JSON.stringify({ csv_content: csvContent, domain: domain || 'enterprise' }),
    }),
  uploadJson: (jsonContent: string, domain?: string) =>
    request<import('./types').IngestResult>('/signals/upload/json', {
      method: 'POST', body: JSON.stringify({ json_content: jsonContent, domain: domain || 'enterprise' }),
    }),
  uploadLogs: (logContent: string, logFormat?: string, domain?: string) =>
    request<import('./types').IngestResult>('/signals/upload/logs', {
      method: 'POST', body: JSON.stringify({ log_content: logContent, log_format: logFormat || 'auto', domain: domain || 'enterprise' }),
    }),
  analyzeEmailHeaders: (headers: string) =>
    request<import('./types').EmailAnalysis>('/signals/analyze/email-headers', {
      method: 'POST', body: JSON.stringify({ headers }),
    }),
  querySiem: (siemType: string, query: string, timeRange?: string) =>
    request<import('./types').SIEMResult>('/signals/collect/siem', {
      method: 'POST', body: JSON.stringify({ siem_type: siemType, query, time_range: timeRange || '24h' }),
    }),
  registerWebhook: (name: string, signalType?: string, domain?: string) =>
    request<import('./types').WebhookRegistration>('/signals/webhooks/register', {
      method: 'POST', body: JSON.stringify({ name, signal_type: signalType || 'custom', domain: domain || 'enterprise' }),
    }),
  listWebhooks: () =>
    request<{ webhooks: import('./types').WebhookInfo[] }>('/signals/webhooks').then(r => r.webhooks),

  // Calibration
  getCalibrationResponses: () =>
    request<{ pending: import('./types').CalibrationResponse[] }>('/calibration/pending-reviews').then(r => r.pending),
  approveCalibration: (id: string) =>
    request(`/calibration/responses/${id}/approve`, { method: 'POST' }),
  rejectCalibration: (id: string) =>
    request(`/calibration/responses/${id}/reject`, { method: 'POST' }),

  // Domains
  getDomains: () =>
    request<{ domains: import('./types').DomainConfig[] }>('/domains').then(r => r.domains),
  getDomain: (name: string) =>
    request<import('./types').DomainConfig>(`/domains/${encodeURIComponent(name)}`),
  uploadDomainYaml: (yamlContent: string) =>
    request<{ status: string; domain: string }>('/domains/upload/yaml', {
      method: 'POST',
      body: JSON.stringify({ yaml_content: yamlContent }),
    }),
  analyzeUrl: (url: string) =>
    request<import('./types').BreachAnalysis>('/domains/analyze-url', {
      method: 'POST',
      body: JSON.stringify({ url }),
    }),

  // Live Scanner
  liveScan: (url: string, scanPorts = true, scanDns = true) =>
    request<import('./types').LiveScanResult>('/scanner/scan', {
      method: 'POST',
      body: JSON.stringify({ url, scan_ports: scanPorts, scan_dns: scanDns }),
    }),

  // Governance
  getPendingActions: () =>
    request<{ pending: import('./types').GovernanceAction[] }>('/governance/gates/pending').then(r => r.pending),
  approveGovernanceAction: (gateType: string, actionId: string) =>
    request(`/governance/${gateType}/${actionId}/approve`, { method: 'POST' }),
  rejectGovernanceAction: (gateType: string, actionId: string) =>
    request(`/governance/${gateType}/${actionId}/reject`, { method: 'POST' }),
  getAuditLog: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<{ entries: import('./types').AuditLogEntry[]; total: number }>(`/governance/audit-log${qs}`)
  },

  // Drift Map
  getDriftHeatmap: (domain = 'enterprise', days = 30) =>
    request<import('./types').DriftHeatmap>(`/drift-map/heatmap?domain=${domain}&days=${days}`),
  getDriftTrend: (pattern: string, days = 30, teamId?: string) => {
    const qs = new URLSearchParams({ days: String(days) })
    if (teamId) qs.set('team_id', teamId)
    return request<import('./types').DriftTrend>(`/drift-map/trend/${pattern}?${qs}`)
  },
  getDriftSummary: (domain = 'enterprise') =>
    request<import('./types').DriftSummary>(`/drift-map/summary?domain=${domain}`),

  // Reports
  getWeeklyReport: (domain = 'enterprise') =>
    request<import('./types').WeeklyReportData>(`/reports/weekly-summary?domain=${domain}`),
  getNISTRisk: (domain = 'enterprise') =>
    request<import('./types').NISTRiskData>(`/reports/nist-risk?domain=${domain}`),
  getBoardSummary: (domain = 'enterprise') =>
    request<import('./types').BoardSummaryData>(`/reports/board-summary?domain=${domain}`),
  getPatternTrend: (pattern: string, days = 30) =>
    request<{ pattern: string; days: number; trend: import('./types').TrendDataPoint[] }>(`/reports/trend/${pattern}?days=${days}`),

  // Export
  exportReport: (format: 'csv' | 'json', reportType: string, domain = 'enterprise') =>
    request<Blob>(`/reports/export?format=${format}&report_type=${reportType}&domain=${domain}`),

  // Risk Forecast (v2 predictive engine)
  getRiskForecastAll: () =>
    request<{ domains: Array<{ domain: string; breach_probability_pct: number; active_alerts: number; baseline_pct: number }> }>(
      '/risk-forecast/'
    ),
  getRiskForecast: (domain = 'enterprise', horizonDays = 30) =>
    request<{
      domain: string
      horizon_days: number
      breach_probability_pct: number
      confidence_interval: { low: number; high: number }
      risk_level: string
      components: { domain_baseline_pct: number; drift_modifier: number; pattern_risk_score: number; nist_risk_score: number }
      top_contributing_patterns: Array<{ pattern: string; contribution: number }>
      top_nist_gaps: Array<{ control: string; risk: number }>
      active_signals: number
      computed_at: string
      methodology: string
    }>(`/risk-forecast/${encodeURIComponent(domain)}?horizon_days=${horizonDays}`),
  getRiskTrend: (domain = 'enterprise', days = 14) =>
    request<{ domain: string; days: number; trend: Array<{ date: string; breach_probability_pct: number; active_alerts: number }> }>(
      `/risk-forecast/${encodeURIComponent(domain)}/trend?days=${days}`
    ),

  // Threat Intelligence
  getThreatFeed: (severity?: string, pattern?: string) => {
    const qs = new URLSearchParams()
    if (severity) qs.set('severity', severity)
    if (pattern) qs.set('pattern', pattern)
    const q = qs.toString()
    return request<{ items: import('./types').ThreatIntelItem[]; total: number }>(`/threat-intel/feed${q ? '?' + q : ''}`)
  },
  getThreatCorrelations: () =>
    request<{ correlations: import('./types').ThreatCorrelation[]; total_threats: number; active_correlations: number }>('/threat-intel/correlate'),

  // Scans
  triggerScan: (domain = 'enterprise', scope = 'full') =>
    request<{ scan_id: string; status: string; message: string }>('/scans/trigger', {
      method: 'POST', body: JSON.stringify({ domain, scope }),
    }),
  getScanStatus: () =>
    request<{ active: boolean; scan_id?: string; status?: string; signals_processed?: number; alerts_generated?: number }>('/scans/status'),
  getScanHistory: (limit = 20) =>
    request<{ scans: import('./types').ScanRecord[]; total: number }>(`/scans/history?limit=${limit}`),
  createScanSchedule: (domain: string, scope: string, cron: string) =>
    request('/scans/schedule', { method: 'POST', body: JSON.stringify({ domain, scope, cron_expression: cron }) }),
  getScanSchedules: () =>
    request<{ schedules: import('./types').ScanSchedule[]; total: number }>('/scans/schedules'),

  // Onboarding
  getOnboardingStatus: () =>
    request<{ steps: import('./types').OnboardingStep[]; completed: boolean }>('/onboarding/status'),
  getOnboardingDomains: () =>
    request<{ domains: Array<{ id: string; name: string; description: string; icon: string }> }>('/onboarding/domains'),
  completeOnboarding: (data: Record<string, unknown>) =>
    request('/onboarding/complete', { method: 'POST', body: JSON.stringify(data) }),
}
