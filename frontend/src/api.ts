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
    const body = await res.text()
    throw new Error(`API ${res.status}: ${body}`)
  }
  return res.json()
}

export const api = {
  // Health
  health: () => request<{ status: string }>('/health'),

  // Alerts
  getAlerts: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<{ alerts: import('./types').Alert[]; total: number }>(`/alerts${qs}`)
  },
  acknowledgeAlert: (id: string) =>
    request(`/alerts/${id}/acknowledge`, { method: 'POST' }),
  resolveAlert: (id: string) =>
    request(`/alerts/${id}/resolve`, { method: 'POST' }),
  getHealthScore: () =>
    request<import('./types').HealthScore>('/alerts/health-score'),

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
    request<import('./types').CalibrationResponse[]>('/calibration/responses'),
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

  // Governance
  getPendingActions: () =>
    request<import('./types').GovernanceAction[]>('/governance/pending'),
  getAuditLog: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<{ entries: unknown[]; total: number }>(`/governance/audit-log${qs}`)
  },

  // Reports
  getWeeklyReport: () =>
    request<import('./types').WeeklyReport>('/reports/weekly'),
  getTrendData: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<import('./types').TrendDataPoint[]>(`/reports/trend${qs}`)
  },
  getNISTRiskMatrix: () =>
    request<Record<string, unknown>>('/reports/nist-risk-matrix'),
  getBoardSummary: () =>
    request<Record<string, unknown>>('/reports/board-summary'),

  // Onboarding
  getOnboardingStatus: () =>
    request<{ steps: import('./types').OnboardingStep[]; completed: boolean }>('/onboarding/status'),
  completeOnboardingStep: (step: number, data: Record<string, unknown>) =>
    request(`/onboarding/step/${step}`, { method: 'POST', body: JSON.stringify(data) }),
}
