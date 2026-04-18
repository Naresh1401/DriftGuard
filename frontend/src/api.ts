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
