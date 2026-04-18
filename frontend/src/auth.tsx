import { createContext, useContext, useState, useMemo, type ReactNode } from 'react'
import type { UserRole } from './types'

/* ── Permission definitions ─────────────────────────── */
export type Permission =
  | 'view_dashboard'
  | 'view_alerts'
  | 'acknowledge_alert'
  | 'resolve_alert'
  | 'view_drift_map'
  | 'view_calibration'
  | 'approve_calibration'
  | 'view_domains'
  | 'manage_domains'
  | 'view_governance'
  | 'approve_governance'
  | 'view_reports_weekly'
  | 'view_reports_nist'
  | 'view_reports_board'
  | 'view_nist_detail'

const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  admin: [
    'view_dashboard', 'view_alerts', 'acknowledge_alert', 'resolve_alert',
    'view_drift_map', 'view_calibration', 'approve_calibration',
    'view_domains', 'manage_domains', 'view_governance', 'approve_governance',
    'view_reports_weekly', 'view_reports_nist', 'view_reports_board', 'view_nist_detail',
  ],
  ciso: [
    'view_dashboard', 'view_alerts', 'acknowledge_alert', 'resolve_alert',
    'view_drift_map', 'view_calibration',
    'view_domains', 'view_governance', 'approve_governance',
    'view_reports_weekly', 'view_reports_nist', 'view_reports_board', 'view_nist_detail',
  ],
  ni_architect: [
    'view_dashboard', 'view_alerts',
    'view_drift_map', 'view_calibration', 'approve_calibration',
    'view_governance', 'approve_governance',
    'view_reports_weekly', 'view_reports_nist',
  ],
  compliance_officer: [
    'view_dashboard', 'view_alerts', 'acknowledge_alert', 'resolve_alert',
    'view_drift_map', 'view_calibration',
    'view_governance',
    'view_reports_weekly', 'view_reports_nist',
  ],
  viewer: [
    'view_dashboard', 'view_alerts',
    'view_drift_map',
    'view_reports_weekly',
  ],
}

/* ── Nav visibility per role ────────────────────────── */
export const NAV_ACCESS: Record<string, UserRole[]> = {
  '/':             ['admin', 'ciso', 'ni_architect', 'compliance_officer', 'viewer'],
  '/alerts':       ['admin', 'ciso', 'ni_architect', 'compliance_officer', 'viewer'],
  '/drift-map':    ['admin', 'ciso', 'ni_architect', 'compliance_officer', 'viewer'],
  '/calibration':  ['admin', 'ciso', 'ni_architect', 'compliance_officer'],
  '/domains':      ['admin', 'ciso'],
  '/governance':   ['admin', 'ciso', 'ni_architect', 'compliance_officer'],
  '/reports':      ['admin', 'ciso', 'ni_architect', 'compliance_officer'],
}

/* ── Context ─────────────────────────────────────────── */
interface AuthState {
  role: UserRole
  setRole: (r: UserRole) => void
  authenticated: boolean
  login: (token: string, role: UserRole) => void
  logout: () => void
  can: (p: Permission) => boolean
  permissions: Permission[]
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [role, setRoleState] = useState<UserRole>(() => {
    return (localStorage.getItem('driftguard_role') as UserRole) || 'viewer'
  })
  const [authenticated, setAuthenticated] = useState(() => {
    return !!localStorage.getItem('driftguard_token')
  })

  const permissions = useMemo(() => ROLE_PERMISSIONS[role] ?? [], [role])
  const can = useMemo(() => {
    const set = new Set(permissions)
    return (p: Permission) => set.has(p)
  }, [permissions])

  function setRole(r: UserRole) {
    setRoleState(r)
    localStorage.setItem('driftguard_role', r)
  }

  function login(token: string, r: UserRole) {
    localStorage.setItem('driftguard_token', token)
    localStorage.setItem('driftguard_role', r)
    setAuthenticated(true)
    setRoleState(r)
  }

  function logout() {
    localStorage.removeItem('driftguard_token')
    localStorage.removeItem('driftguard_role')
    setAuthenticated(false)
    setRoleState('viewer')
  }

  return (
    <AuthContext.Provider value={{ role, setRole, authenticated, login, logout, can, permissions }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
