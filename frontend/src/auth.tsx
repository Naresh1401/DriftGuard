import { createContext, useContext, useState, useEffect, type ReactNode } from 'react'
import type { UserRole } from './types'

interface AuthState {
  role: UserRole
  setRole: (r: UserRole) => void
  authenticated: boolean
  login: (token: string, role: UserRole) => void
  logout: () => void
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [role, setRoleState] = useState<UserRole>(() => {
    return (localStorage.getItem('driftguard_role') as UserRole) || 'viewer'
  })
  const [authenticated, setAuthenticated] = useState(() => {
    return !!localStorage.getItem('driftguard_token')
  })

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
    <AuthContext.Provider value={{ role, setRole, authenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
