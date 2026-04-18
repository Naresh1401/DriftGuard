import { Outlet, NavLink } from 'react-router-dom'
import { useAuth } from '../auth'
import {
  LayoutDashboard,
  AlertTriangle,
  Map,
  BookOpen,
  Globe,
  Shield,
  BarChart3,
  ChevronDown,
} from 'lucide-react'
import { useState } from 'react'
import clsx from 'clsx'
import type { UserRole } from '../types'

const ETHICAL_BANNER =
  'DriftGuard detects organizational patterns — never individual behavior. No employee is identified, profiled, or targeted.'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/alerts', label: 'Alert Center', icon: AlertTriangle },
  { to: '/drift-map', label: 'Drift Map', icon: Map },
  { to: '/calibration', label: 'NI Calibration', icon: BookOpen },
  { to: '/domains', label: 'Domains', icon: Globe },
  { to: '/governance', label: 'Governance', icon: Shield },
  { to: '/reports', label: 'Reports', icon: BarChart3 },
]

const ROLE_LABELS: Record<UserRole, string> = {
  compliance_officer: 'Compliance Officer',
  ciso: 'CISO',
  ni_architect: 'NI Architect',
  admin: 'Administrator',
  viewer: 'Viewer',
}

export default function Layout() {
  const { role, setRole } = useAuth()
  const [roleOpen, setRoleOpen] = useState(false)

  return (
    <div className="min-h-screen flex flex-col">
      {/* Ethical banner — permanent, non-dismissible */}
      <div className="bg-drift-800 text-white text-center text-xs py-1.5 px-4 font-medium tracking-wide">
        {ETHICAL_BANNER}
      </div>

      <div className="flex flex-1">
        {/* Sidebar */}
        <aside className="w-64 bg-white border-r border-gray-200 flex flex-col">
          <div className="p-6 border-b border-gray-100">
            <h1 className="text-xl font-bold text-drift-800 tracking-tight">
              DriftGuard
            </h1>
            <p className="text-xs text-gray-500 mt-0.5">
              Human-State Drift Detection
            </p>
          </div>

          <nav className="flex-1 py-4 space-y-0.5 px-3">
            {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                end={to === '/'}
                className={({ isActive }) =>
                  clsx(
                    'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-drift-50 text-drift-800'
                      : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                  )
                }
              >
                <Icon size={18} />
                {label}
              </NavLink>
            ))}
          </nav>

          {/* Role switcher (for demo/dev) */}
          <div className="p-4 border-t border-gray-100 relative">
            <button
              onClick={() => setRoleOpen(!roleOpen)}
              className="w-full flex items-center justify-between px-3 py-2 rounded-lg bg-gray-50 text-sm text-gray-700 hover:bg-gray-100"
            >
              <span className="font-medium">{ROLE_LABELS[role]}</span>
              <ChevronDown size={16} />
            </button>
            {roleOpen && (
              <div className="absolute bottom-full left-4 right-4 mb-1 bg-white border border-gray-200 rounded-lg shadow-lg z-50">
                {(Object.keys(ROLE_LABELS) as UserRole[]).map((r) => (
                  <button
                    key={r}
                    onClick={() => {
                      setRole(r)
                      setRoleOpen(false)
                    }}
                    className={clsx(
                      'w-full text-left px-3 py-2 text-sm hover:bg-gray-50 first:rounded-t-lg last:rounded-b-lg',
                      r === role ? 'text-drift-700 font-medium' : 'text-gray-600'
                    )}
                  >
                    {ROLE_LABELS[r]}
                  </button>
                ))}
              </div>
            )}
          </div>
        </aside>

        {/* Main content */}
        <main className="flex-1 overflow-auto">
          <div className="max-w-7xl mx-auto p-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
