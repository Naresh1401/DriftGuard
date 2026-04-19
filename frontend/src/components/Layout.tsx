import { useState } from 'react'
import { Outlet, NavLink, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useAuth, NAV_ACCESS } from '../auth'
import {
  LayoutDashboard,
  AlertTriangle,
  Map,
  BookOpen,
  Globe,
  Shield,
  BarChart3,
  DatabaseZap,
  Radar,
  ShieldAlert,
  ScanSearch,
  LogOut,
  Menu,
  X,
} from 'lucide-react'
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
  { to: '/data-collection', label: 'Data Collection', icon: DatabaseZap },
  { to: '/live-scanner', label: 'Live Scanner', icon: Radar },
  { to: '/governance', label: 'Governance', icon: Shield },
  { to: '/reports', label: 'Reports', icon: BarChart3 },
  { to: '/threat-intel', label: 'Threat Intel', icon: ShieldAlert },
  { to: '/scans', label: 'Scans', icon: ScanSearch },
]

const ROLE_LABELS: Record<UserRole, string> = {
  compliance_officer: 'Compliance Officer',
  ciso: 'CISO',
  ni_architect: 'NI Architect',
  admin: 'Administrator',
  viewer: 'Viewer',
}

const ROLE_DESCRIPTIONS: Record<UserRole, string> = {
  admin: 'Full system access',
  ciso: 'Risk analysis & NIST',
  ni_architect: 'Calibration & approval',
  compliance_officer: 'Alerts & compliance',
  viewer: 'Read-only access',
}

const ROLE_COLORS: Record<UserRole, string> = {
  admin: 'bg-purple-100 text-purple-700 border-purple-200',
  ciso: 'bg-red-100 text-red-700 border-red-200',
  ni_architect: 'bg-indigo-100 text-indigo-700 border-indigo-200',
  compliance_officer: 'bg-blue-100 text-blue-700 border-blue-200',
  viewer: 'bg-gray-100 text-gray-600 border-gray-200',
}

export default function Layout() {
  const { role, logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  // Route guard: redirect to dashboard if user navigates to a restricted page
  const currentPath = location.pathname
  const allowedRoles = NAV_ACCESS[currentPath]
  if (allowedRoles && !allowedRoles.includes(role)) {
    return <Navigate to="/" replace />
  }

  const visibleNav = NAV_ITEMS.filter(({ to }) => {
    const roles = NAV_ACCESS[to]
    return !roles || roles.includes(role)
  })

  const sidebarContent = (
    <>
      <div className="p-6 border-b border-gray-100 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-drift-800 tracking-tight">
            DriftGuard
          </h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Human-State Drift Detection
          </p>
        </div>
        <button
          onClick={() => setSidebarOpen(false)}
          className="lg:hidden p-1.5 rounded-lg hover:bg-gray-100 text-gray-500"
          aria-label="Close sidebar"
        >
          <X size={20} />
        </button>
      </div>

      <nav className="flex-1 py-4 space-y-0.5 px-3 overflow-y-auto">
        {visibleNav.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            onClick={() => setSidebarOpen(false)}
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

      {/* User info & logout */}
      <div className="p-4 border-t border-gray-100">
        <div className="mb-3">
          <span className={clsx('inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold border', ROLE_COLORS[role])}>
            {ROLE_LABELS[role]}
          </span>
          <p className="text-xs text-gray-400 mt-1">{ROLE_DESCRIPTIONS[role]}</p>
        </div>
        <button
          onClick={() => { logout(); navigate('/login') }}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-gray-50 text-sm text-gray-600 hover:bg-red-50 hover:text-red-600 transition-colors"
        >
          <LogOut size={16} />
          <span>Sign Out</span>
        </button>
      </div>
    </>
  )

  return (
    <div className="min-h-screen flex flex-col">
      {/* Ethical banner — permanent, non-dismissible */}
      <div className="bg-drift-800 text-white text-center text-xs py-1.5 px-4 font-medium tracking-wide">
        {ETHICAL_BANNER}
      </div>

      {/* Mobile header with hamburger */}
      <div className="lg:hidden flex items-center justify-between px-4 py-3 bg-white border-b border-gray-200">
        <div>
          <h1 className="text-lg font-bold text-drift-800">DriftGuard</h1>
        </div>
        <button
          onClick={() => setSidebarOpen(true)}
          className="p-2 rounded-lg hover:bg-gray-100 text-gray-600"
          aria-label="Open menu"
        >
          <Menu size={22} />
        </button>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Mobile sidebar overlay */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 z-40 bg-black/40 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}

        {/* Mobile sidebar drawer */}
        <aside
          className={clsx(
            'fixed inset-y-0 left-0 z-50 w-72 bg-white border-r border-gray-200 flex flex-col transform transition-transform duration-200 ease-in-out lg:hidden',
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          )}
        >
          {sidebarContent}
        </aside>

        {/* Desktop sidebar — always visible on lg+ */}
        <aside className="hidden lg:flex w-64 bg-white border-r border-gray-200 flex-col shrink-0">
          {sidebarContent}
        </aside>

        {/* Main content */}
        <main className="flex-1 overflow-auto min-w-0">
          <div className="max-w-7xl mx-auto p-4 sm:p-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
