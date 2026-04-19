import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './auth'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import AlertCenter from './pages/AlertCenter'
import DriftMap from './pages/DriftMap'
import Calibration from './pages/Calibration'
import Domains from './pages/Domains'
import Governance from './pages/Governance'
import Reports from './pages/Reports'
import Onboarding from './pages/Onboarding'
import DataCollection from './pages/DataCollection'
import LiveScanner from './pages/LiveScanner'
import ThreatIntel from './pages/ThreatIntel'
import Scans from './pages/Scans'
import type { ReactNode } from 'react'

function RequireAuth({ children }: { children: ReactNode }) {
  const { authenticated } = useAuth()
  if (!authenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

function GuestOnly({ children }: { children: ReactNode }) {
  const { authenticated } = useAuth()
  if (authenticated) return <Navigate to="/" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<GuestOnly><Login /></GuestOnly>} />
        <Route path="/onboarding" element={<Onboarding />} />
        <Route element={<RequireAuth><Layout /></RequireAuth>}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<AlertCenter />} />
          <Route path="/drift-map" element={<DriftMap />} />
          <Route path="/calibration" element={<Calibration />} />
          <Route path="/domains" element={<Domains />} />
          <Route path="/data-collection" element={<DataCollection />} />
          <Route path="/live-scanner" element={<LiveScanner />} />
          <Route path="/governance" element={<Governance />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/threat-intel" element={<ThreatIntel />} />
          <Route path="/scans" element={<Scans />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  )
}
