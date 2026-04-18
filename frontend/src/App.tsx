import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './auth'
import Layout from './components/Layout'
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

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/onboarding" element={<Onboarding />} />
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<AlertCenter />} />
          <Route path="/drift-map" element={<DriftMap />} />
          <Route path="/calibration" element={<Calibration />} />
          <Route path="/domains" element={<Domains />} />
          <Route path="/data-collection" element={<DataCollection />} />
          <Route path="/live-scanner" element={<LiveScanner />} />
          <Route path="/governance" element={<Governance />} />
          <Route path="/reports" element={<Reports />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  )
}
