import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../auth'
import { CheckCircle, Globe, Shield, Zap } from 'lucide-react'
import clsx from 'clsx'
import type { UserRole } from '../types'
import { api } from '../api'

const STEPS = [
  {
    title: 'Select Your Domain',
    description: 'Choose the industry vertical that best matches your organization.',
    icon: Globe,
  },
  {
    title: 'Configure Your Role',
    description: 'Select your primary role to customize your dashboard view.',
    icon: Shield,
  },
  {
    title: 'Connect Data Sources',
    description: 'Connect your SIEM, cloud audit, or workspace signals.',
    icon: Zap,
  },
]

const DOMAINS = [
  { id: 'healthcare', name: 'Healthcare', desc: 'HIPAA-aware clinical monitoring' },
  { id: 'finance', name: 'Finance', desc: 'SOX/PCI DSS compliance' },
  { id: 'government', name: 'Government', desc: 'FedRAMP/FISMA alignment' },
  { id: 'retail', name: 'Retail', desc: 'PCI DSS retail monitoring' },
  { id: 'education', name: 'Education', desc: 'FERPA student data protection' },
  { id: 'enterprise', name: 'Enterprise', desc: 'General cybersecurity monitoring' },
]

const ROLES: { id: UserRole; name: string; desc: string }[] = [
  { id: 'compliance_officer', name: 'Compliance Officer', desc: 'Plain language dashboards and reports' },
  { id: 'ciso', name: 'CISO', desc: 'Full technical depth, NIST controls, risk matrices' },
  { id: 'ni_architect', name: 'NI Architect', desc: 'Calibration feedback and content management' },
  { id: 'admin', name: 'Administrator', desc: 'Full system access and configuration' },
]

const CONNECTORS = [
  { id: 'splunk', name: 'Splunk', desc: 'SIEM integration via REST API' },
  { id: 'sentinel', name: 'Microsoft Sentinel', desc: 'Azure Log Analytics' },
  { id: 'cloudtrail', name: 'AWS CloudTrail', desc: 'Cloud audit logs' },
  { id: 'google_workspace', name: 'Google Workspace', desc: 'Admin and login audit' },
  { id: 'epic_emr', name: 'Epic EMR', desc: 'Healthcare FHIR AuditEvent' },
]

export default function Onboarding() {
  const navigate = useNavigate()
  const { setRole } = useAuth()
  const [step, setStep] = useState(0)
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null)
  const [selectedRole, setSelectedRole] = useState<UserRole | null>(null)
  const [selectedConnectors, setSelectedConnectors] = useState<string[]>([])

  function handleNext() {
    if (step < 2) {
      setStep(step + 1)
    } else {
      // Save onboarding to backend
      api.completeOnboarding({
        domain: selectedDomain || 'enterprise',
        step1: { domain: selectedDomain || 'enterprise' },
        step2: { connectors: selectedConnectors.map(c => ({ connector_type: c, config: {} })), sample_file_mode: false },
        step3: { alert_sensitivity: 'balanced', priority_nist_controls: [], response_delivery: ['dashboard'] },
      }).catch(() => { /* proceed even if save fails */ })
      if (selectedRole) setRole(selectedRole)
      navigate('/')
    }
  }

  function toggleConnector(id: string) {
    setSelectedConnectors((prev) =>
      prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]
    )
  }

  const canProceed =
    (step === 0 && selectedDomain) ||
    (step === 1 && selectedRole) ||
    step === 2

  return (
    <div className="min-h-screen bg-gradient-to-br from-drift-50 to-white flex items-center justify-center p-6">
      <div className="max-w-2xl w-full">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-drift-800">Welcome to DriftGuard</h1>
          <p className="text-gray-500 mt-2">Human-State Drift Detection System</p>
        </div>

        {/* Step indicator */}
        <div className="flex items-center justify-center gap-2 sm:gap-4 mb-8">
          {STEPS.map((s, i) => (
            <div key={i} className="flex items-center gap-1 sm:gap-2">
              <div
                className={clsx(
                  'w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold shrink-0',
                  i < step
                    ? 'bg-green-500 text-white'
                    : i === step
                      ? 'bg-drift-700 text-white'
                      : 'bg-gray-200 text-gray-500'
                )}
              >
                {i < step ? <CheckCircle size={16} /> : i + 1}
              </div>
              <span className={clsx('text-xs sm:text-sm hidden sm:inline', i === step ? 'text-gray-900 font-medium' : 'text-gray-500')}>
                {s.title}
              </span>
              {i < 2 && <div className="w-6 sm:w-12 h-px bg-gray-300" />}
            </div>
          ))}
        </div>

        {/* Step content */}
        <div className="card">
          <div className="flex items-center gap-3 mb-6">
            {(() => {
              const Icon = STEPS[step].icon
              return <Icon size={24} className="text-drift-700" />
            })()}
            <div>
              <h2 className="text-lg font-semibold text-gray-900">{STEPS[step].title}</h2>
              <p className="text-sm text-gray-500">{STEPS[step].description}</p>
            </div>
          </div>

          {step === 0 && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {DOMAINS.map((d) => (
                <button
                  key={d.id}
                  onClick={() => setSelectedDomain(d.id)}
                  className={clsx(
                    'p-4 rounded-lg border-2 text-left transition-all',
                    selectedDomain === d.id
                      ? 'border-drift-600 bg-drift-50'
                      : 'border-gray-200 hover:border-gray-300'
                  )}
                >
                  <p className="font-medium text-gray-900">{d.name}</p>
                  <p className="text-xs text-gray-500 mt-1">{d.desc}</p>
                </button>
              ))}
            </div>
          )}

          {step === 1 && (
            <div className="space-y-3">
              {ROLES.map((r) => (
                <button
                  key={r.id}
                  onClick={() => setSelectedRole(r.id)}
                  className={clsx(
                    'w-full p-4 rounded-lg border-2 text-left transition-all',
                    selectedRole === r.id
                      ? 'border-drift-600 bg-drift-50'
                      : 'border-gray-200 hover:border-gray-300'
                  )}
                >
                  <p className="font-medium text-gray-900">{r.name}</p>
                  <p className="text-xs text-gray-500 mt-1">{r.desc}</p>
                </button>
              ))}
            </div>
          )}

          {step === 2 && (
            <div className="space-y-3">
              <p className="text-xs text-gray-500 mb-4">
                Select one or more data sources. You can configure connection details later.
              </p>
              {CONNECTORS.map((c) => (
                <button
                  key={c.id}
                  onClick={() => toggleConnector(c.id)}
                  className={clsx(
                    'w-full p-4 rounded-lg border-2 text-left transition-all flex items-center gap-3',
                    selectedConnectors.includes(c.id)
                      ? 'border-drift-600 bg-drift-50'
                      : 'border-gray-200 hover:border-gray-300'
                  )}
                >
                  <div
                    className={clsx(
                      'w-5 h-5 rounded border-2 flex items-center justify-center',
                      selectedConnectors.includes(c.id)
                        ? 'bg-drift-600 border-drift-600'
                        : 'border-gray-300'
                    )}
                  >
                    {selectedConnectors.includes(c.id) && (
                      <CheckCircle size={14} className="text-white" />
                    )}
                  </div>
                  <div>
                    <p className="font-medium text-gray-900">{c.name}</p>
                    <p className="text-xs text-gray-500">{c.desc}</p>
                  </div>
                </button>
              ))}
              <p className="text-xs text-gray-400 mt-2">
                Skip this step to use demo data
              </p>
            </div>
          )}

          {/* Actions */}
          <div className="mt-6 flex items-center justify-between">
            {step > 0 ? (
              <button onClick={() => setStep(step - 1)} className="btn-secondary">
                Back
              </button>
            ) : (
              <div />
            )}
            <button onClick={handleNext} disabled={!canProceed} className="btn-primary disabled:opacity-50">
              {step === 2 ? 'Launch DriftGuard' : 'Continue'}
            </button>
          </div>
        </div>

        {/* Ethical notice */}
        <p className="text-center text-xs text-gray-400 mt-6 max-w-md mx-auto">
          DriftGuard detects organizational patterns — never individual behavior.
          No employee is identified, profiled, or targeted.
        </p>
      </div>
    </div>
  )
}
