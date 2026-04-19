import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../auth'
import { api } from '../api'
import { Shield, Eye, EyeOff, AlertCircle, Loader2 } from 'lucide-react'
import type { UserRole } from '../types'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()

  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [fullName, setFullName] = useState('')
  const [organization, setOrganization] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      let res: { access_token: string; role: string; email: string; full_name: string }
      if (mode === 'login') {
        res = await api.login(email, password)
      } else {
        if (!fullName.trim()) {
          setError('Full name is required')
          setLoading(false)
          return
        }
        res = await api.register(email, password, fullName, organization)
      }
      login(res.access_token, res.role as UserRole)
      navigate('/', { replace: true })
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Something went wrong'
      // Extract the meaningful part from "API 4XX: ..."
      const match = msg.match(/API \d+: (.+)/)
      if (match) {
        try {
          const parsed = JSON.parse(match[1])
          setError(parsed.detail || match[1])
        } catch {
          setError(match[1])
        }
      } else {
        setError(msg)
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-drift-900 via-drift-800 to-gray-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo / Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-drift-600 rounded-2xl mb-4">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">DriftGuard</h1>
          <p className="text-drift-300 text-sm mt-1">Human-State Drift Detection</p>
        </div>

        {/* Card */}
        <div className="bg-white rounded-2xl shadow-2xl p-8">
          {/* Mode tabs */}
          <div className="flex rounded-lg bg-gray-100 p-1 mb-6">
            <button
              type="button"
              onClick={() => { setMode('login'); setError('') }}
              className={`flex-1 py-2 text-sm font-medium rounded-md transition-colors ${
                mode === 'login' ? 'bg-white text-drift-800 shadow-sm' : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => { setMode('register'); setError('') }}
              className={`flex-1 py-2 text-sm font-medium rounded-md transition-colors ${
                mode === 'register' ? 'bg-white text-drift-800 shadow-sm' : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              Create Account
            </button>
          </div>

          {/* Error display */}
          {error && (
            <div className="flex items-start gap-2 bg-red-50 border border-red-200 text-red-700 rounded-lg p-3 mb-4 text-sm">
              <AlertCircle size={16} className="mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'register' && (
              <>
                <div>
                  <label htmlFor="fullName" className="block text-sm font-medium text-gray-700 mb-1">
                    Full Name
                  </label>
                  <input
                    id="fullName"
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    required
                    minLength={2}
                    maxLength={200}
                    autoComplete="name"
                    className="w-full px-3 py-2.5 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-drift-500 focus:border-drift-500 outline-none transition-colors"
                    placeholder="Jane Smith"
                  />
                </div>
                <div>
                  <label htmlFor="organization" className="block text-sm font-medium text-gray-700 mb-1">
                    Organization <span className="text-gray-400">(optional)</span>
                  </label>
                  <input
                    id="organization"
                    type="text"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    maxLength={200}
                    autoComplete="organization"
                    className="w-full px-3 py-2.5 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-drift-500 focus:border-drift-500 outline-none transition-colors"
                    placeholder="Acme Corp"
                  />
                </div>
              </>
            )}

            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                Email
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                className="w-full px-3 py-2.5 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-drift-500 focus:border-drift-500 outline-none transition-colors"
                placeholder="you@company.com"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  minLength={8}
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  className="w-full px-3 py-2.5 pr-10 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-drift-500 focus:border-drift-500 outline-none transition-colors"
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              {mode === 'register' && (
                <p className="text-xs text-gray-400 mt-1.5">
                  Min 8 chars, with uppercase, lowercase, number & special character
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 bg-drift-700 hover:bg-drift-800 disabled:bg-drift-400 text-white font-medium rounded-lg text-sm transition-colors flex items-center justify-center gap-2"
            >
              {loading && <Loader2 size={16} className="animate-spin" />}
              {mode === 'login' ? 'Sign In' : 'Create Account'}
            </button>
          </form>

          {/* Ethical note */}
          <div className="mt-6 pt-4 border-t border-gray-100">
            <p className="text-xs text-gray-400 text-center leading-relaxed">
              DriftGuard detects organizational patterns — never individual behavior.
              No employee is identified, profiled, or targeted.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
