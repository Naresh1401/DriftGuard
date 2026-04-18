import clsx from 'clsx'
import type { AlertLevel } from '../types'

interface Props {
  score: number
  size?: 'sm' | 'lg'
}

function scoreColor(score: number): string {
  if (score >= 80) return 'text-green-600'
  if (score >= 60) return 'text-yellow-600'
  if (score >= 40) return 'text-orange-500'
  return 'text-red-600'
}

function scoreLabel(score: number): string {
  if (score >= 80) return 'Healthy'
  if (score >= 60) return 'Moderate'
  if (score >= 40) return 'Elevated Risk'
  return 'Critical'
}

export function HealthScoreGauge({ score, size = 'lg' }: Props) {
  const radius = size === 'lg' ? 80 : 40
  const stroke = size === 'lg' ? 12 : 8
  const circumference = 2 * Math.PI * radius
  const progress = ((100 - score) / 100) * circumference

  return (
    <div className="flex flex-col items-center">
      <svg
        width={(radius + stroke) * 2}
        height={(radius + stroke) * 2}
        className="transform -rotate-90"
      >
        <circle
          cx={radius + stroke}
          cy={radius + stroke}
          r={radius}
          fill="none"
          stroke="#e5e7eb"
          strokeWidth={stroke}
        />
        <circle
          cx={radius + stroke}
          cy={radius + stroke}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={stroke}
          strokeDasharray={circumference}
          strokeDashoffset={progress}
          strokeLinecap="round"
          className={clsx('transition-all duration-700', scoreColor(score))}
        />
      </svg>
      <div className="absolute flex flex-col items-center justify-center" style={{ marginTop: size === 'lg' ? 40 : 16 }}>
        <span className={clsx('font-bold', scoreColor(score), size === 'lg' ? 'text-4xl' : 'text-xl')}>
          {score}
        </span>
        <span className="text-xs text-gray-500 mt-1">{scoreLabel(score)}</span>
      </div>
    </div>
  )
}

export function AlertBadge({ level }: { level: AlertLevel }) {
  return (
    <span
      className={clsx(
        level === 'Watch' && 'badge-watch',
        level === 'Warning' && 'badge-warning',
        level === 'Critical' && 'badge-critical'
      )}
    >
      {level}
    </span>
  )
}

export function SeverityDot({ severity }: { severity: number }) {
  const colors: Record<number, string> = {
    1: 'bg-severity-1',
    2: 'bg-severity-2',
    3: 'bg-severity-3',
    4: 'bg-severity-4',
    5: 'bg-severity-5',
  }
  return (
    <span className={clsx('inline-block w-3 h-3 rounded-full', colors[severity] || 'bg-gray-400')} />
  )
}

export function PatternTag({ pattern }: { pattern: string }) {
  const display = pattern.replace(/_/g, ' ')
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-drift-100 text-drift-800">
      {display}
    </span>
  )
}

export function LoadingSpinner() {
  return (
    <div className="flex items-center justify-center py-12">
      <div className="w-8 h-8 border-4 border-drift-200 border-t-drift-600 rounded-full animate-spin" />
    </div>
  )
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="text-center py-12 text-gray-500">
      <p>{message}</p>
    </div>
  )
}
