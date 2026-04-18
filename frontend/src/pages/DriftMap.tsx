import { useState } from 'react'
import clsx from 'clsx'
import type { DriftPattern } from '../types'
import { PatternTag } from '../components/Shared'

const PATTERNS: DriftPattern[] = [
  'Fatigue',
  'Overconfidence',
  'Hurry',
  'Quiet_Fear',
  'Hoarding',
  'Compliance_Theater',
]

const DEPARTMENTS = ['SOC', 'Engineering', 'Compliance', 'HR', 'Finance', 'Clinical IT', 'DevOps', 'Legal']

// Demo heatmap data: department × pattern → severity
const HEATMAP_DATA: Record<string, Record<DriftPattern, number>> = {
  SOC: { Fatigue: 3, Overconfidence: 1, Hurry: 2, Quiet_Fear: 1, Hoarding: 0, Compliance_Theater: 1 },
  Engineering: { Fatigue: 2, Overconfidence: 3, Hurry: 3, Quiet_Fear: 0, Hoarding: 1, Compliance_Theater: 0 },
  Compliance: { Fatigue: 1, Overconfidence: 1, Hurry: 1, Quiet_Fear: 2, Hoarding: 0, Compliance_Theater: 4 },
  HR: { Fatigue: 1, Overconfidence: 0, Hurry: 1, Quiet_Fear: 3, Hoarding: 2, Compliance_Theater: 1 },
  Finance: { Fatigue: 1, Overconfidence: 2, Hurry: 1, Quiet_Fear: 1, Hoarding: 3, Compliance_Theater: 2 },
  'Clinical IT': { Fatigue: 3, Overconfidence: 1, Hurry: 4, Quiet_Fear: 2, Hoarding: 0, Compliance_Theater: 1 },
  DevOps: { Fatigue: 2, Overconfidence: 2, Hurry: 3, Quiet_Fear: 0, Hoarding: 1, Compliance_Theater: 0 },
  Legal: { Fatigue: 0, Overconfidence: 1, Hurry: 1, Quiet_Fear: 2, Hoarding: 2, Compliance_Theater: 2 },
}

const SEVERITY_COLORS = [
  'bg-gray-100',     // 0 - none
  'bg-green-200',    // 1
  'bg-yellow-200',   // 2
  'bg-orange-300',   // 3
  'bg-red-400',      // 4
  'bg-red-600',      // 5
]

const PATTERN_DESCRIPTIONS: Record<DriftPattern, string> = {
  Fatigue: 'Sustained workload leading to reduced vigilance and mechanical compliance. The person is not negligent — they are exhausted.',
  Overconfidence: 'Accumulated expertise bypassing safety protocols. The expert believes they no longer need the net.',
  Hurry: 'Deadline pressure compressing validation into formality. Shortcuts taken now become permanent configurations.',
  Quiet_Fear: 'Known issues going unreported because the cost of speaking up feels higher than the cost of silence.',
  Hoarding: 'Access and authority accumulating beyond role requirements. Not malicious — but concentrated access is concentrated risk.',
  Compliance_Theater: 'Audit scores are high but security outcomes are not changing. The most dangerous pattern because it generates false confidence.',
}

export default function DriftMap() {
  const [selected, setSelected] = useState<{ dept: string; pattern: DriftPattern } | null>(null)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Drift Map</h1>
        <p className="text-sm text-gray-500 mt-1">
          Organizational heatmap — drift pattern severity by department
        </p>
      </div>

      {/* Heatmap */}
      <div className="card overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr>
              <th className="text-left text-xs font-medium text-gray-500 pb-3 pr-4">Department</th>
              {PATTERNS.map((p) => (
                <th key={p} className="text-center text-xs font-medium text-gray-500 pb-3 px-2">
                  {p.replace(/_/g, ' ')}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {DEPARTMENTS.map((dept) => (
              <tr key={dept} className="border-t border-gray-50">
                <td className="py-2 pr-4 text-sm font-medium text-gray-700">{dept}</td>
                {PATTERNS.map((pattern) => {
                  const severity = HEATMAP_DATA[dept]?.[pattern] ?? 0
                  const isSelected = selected?.dept === dept && selected?.pattern === pattern
                  return (
                    <td key={pattern} className="py-2 px-2">
                      <button
                        onClick={() =>
                          setSelected(
                            isSelected ? null : { dept, pattern }
                          )
                        }
                        className={clsx(
                          'w-full h-10 rounded-md transition-all',
                          SEVERITY_COLORS[severity],
                          isSelected && 'ring-2 ring-drift-600 ring-offset-1',
                          severity > 0 && 'hover:ring-2 hover:ring-gray-300 cursor-pointer'
                        )}
                        title={`${dept} — ${pattern.replace(/_/g, ' ')}: severity ${severity}`}
                      />
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>

        {/* Legend */}
        <div className="mt-4 flex items-center gap-3 text-xs text-gray-500">
          <span>Severity:</span>
          {['None', '1', '2', '3', '4', '5'].map((label, i) => (
            <div key={i} className="flex items-center gap-1">
              <div className={clsx('w-4 h-4 rounded', SEVERITY_COLORS[i])} />
              <span>{label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Detail panel */}
      {selected && (
        <div className="card border-l-4 border-l-drift-600">
          <div className="flex items-center gap-3 mb-3">
            <PatternTag pattern={selected.pattern} />
            <span className="text-sm font-medium text-gray-700">{selected.dept}</span>
            <span className="text-xs text-gray-500">
              Severity: {HEATMAP_DATA[selected.dept]?.[selected.pattern] ?? 0}/5
            </span>
          </div>
          <p className="text-sm text-gray-700">
            {PATTERN_DESCRIPTIONS[selected.pattern]}
          </p>
          <div className="mt-3 text-xs text-gray-500">
            This is an organizational pattern observation — not an individual performance indicator.
          </div>
        </div>
      )}
    </div>
  )
}
