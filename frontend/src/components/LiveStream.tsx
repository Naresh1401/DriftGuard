import { useEffect, useState } from 'react'
import { Activity, Radio } from 'lucide-react'

type AlertEvt = {
  alert_id: string
  domain: string
  pattern: string
  level: string
  severity: number
  confidence: number
  ts: string
}

type PulseEvt = { ts: string; active_alerts: number; domains: string[] }

/**
 * LiveStream: subscribes to the SSE channel `/api/v1/stream/events` and
 * surfaces a small live indicator + recent alert ticker.
 */
export default function LiveStream() {
  const [connected, setConnected] = useState(false)
  const [pulse, setPulse] = useState<PulseEvt | null>(null)
  const [recent, setRecent] = useState<AlertEvt[]>([])

  useEffect(() => {
    const token = localStorage.getItem('driftguard_token')
    if (!token) return
    const host = (import.meta.env.VITE_API_URL as string) || ''
    const url = `${host}/api/v1/stream/events?token=${encodeURIComponent(token)}`
    const es = new EventSource(url)

    es.addEventListener('hello', () => setConnected(true))
    es.addEventListener('pulse', (e: MessageEvent) => {
      try {
        setPulse(JSON.parse(e.data))
      } catch {
        /* ignore */
      }
    })
    es.addEventListener('alert', (e: MessageEvent) => {
      try {
        const a = JSON.parse(e.data) as AlertEvt
        setRecent((prev) => [a, ...prev].slice(0, 5))
      } catch {
        /* ignore */
      }
    })
    es.onerror = () => setConnected(false)

    return () => es.close()
  }, [])

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2 text-sm font-medium text-gray-700">
          <Radio size={14} className={connected ? 'text-green-500' : 'text-gray-400'} />
          Live Signal Stream
          <span className={`text-xs px-2 py-0.5 rounded-full ${connected ? 'bg-green-50 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
            {connected ? 'connected' : 'offline'}
          </span>
        </div>
        {pulse && (
          <div className="text-xs text-gray-500 flex items-center gap-1">
            <Activity size={12} />
            {pulse.active_alerts} active · {pulse.domains.length} domain{pulse.domains.length === 1 ? '' : 's'}
          </div>
        )}
      </div>

      {recent.length === 0 ? (
        <div className="text-xs text-gray-400 italic">
          No new alerts on this channel. Pulse refreshes every ~3s.
        </div>
      ) : (
        <ul className="space-y-1.5">
          {recent.map((a) => (
            <li key={a.alert_id} className="flex items-center justify-between text-xs">
              <span className="truncate">
                <span className="font-mono text-gray-500 mr-2">{new Date(a.ts).toLocaleTimeString()}</span>
                <span className="font-medium text-gray-800">{a.pattern}</span>
                <span className="text-gray-500 mx-1">·</span>
                <span className="text-gray-600">{a.domain}</span>
              </span>
              <span
                className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                  a.level === 'critical'
                    ? 'bg-red-50 text-red-700'
                    : a.level === 'high'
                    ? 'bg-orange-50 text-orange-700'
                    : a.level === 'medium'
                    ? 'bg-yellow-50 text-yellow-700'
                    : 'bg-blue-50 text-blue-700'
                }`}
              >
                {a.level}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
