import { useEffect, useRef, useState } from 'react'
import { useDeploymentStore } from '../store/deploymentStore'

const levelColors: Record<string, string> = {
  info: 'text-green-400',
  stdout: 'text-green-400',
  stderr: 'text-red-400',
  error: 'text-red-400',
  warning: 'text-yellow-400',
}

export default function LogTerminal() {
  const logs = useDeploymentStore((s) => s.logs)
  const containerRef = useRef<HTMLDivElement>(null)
  const [autoScroll, setAutoScroll] = useState(true)

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight
    }
  }, [logs, autoScroll])

  const handleScroll = () => {
    if (!containerRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current
    setAutoScroll(scrollHeight - scrollTop - clientHeight < 50)
  }

  const copyLogs = () => {
    const text = logs.map((l) => `[${l.level}] ${l.message}`).join('\n')
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="relative">
      <div className="flex justify-between items-center mb-2">
        <h3 className="text-sm font-semibold text-slate-400">Live Logs</h3>
        <div className="flex gap-2">
          {!autoScroll && (
            <button
              onClick={() => {
                setAutoScroll(true)
                if (containerRef.current) {
                  containerRef.current.scrollTop = containerRef.current.scrollHeight
                }
              }}
              className="text-xs px-2 py-1 rounded bg-slate-700 text-slate-300 hover:bg-slate-600"
            >
              Scroll to bottom
            </button>
          )}
          <button
            onClick={copyLogs}
            className="text-xs px-2 py-1 rounded bg-slate-700 text-slate-300 hover:bg-slate-600"
          >
            Copy
          </button>
        </div>
      </div>
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="bg-slate-900 rounded-lg border border-slate-700 p-3 h-80 overflow-y-auto font-mono text-xs leading-relaxed"
      >
        {logs.length === 0 ? (
          <span className="text-slate-500">Waiting for output...</span>
        ) : (
          logs.map((log, i) => (
            <div key={i} className={levelColors[log.level] ?? 'text-slate-300'}>
              {log.message}
            </div>
          ))
        )}
      </div>
    </div>
  )
}
