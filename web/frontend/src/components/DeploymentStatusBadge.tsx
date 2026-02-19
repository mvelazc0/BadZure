import type { DeploymentState } from '../types'

const stateConfig: Record<DeploymentState, { label: string; color: string; pulse: boolean }> = {
  idle: { label: 'Idle', color: 'bg-slate-500', pulse: false },
  deploying: { label: 'Deploying', color: 'bg-blue-500', pulse: true },
  deployed: { label: 'Deployed', color: 'bg-green-500', pulse: false },
  destroying: { label: 'Destroying', color: 'bg-yellow-500', pulse: true },
  error: { label: 'Error', color: 'bg-red-500', pulse: false },
}

export default function DeploymentStatusBadge({ state }: { state: DeploymentState }) {
  const config = stateConfig[state]
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="relative flex h-2.5 w-2.5">
        {config.pulse && (
          <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${config.color} opacity-75`} />
        )}
        <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${config.color}`} />
      </span>
      <span className="text-slate-300">{config.label}</span>
    </div>
  )
}
