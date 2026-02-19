import { useState } from 'react'
import { useDeploymentStatus } from '../hooks/useDeploymentStatus'
import { useDeploymentStore } from '../store/deploymentStore'
import { api } from '../api/client'
import DeploymentStatusBadge from '../components/DeploymentStatusBadge'
import ResourceList from '../components/ResourceList'
import LogTerminal from '../components/LogTerminal'
import ConfirmDialog from '../components/ConfirmDialog'

export default function StatusPage() {
  const { data: status } = useDeploymentStatus()
  const clearLogs = useDeploymentStore((s) => s.clearLogs)
  const [showConfirm, setShowConfirm] = useState(false)

  const state = status?.state ?? 'idle'
  const canDestroy = state === 'deployed' || state === 'error'
  const isDestroying = state === 'destroying'

  const handleDestroy = async () => {
    setShowConfirm(false)
    clearLogs()
    try {
      await api.destroy()
    } catch (err) {
      console.error('Destroy failed:', err)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-start">
        <div>
          <h2 className="text-2xl font-bold text-white">Deployment Status</h2>
          <div className="mt-2">
            <DeploymentStatusBadge state={state} />
          </div>
        </div>
        {canDestroy && (
          <button
            onClick={() => setShowConfirm(true)}
            className="px-4 py-2 text-sm rounded-lg bg-red-600 text-white hover:bg-red-500 font-medium"
          >
            Destroy Environment
          </button>
        )}
      </div>

      {/* Timing info */}
      {status?.started_at && (
        <div className="text-sm text-slate-400 space-y-1">
          <p>Started: {new Date(status.started_at).toLocaleString()}</p>
          {status.completed_at && (
            <p>Completed: {new Date(status.completed_at).toLocaleString()}</p>
          )}
        </div>
      )}

      {/* Error message */}
      {status?.error_message && (
        <div className="bg-red-900/20 border border-red-800 rounded-lg p-4">
          <p className="text-sm text-red-400">{status.error_message}</p>
        </div>
      )}

      {/* Active scenarios */}
      {status?.scenario_ids && status.scenario_ids.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-slate-400 mb-2">Deployed Scenarios</h3>
          <div className="flex flex-wrap gap-2">
            {status.scenario_ids.map((id) => (
              <span key={id} className="px-3 py-1 rounded-full bg-slate-700 text-slate-300 text-xs">
                {id}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Resources */}
      {state === 'deployed' && status?.resources && (
        <ResourceList resources={status.resources} />
      )}

      {/* Log terminal (visible during deploy/destroy operations) */}
      {(isDestroying || state === 'deploying' || state === 'error') && (
        <LogTerminal />
      )}

      {/* Idle state */}
      {state === 'idle' && (
        <div className="text-center py-12 text-slate-500">
          No active deployment. Select scenarios from the catalog to get started.
        </div>
      )}

      {/* Confirm dialog */}
      {showConfirm && (
        <ConfirmDialog
          title="Destroy Environment"
          message="This will destroy all resources created by the current deployment. This action cannot be undone."
          confirmLabel="Destroy"
          onConfirm={handleDestroy}
          onCancel={() => setShowConfirm(false)}
        />
      )}
    </div>
  )
}
