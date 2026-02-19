import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { useDeploymentStore } from '../store/deploymentStore'
import { useDeploymentStatus } from '../hooks/useDeploymentStatus'
import TenantConfigForm from '../components/TenantConfigForm'
import LogTerminal from '../components/LogTerminal'

export default function DeployPage() {
  const navigate = useNavigate()
  const selectedIds = useDeploymentStore((s) => s.selectedScenarioIds)
  const tenantConfig = useDeploymentStore((s) => s.tenantConfig)
  const clearLogs = useDeploymentStore((s) => s.clearLogs)
  const deploymentState = useDeploymentStore((s) => s.deploymentState)

  const { data: scenarios } = useQuery({
    queryKey: ['scenarios'],
    queryFn: api.getScenarios,
  })

  // Keep status polling active
  useDeploymentStatus()

  const selectedScenarios = scenarios?.filter((s) => selectedIds.includes(s.id)) ?? []
  const isDeploying = deploymentState === 'deploying'
  const isDeployed = deploymentState === 'deployed'

  const handleDeploy = async () => {
    if (selectedIds.length === 0) return
    clearLogs()

    const hasConfig = tenantConfig.tenant_id && tenantConfig.domain && tenantConfig.subscription_id
    try {
      await api.deploy({
        scenario_ids: selectedIds,
        tenant_config: hasConfig ? tenantConfig : undefined,
      })
    } catch (err) {
      // Error will show in logs via websocket
      console.error('Deploy failed:', err)
    }
  }

  if (selectedIds.length === 0 && !isDeploying) {
    return (
      <div className="text-center py-12">
        <p className="text-slate-400">No scenarios selected.</p>
        <button
          onClick={() => navigate('/')}
          className="mt-4 px-4 py-2 text-sm bg-bz-accent text-white rounded hover:bg-blue-600"
        >
          Browse Scenarios
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">Deploy Attack Paths</h2>
        <p className="text-sm text-slate-400 mt-1">
          {selectedScenarios.length} scenario{selectedScenarios.length > 1 ? 's' : ''} selected
        </p>
      </div>

      {/* Selected scenario chips */}
      <div className="flex flex-wrap gap-2">
        {selectedScenarios.map((s) => (
          <span key={s.id} className="px-3 py-1 rounded-full bg-bz-accent/20 text-bz-accent text-xs font-medium">
            {s.name}
          </span>
        ))}
      </div>

      {/* Tenant config */}
      <TenantConfigForm />

      {/* Deploy button */}
      <div className="flex gap-3">
        <button
          onClick={handleDeploy}
          disabled={isDeploying || isDeployed}
          className={`px-6 py-2.5 rounded-lg font-medium text-sm transition-colors ${
            isDeploying || isDeployed
              ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
              : 'bg-bz-accent text-white hover:bg-blue-600'
          }`}
        >
          {isDeploying ? 'Deploying...' : isDeployed ? 'Deployed' : 'Start Deployment'}
        </button>
        {isDeployed && (
          <button
            onClick={() => navigate('/status')}
            className="px-6 py-2.5 rounded-lg font-medium text-sm bg-green-600 text-white hover:bg-green-500"
          >
            View Status
          </button>
        )}
      </div>

      {/* Log terminal */}
      <LogTerminal />
    </div>
  )
}
