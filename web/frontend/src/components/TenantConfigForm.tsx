import { useDeploymentStore } from '../store/deploymentStore'

export default function TenantConfigForm() {
  const tenantConfig = useDeploymentStore((s) => s.tenantConfig)
  const setTenantConfig = useDeploymentStore((s) => s.setTenantConfig)

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-slate-400">Tenant Configuration</h3>
      <p className="text-xs text-slate-500">
        Leave blank to use environment variables (BADZURE_TENANT_ID, BADZURE_DOMAIN, BADZURE_SUBSCRIPTION_ID)
      </p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div>
          <label className="block text-xs text-slate-400 mb-1">Tenant ID</label>
          <input
            type="text"
            value={tenantConfig.tenant_id}
            onChange={(e) => setTenantConfig({ tenant_id: e.target.value })}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            className="w-full bg-slate-800 border border-slate-600 rounded px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-bz-accent"
          />
        </div>
        <div>
          <label className="block text-xs text-slate-400 mb-1">Domain</label>
          <input
            type="text"
            value={tenantConfig.domain}
            onChange={(e) => setTenantConfig({ domain: e.target.value })}
            placeholder="yourdomain.onmicrosoft.com"
            className="w-full bg-slate-800 border border-slate-600 rounded px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-bz-accent"
          />
        </div>
        <div>
          <label className="block text-xs text-slate-400 mb-1">Subscription ID</label>
          <input
            type="text"
            value={tenantConfig.subscription_id}
            onChange={(e) => setTenantConfig({ subscription_id: e.target.value })}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            className="w-full bg-slate-800 border border-slate-600 rounded px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-bz-accent"
          />
        </div>
      </div>
    </div>
  )
}
