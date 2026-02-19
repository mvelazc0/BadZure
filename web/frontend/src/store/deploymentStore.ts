import { create } from 'zustand'
import type { DeploymentState, LogMessage, TenantConfig } from '../types'

interface DeploymentStore {
  // Selections
  selectedScenarioIds: string[]
  toggleScenario: (id: string) => void
  clearSelections: () => void

  // Tenant config
  tenantConfig: TenantConfig
  setTenantConfig: (config: Partial<TenantConfig>) => void

  // Logs
  logs: LogMessage[]
  addLog: (log: LogMessage) => void
  clearLogs: () => void

  // Status
  deploymentState: DeploymentState
  setDeploymentState: (state: DeploymentState) => void
}

export const useDeploymentStore = create<DeploymentStore>((set) => ({
  selectedScenarioIds: [],
  toggleScenario: (id) =>
    set((s) => ({
      selectedScenarioIds: s.selectedScenarioIds.includes(id)
        ? s.selectedScenarioIds.filter((sid) => sid !== id)
        : [...s.selectedScenarioIds, id],
    })),
  clearSelections: () => set({ selectedScenarioIds: [] }),

  tenantConfig: { tenant_id: '', domain: '', subscription_id: '' },
  setTenantConfig: (config) =>
    set((s) => ({ tenantConfig: { ...s.tenantConfig, ...config } })),

  logs: [],
  addLog: (log) => set((s) => ({ logs: [...s.logs, log].slice(-1000) })),
  clearLogs: () => set({ logs: [] }),

  deploymentState: 'idle',
  setDeploymentState: (state) => set({ deploymentState: state }),
}))
