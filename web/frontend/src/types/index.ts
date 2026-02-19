export interface ScenarioCatalogEntry {
  id: string
  name: string
  technique: string
  description: string
  tags: string[]
  mode: string
  difficulty: string
  identity_type: string
  method: string
  requires_azure_resources: string[]
}

export interface ScenarioDetail extends ScenarioCatalogEntry {
  long_description: string
  attack_path_key: string
  yaml_content: string
}

export interface TenantConfig {
  tenant_id: string
  domain: string
  subscription_id: string
}

export interface DeployRequest {
  scenario_ids: string[]
  tenant_config?: TenantConfig
}

export type DeploymentState = 'idle' | 'deploying' | 'deployed' | 'destroying' | 'error'

export interface DeploymentResource {
  type: string
  name: string
  provider: string
}

export interface DeploymentStatus {
  state: DeploymentState
  scenario_ids: string[]
  resources: DeploymentResource[]
  started_at: string | null
  completed_at: string | null
  error_message: string | null
}

export interface LogMessage {
  timestamp: string
  level: string
  message: string
  source: string | null
}
