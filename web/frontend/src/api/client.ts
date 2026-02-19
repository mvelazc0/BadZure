import type { ScenarioCatalogEntry, ScenarioDetail, DeployRequest, DeploymentStatus } from '../types'

const BASE = '/api'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  getScenarios: () => request<ScenarioCatalogEntry[]>('/scenarios'),

  getScenario: (id: string) => request<ScenarioDetail>(`/scenarios/${id}`),

  deploy: (data: DeployRequest) =>
    request<{ message: string }>('/deploy', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getStatus: () => request<DeploymentStatus>('/status'),

  destroy: () =>
    request<{ message: string }>('/destroy', { method: 'POST' }),
}
