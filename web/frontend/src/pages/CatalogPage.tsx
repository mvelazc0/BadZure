import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { useDeploymentStore } from '../store/deploymentStore'
import ScenarioCard from '../components/ScenarioCard'
import ScenarioDetailModal from '../components/ScenarioDetail'
import type { ScenarioDetail } from '../types'

const TECHNIQUES = [
  'All',
  'ApplicationOwnershipAbuse',
  'ApplicationAdministratorAbuse',
  'CloudAppAdministratorAbuse',
  'KeyVaultSecretTheft',
  'StorageCertificateTheft',
  'ManagedIdentityTheft',
]

export default function CatalogPage() {
  const navigate = useNavigate()
  const [filter, setFilter] = useState('All')
  const [detailScenario, setDetailScenario] = useState<ScenarioDetail | null>(null)

  const { data: scenarios, isLoading } = useQuery({
    queryKey: ['scenarios'],
    queryFn: api.getScenarios,
  })

  const selectedIds = useDeploymentStore((s) => s.selectedScenarioIds)
  const toggleScenario = useDeploymentStore((s) => s.toggleScenario)

  const filtered = scenarios?.filter(
    (s) => filter === 'All' || s.technique === filter
  )

  const handleViewDetail = async (id: string) => {
    const detail = await api.getScenario(id)
    setDetailScenario(detail)
  }

  return (
    <div>
      <div className="flex justify-between items-start mb-6">
        <div>
          <h2 className="text-2xl font-bold text-white">Attack Path Scenarios</h2>
          <p className="text-sm text-slate-400 mt-1">
            Select scenarios to deploy. {selectedIds.length > 0 && (
              <span className="text-bz-accent">{selectedIds.length} selected</span>
            )}
          </p>
        </div>
        {selectedIds.length > 0 && (
          <button
            onClick={() => navigate('/deploy')}
            className="px-4 py-2 bg-bz-accent text-white rounded-lg font-medium text-sm hover:bg-blue-600 transition-colors"
          >
            Deploy {selectedIds.length} scenario{selectedIds.length > 1 ? 's' : ''}
          </button>
        )}
      </div>

      {/* Technique filter */}
      <div className="flex flex-wrap gap-2 mb-6">
        {TECHNIQUES.map((t) => (
          <button
            key={t}
            onClick={() => setFilter(t)}
            className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${
              filter === t
                ? 'bg-bz-accent text-white'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            {t === 'All' ? 'All' : t.replace(/([A-Z])/g, ' $1').trim()}
          </button>
        ))}
      </div>

      {/* Scenario grid */}
      {isLoading ? (
        <div className="text-slate-500 text-center py-12">Loading scenarios...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered?.map((scenario) => (
            <ScenarioCard
              key={scenario.id}
              scenario={scenario}
              selected={selectedIds.includes(scenario.id)}
              onToggle={() => toggleScenario(scenario.id)}
              onViewDetail={() => handleViewDetail(scenario.id)}
            />
          ))}
        </div>
      )}

      {/* Detail modal */}
      {detailScenario && (
        <ScenarioDetailModal
          scenario={detailScenario}
          onClose={() => setDetailScenario(null)}
        />
      )}
    </div>
  )
}
