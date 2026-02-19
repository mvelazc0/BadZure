import type { ScenarioCatalogEntry } from '../types'

interface Props {
  scenario: ScenarioCatalogEntry
  selected: boolean
  onToggle: () => void
  onViewDetail: () => void
}

const difficultyColors: Record<string, string> = {
  beginner: 'text-green-400 bg-green-400/10',
  intermediate: 'text-yellow-400 bg-yellow-400/10',
  advanced: 'text-red-400 bg-red-400/10',
}

const techniqueColors: Record<string, string> = {
  ApplicationOwnershipAbuse: 'border-purple-500/40',
  ApplicationAdministratorAbuse: 'border-orange-500/40',
  CloudAppAdministratorAbuse: 'border-cyan-500/40',
  KeyVaultSecretTheft: 'border-yellow-500/40',
  StorageCertificateTheft: 'border-pink-500/40',
  ManagedIdentityTheft: 'border-emerald-500/40',
}

export default function ScenarioCard({ scenario, selected, onToggle, onViewDetail }: Props) {
  const borderColor = techniqueColors[scenario.technique] ?? 'border-slate-600'

  return (
    <div
      className={`relative rounded-lg border-2 p-4 transition-all cursor-pointer ${
        selected
          ? 'border-bz-accent bg-bz-accent/5 ring-1 ring-bz-accent/30'
          : `${borderColor} bg-slate-800/50 hover:bg-slate-800`
      }`}
      onClick={onToggle}
    >
      {/* Checkbox */}
      <div className="absolute top-3 right-3">
        <div
          className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-colors ${
            selected ? 'bg-bz-accent border-bz-accent' : 'border-slate-500'
          }`}
        >
          {selected && (
            <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          )}
        </div>
      </div>

      {/* Content */}
      <div className="pr-8">
        <h3 className="text-sm font-semibold text-white leading-tight">{scenario.name}</h3>

        <div className="flex flex-wrap gap-1.5 mt-2">
          <span className="text-xs px-2 py-0.5 rounded-full bg-slate-700 text-slate-300">
            {scenario.technique.replace(/([A-Z])/g, ' $1').trim()}
          </span>
          <span className={`text-xs px-2 py-0.5 rounded-full ${difficultyColors[scenario.difficulty] ?? 'text-slate-400 bg-slate-700'}`}>
            {scenario.difficulty}
          </span>
          <span className="text-xs px-2 py-0.5 rounded-full bg-slate-700 text-slate-300">
            {scenario.identity_type === 'service_principal' ? 'SP' : 'User'}
          </span>
        </div>

        <p className="text-xs text-slate-400 mt-2 line-clamp-2">{scenario.description}</p>

        {scenario.requires_azure_resources.length > 0 && (
          <div className="flex gap-1 mt-2">
            {scenario.requires_azure_resources.map((r) => (
              <span key={r} className="text-xs px-1.5 py-0.5 rounded bg-amber-900/30 text-amber-400">
                {r.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* View Detail link */}
      <button
        onClick={(e) => {
          e.stopPropagation()
          onViewDetail()
        }}
        className="text-xs text-bz-accent hover:text-blue-300 mt-2 inline-block"
      >
        View details
      </button>
    </div>
  )
}
