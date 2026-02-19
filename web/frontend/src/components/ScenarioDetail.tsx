import type { ScenarioDetail as ScenarioDetailType } from '../types'

interface Props {
  scenario: ScenarioDetailType
  onClose: () => void
}

export default function ScenarioDetail({ scenario, onClose }: Props) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="bg-slate-800 rounded-lg border border-slate-600 max-w-2xl w-full mx-4 max-h-[80vh] overflow-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-6">
          <div className="flex justify-between items-start">
            <h2 className="text-lg font-bold text-white">{scenario.name}</h2>
            <button onClick={onClose} className="text-slate-400 hover:text-white text-xl leading-none">&times;</button>
          </div>

          <div className="flex flex-wrap gap-2 mt-3">
            {scenario.tags.map((tag) => (
              <span key={tag} className="text-xs px-2 py-0.5 rounded-full bg-slate-700 text-slate-300">
                {tag}
              </span>
            ))}
          </div>

          <p className="text-sm text-slate-300 mt-4 leading-relaxed">{scenario.long_description}</p>

          <div className="mt-4">
            <h3 className="text-sm font-semibold text-slate-400 mb-2">YAML Configuration</h3>
            <pre className="bg-slate-900 rounded p-3 text-xs text-green-400 overflow-x-auto font-mono">
              {scenario.yaml_content}
            </pre>
          </div>

          <div className="grid grid-cols-2 gap-4 mt-4 text-sm">
            <div>
              <span className="text-slate-500">Technique:</span>{' '}
              <span className="text-slate-300">{scenario.technique}</span>
            </div>
            <div>
              <span className="text-slate-500">Method:</span>{' '}
              <span className="text-slate-300">{scenario.method}</span>
            </div>
            <div>
              <span className="text-slate-500">Identity:</span>{' '}
              <span className="text-slate-300">{scenario.identity_type}</span>
            </div>
            <div>
              <span className="text-slate-500">Difficulty:</span>{' '}
              <span className="text-slate-300">{scenario.difficulty}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
