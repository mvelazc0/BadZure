import type { DeploymentResource } from '../types'

interface Props {
  resources: DeploymentResource[]
}

export default function ResourceList({ resources }: Props) {
  if (resources.length === 0) {
    return <p className="text-sm text-slate-500">No resources found in terraform state.</p>
  }

  // Group by type
  const grouped = resources.reduce<Record<string, DeploymentResource[]>>((acc, r) => {
    ;(acc[r.type] ??= []).push(r)
    return acc
  }, {})

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold text-slate-400">
        Deployed Resources ({resources.length})
      </h3>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700">
              <th className="text-left py-2 px-3 text-slate-400 font-medium">Type</th>
              <th className="text-left py-2 px-3 text-slate-400 font-medium">Name</th>
              <th className="text-right py-2 px-3 text-slate-400 font-medium">Count</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(grouped).map(([type, items]) => (
              items.map((item, idx) => (
                <tr key={`${type}-${idx}`} className="border-b border-slate-800 hover:bg-slate-800/50">
                  {idx === 0 && (
                    <td rowSpan={items.length} className="py-2 px-3 text-slate-300 align-top font-mono text-xs">
                      {type}
                      <span className="ml-2 text-slate-500">({items.length})</span>
                    </td>
                  )}
                  <td className="py-2 px-3 text-white">{item.name}</td>
                  {idx === 0 && (
                    <td rowSpan={items.length} className="py-2 px-3 text-right text-slate-400">
                      {items.length}
                    </td>
                  )}
                </tr>
              ))
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
