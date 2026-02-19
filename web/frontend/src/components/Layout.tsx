import { NavLink } from 'react-router-dom'
import { useDeploymentStatus } from '../hooks/useDeploymentStatus'
import { useWebSocket } from '../hooks/useWebSocket'
import DeploymentStatusBadge from './DeploymentStatusBadge'

const navItems = [
  { to: '/', label: 'Scenarios' },
  { to: '/deploy', label: 'Deploy' },
  { to: '/status', label: 'Status' },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  useWebSocket()
  const { data: status } = useDeploymentStatus()

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className="w-56 bg-bz-dark border-r border-slate-700 flex flex-col">
        <div className="p-4 border-b border-slate-700">
          <h1 className="text-xl font-bold tracking-wide">
            <span className="text-bz-accent">Bad</span>Zure
          </h1>
          <p className="text-xs text-slate-400 mt-1">Attack Path Simulator</p>
        </div>

        <nav className="flex-1 p-3 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `block px-3 py-2 rounded text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-bz-accent/20 text-bz-accent'
                    : 'text-slate-300 hover:bg-slate-700/50 hover:text-white'
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="p-3 border-t border-slate-700">
          <DeploymentStatusBadge state={status?.state ?? 'idle'} />
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <div className="max-w-7xl mx-auto p-6">
          {children}
        </div>
      </main>
    </div>
  )
}
