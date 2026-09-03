import { NavLink, Outlet } from 'react-router-dom'
import { getApiBaseUrl } from '../api/client'
import { useApiConfig } from '../context/ApiConfigContext'

const navItems = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/scans/new', label: 'New Scan' },
  { to: '/scans', label: 'Scan History' },
  { to: '/settings', label: 'Settings' },
]

export function AppLayout() {
  const { apiKeyConfigured } = useApiConfig()

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[15.5rem_minmax(0,1fr)]">
      <aside className="border-b border-surface-700/70 bg-surface-900/95 lg:sticky lg:top-0 lg:h-screen lg:border-b-0 lg:border-r">
        <div className="px-5 py-7">
          <p className="font-mono text-[11px] uppercase tracking-[0.28em] text-accent-400">
            Authorized scanner
          </p>
          <h1 className="mt-3 font-display text-3xl leading-none tracking-tight text-slate-50">
            Pengu1n AI
          </h1>
          <p className="mt-3 max-w-[12rem] text-sm leading-5 text-slate-400">
            Security console for scoped, evidence-backed assessments.
          </p>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-3 pb-4 lg:flex-col lg:overflow-visible">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                [
                  'px-3 py-2 text-sm whitespace-nowrap transition-colors',
                  isActive
                    ? 'bg-accent-500/12 text-accent-400'
                    : 'text-slate-400 hover:bg-surface-800 hover:text-slate-100',
                ].join(' ')
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="hidden border-t border-surface-700/70 px-5 py-4 font-mono text-[11px] text-slate-500 lg:block">
          <p className="truncate">{getApiBaseUrl()}</p>
          <p className="mt-1">{apiKeyConfigured ? 'API key configured' : 'API key missing'}</p>
        </div>
      </aside>

      <main className="px-4 py-6 sm:px-8 lg:px-10">
        <Outlet />
      </main>
    </div>
  )
}
