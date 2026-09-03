import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiError } from '../api/client'
import { listScans } from '../api/scans'
import type { ScanSummary } from '../api/types'
import { EmptyState } from '../components/EmptyState'
import { ErrorAlert } from '../components/ErrorAlert'
import { PageSkeleton } from '../components/LoadingSpinner'
import { SeverityBadge } from '../components/SeverityBadge'
import { SeverityBreakdown } from '../components/SeverityBreakdown'
import { StatCard } from '../components/StatCard'
import { formatDateTime, formatDuration } from '../utils/format'
import { SEVERITY_ORDER, emptySeverityCounts, normalizeSeverity } from '../utils/severity'

export function DashboardPage() {
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    setLoading(true)
    listScans()
      .then((data) => {
        if (active) {
          setScans(data)
          setError(null)
        }
      })
      .catch((err: unknown) => {
        if (active) {
          setError(err instanceof ApiError ? err.message : 'Failed to load scans.')
        }
      })
      .finally(() => {
        if (active) {
          setLoading(false)
        }
      })
    return () => {
      active = false
    }
  }, [])

  const highestRisk = useMemo(() => {
    let highest = normalizeSeverity('INFO')
    for (const scan of scans) {
      const candidate = normalizeSeverity(scan.risk_severity)
      if (SEVERITY_ORDER.indexOf(candidate) > SEVERITY_ORDER.indexOf(highest)) {
        highest = candidate
      }
    }
    return highest
  }, [scans])

  const findingCounts = useMemo(() => {
    const totals = emptySeverityCounts()
    for (const scan of scans) {
      const counts = scan.risk_counts ?? {}
      for (const severity of SEVERITY_ORDER) {
        totals[severity] += counts[severity] ?? 0
      }
    }
    return totals
  }, [scans])

  const recentScans = scans.slice(0, 5)
  const totalFindings = scans.reduce((sum, scan) => sum + scan.finding_count, 0)

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="font-display text-3xl tracking-tight text-slate-50">Dashboard</h2>
          <p className="mt-2 max-w-xl text-sm leading-6 text-slate-400">
            Live scan posture from the FastAPI backend. No simulated results.
          </p>
        </div>
        <Link
          to="/scans/new"
          className="bg-accent-500 px-4 py-2 text-sm font-semibold text-surface-950 hover:bg-accent-400"
        >
          Start scan
        </Link>
      </header>

      {loading ? <PageSkeleton /> : null}
      {error ? <ErrorAlert message={error} /> : null}

      {!loading && !error && scans.length === 0 ? (
        <EmptyState
          title="No scans yet"
          description="Run an authorized assessment to populate this console with real history, findings, and reports."
          action={
            <Link
              to="/scans/new"
              className="bg-accent-500 px-4 py-2 text-sm font-semibold text-surface-950 hover:bg-accent-400"
            >
              Create a scan
            </Link>
          }
        />
      ) : null}

      {!loading && !error && scans.length > 0 ? (
        <>
          <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Total scans" value={scans.length} />
            <StatCard label="Total findings" value={totalFindings} />
            <StatCard label="Highest risk" value={highestRisk} hint="Highest stored scan severity" />
            <StatCard
              label="Latest report"
              value={recentScans[0]?.target ?? '—'}
              hint={recentScans[0] ? formatDateTime(recentScans[0].started_at) : undefined}
            />
          </section>

          <SeverityBreakdown counts={findingCounts} />

          <section>
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-sm font-semibold text-slate-200">Recent scans</h3>
              <Link to="/scans" className="text-sm text-accent-400 hover:text-accent-500">
                View all
              </Link>
            </div>
            <div className="mt-3 overflow-x-auto">
              <table className="min-w-full text-left text-sm">
                <thead className="text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="py-2 pr-4 font-medium">Target</th>
                    <th className="py-2 pr-4 font-medium">Profile</th>
                    <th className="py-2 pr-4 font-medium">Risk</th>
                    <th className="py-2 pr-4 font-medium">Findings</th>
                    <th className="py-2 pr-4 font-medium">When</th>
                    <th className="py-2 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {recentScans.map((scan) => (
                    <tr key={scan.scan_id} className="border-t border-surface-700/60">
                      <td className="py-3 pr-4 font-mono text-slate-200">{scan.target}</td>
                      <td className="py-3 pr-4 text-slate-300">{scan.profile}</td>
                      <td className="py-3 pr-4">
                        <SeverityBadge severity={scan.risk_severity} />
                      </td>
                      <td className="py-3 pr-4 text-slate-300">{scan.finding_count}</td>
                      <td className="py-3 pr-4 text-slate-400">
                        {formatDateTime(scan.started_at)}
                        <span className="block text-xs">{formatDuration(scan.duration_seconds)}</span>
                      </td>
                      <td className="py-3">
                        <div className="flex flex-wrap gap-3">
                          <Link to={`/scans/${scan.scan_id}`} className="text-accent-400 hover:text-accent-500">
                            Details
                          </Link>
                          <Link
                            to={`/scans/${scan.scan_id}/report`}
                            className="text-accent-400 hover:text-accent-500"
                          >
                            Report
                          </Link>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      ) : null}
    </div>
  )
}
