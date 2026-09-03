import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiError } from '../api/client'
import { listScans } from '../api/scans'
import type { ScanSummary } from '../api/types'
import { EmptyState } from '../components/EmptyState'
import { ErrorAlert } from '../components/ErrorAlert'
import { PageSkeleton } from '../components/LoadingSpinner'
import { SeverityBadge } from '../components/SeverityBadge'
import { formatDateTime, formatDuration, shortId } from '../utils/format'

export function ScanHistoryPage() {
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
          setError(err instanceof ApiError ? err.message : 'Failed to load scan history.')
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

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="font-display text-3xl tracking-tight text-slate-50">Scan history</h2>
          <p className="mt-2 text-sm text-slate-400">Live data from GET /scans.</p>
        </div>
        <Link
          to="/scans/new"
          className="bg-accent-500 px-4 py-2 text-sm font-semibold text-surface-950 hover:bg-accent-400"
        >
          New scan
        </Link>
      </header>

      {loading ? <PageSkeleton rows={6} /> : null}
      {error ? <ErrorAlert message={error} /> : null}

      {!loading && !error && scans.length === 0 ? (
        <EmptyState
          title="No scan history"
          description="Completed scans will appear here with target, profile, risk, and finding counts."
          action={
            <Link
              to="/scans/new"
              className="bg-accent-500 px-4 py-2 text-sm font-semibold text-surface-950 hover:bg-accent-400"
            >
              Run first scan
            </Link>
          }
        />
      ) : null}

      {!loading && !error && scans.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="py-3 pr-4 font-medium">Scan</th>
                <th className="py-3 pr-4 font-medium">Target</th>
                <th className="py-3 pr-4 font-medium">Profile</th>
                <th className="py-3 pr-4 font-medium">Status</th>
                <th className="py-3 pr-4 font-medium">Risk</th>
                <th className="py-3 pr-4 font-medium">Findings</th>
                <th className="py-3 pr-4 font-medium">Started</th>
                <th className="py-3 pr-4 font-medium">Duration</th>
                <th className="py-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.scan_id} className="border-t border-surface-700/60">
                  <td className="py-3 pr-4 font-mono text-xs text-slate-400">
                    {shortId(scan.scan_id, 10)}
                  </td>
                  <td className="py-3 pr-4 font-mono text-slate-200">{scan.target}</td>
                  <td className="py-3 pr-4 text-slate-300">{scan.profile}</td>
                  <td className="py-3 pr-4 text-slate-300">{scan.status}</td>
                  <td className="py-3 pr-4">
                    <SeverityBadge severity={scan.risk_severity} />
                  </td>
                  <td className="py-3 pr-4 text-slate-300">{scan.finding_count}</td>
                  <td className="py-3 pr-4 text-slate-400">{formatDateTime(scan.started_at)}</td>
                  <td className="py-3 pr-4 text-slate-400">
                    {formatDuration(scan.duration_seconds)}
                  </td>
                  <td className="py-3">
                    <div className="flex flex-wrap gap-3">
                      <Link
                        to={`/scans/${scan.scan_id}`}
                        className="text-accent-400 hover:text-accent-500"
                      >
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
      ) : null}
    </div>
  )
}
