import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ApiError } from '../api/client'
import { getScan } from '../api/scans'
import type { Finding, ScanResult } from '../api/types'
import { EmptyState } from '../components/EmptyState'
import { ErrorAlert } from '../components/ErrorAlert'
import { FindingCard } from '../components/FindingCard'
import { PageSkeleton } from '../components/LoadingSpinner'
import { SeverityBadge } from '../components/SeverityBadge'
import { SeverityBreakdown } from '../components/SeverityBreakdown'
import { StatCard } from '../components/StatCard'
import { formatDateTime, formatDuration } from '../utils/format'
import { SEVERITY_ORDER, normalizeSeverity } from '../utils/severity'

function groupFindings(findings: Finding[]): Record<string, Finding[]> {
  const groups: Record<string, Finding[]> = {
    CRITICAL: [],
    HIGH: [],
    MEDIUM: [],
    LOW: [],
    INFO: [],
  }
  for (const finding of findings) {
    groups[normalizeSeverity(finding.severity)].push(finding)
  }
  return groups
}

export function ScanDetailPage() {
  const { scanId = '' } = useParams()
  const [scan, setScan] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    setLoading(true)
    getScan(scanId)
      .then((data) => {
        if (active) {
          setScan(data)
          setError(null)
        }
      })
      .catch((err: unknown) => {
        if (active) {
          setScan(null)
          setError(err instanceof ApiError ? err.message : 'Failed to load scan details.')
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
  }, [scanId])

  const grouped = useMemo(() => groupFindings(scan?.findings ?? []), [scan])

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="font-display text-3xl tracking-tight text-slate-50">Scan details</h2>
          <p className="mt-2 font-mono text-xs text-slate-500">{scanId}</p>
        </div>
        {scan ? (
          <Link
            to={`/scans/${scan.scan_id}/report`}
            className="bg-accent-500 px-4 py-2 text-sm font-semibold text-surface-950 hover:bg-accent-400"
          >
            Open report
          </Link>
        ) : null}
      </header>

      {loading ? <PageSkeleton rows={5} /> : null}
      {error ? <ErrorAlert message={error} /> : null}

      {!loading && !error && scan ? (
        <>
          <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Target" value={scan.target} />
            <StatCard label="Profile" value={scan.profile} />
            <StatCard label="Status" value={scan.status} />
            <StatCard label="Duration" value={formatDuration(scan.duration_seconds)} />
          </section>

          <section className="grid gap-8 lg:grid-cols-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Timeline</h3>
              <dl className="mt-3 space-y-2 text-sm text-slate-300">
                <div className="flex justify-between gap-4">
                  <dt className="text-slate-500">Started</dt>
                  <dd>{formatDateTime(scan.started_at)}</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt className="text-slate-500">Completed</dt>
                  <dd>{formatDateTime(scan.completed_at)}</dd>
                </div>
                {scan.requests_per_second != null ? (
                  <div className="flex justify-between gap-4">
                    <dt className="text-slate-500">Rate limit</dt>
                    <dd>{scan.requests_per_second} req/s</dd>
                  </div>
                ) : null}
              </dl>
            </div>
            <div>
              <div className="flex items-center justify-between gap-3">
                <h3 className="text-sm font-semibold text-slate-200">Risk summary</h3>
                <SeverityBadge severity={scan.risk.severity} />
              </div>
              <SeverityBreakdown counts={scan.risk.counts} title="Finding counts" />
            </div>
          </section>

          <section className="grid gap-8 lg:grid-cols-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Open ports</h3>
              {scan.open_ports.length === 0 ? (
                <p className="mt-3 text-sm text-slate-500">No open ports reported.</p>
              ) : (
                <div className="mt-3 flex flex-wrap gap-2">
                  {scan.open_ports.map((port) => (
                    <span
                      key={port}
                      className="border border-surface-700 bg-surface-900 px-2 py-1 font-mono text-xs text-slate-300"
                    >
                      {port}
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Detected services</h3>
              {scan.services.length === 0 ? (
                <p className="mt-3 text-sm text-slate-500">No services detected.</p>
              ) : (
                <ul className="mt-3 space-y-2 text-sm">
                  {scan.services.map((service) => (
                    <li
                      key={`${service.port}-${service.name}`}
                      className="flex items-center justify-between gap-3 border-t border-surface-700/60 py-2"
                    >
                      <span className="text-slate-200">
                        {service.name}
                        {service.version ? (
                          <span className="text-slate-500"> {service.version}</span>
                        ) : null}
                      </span>
                      <span className="font-mono text-xs text-slate-500">:{service.port}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>

          <section className="space-y-4">
            <h3 className="text-sm font-semibold text-slate-200">
              Findings ({scan.findings.length})
            </h3>
            {scan.findings.length === 0 ? (
              <EmptyState
                title="No findings identified"
                description="This scan completed without reporting security findings."
              />
            ) : (
              SEVERITY_ORDER.map((severity) => {
                const findings = grouped[severity]
                if (findings.length === 0) {
                  return null
                }
                return (
                  <div key={severity} className="space-y-1">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={severity} />
                      <span className="text-xs text-slate-500">{findings.length} finding(s)</span>
                    </div>
                    {findings.map((finding) => (
                      <FindingCard key={`${finding.id}-${finding.port ?? 'na'}`} finding={finding} />
                    ))}
                  </div>
                )
              })
            )}
          </section>
        </>
      ) : null}
    </div>
  )
}
