import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ApiError } from '../api/client'
import { getScanReport } from '../api/scans'
import type { SecurityReport } from '../api/types'
import { EmptyState } from '../components/EmptyState'
import { ErrorAlert } from '../components/ErrorAlert'
import { FindingCard } from '../components/FindingCard'
import { PageSkeleton } from '../components/LoadingSpinner'
import { SeverityBadge } from '../components/SeverityBadge'
import { SeverityBreakdown } from '../components/SeverityBreakdown'
import { StatCard } from '../components/StatCard'
import { formatDateTime, formatDuration } from '../utils/format'

export function ReportPage() {
  const { scanId = '' } = useParams()
  const [report, setReport] = useState<SecurityReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    setLoading(true)
    getScanReport(scanId)
      .then((data) => {
        if (active) {
          setReport(data)
          setError(null)
        }
      })
      .catch((err: unknown) => {
        if (active) {
          setReport(null)
          setError(err instanceof ApiError ? err.message : 'Failed to load security report.')
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

  return (
    <div className="mx-auto max-w-4xl space-y-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="font-display text-3xl tracking-tight text-slate-50">Security report</h2>
          <p className="mt-2 text-sm text-slate-400">
            Assessment view of the stored report. Findings are not invented by the UI.
          </p>
        </div>
        <Link
          to={`/scans/${scanId}`}
          className="border border-surface-700 px-4 py-2 text-sm text-slate-200 hover:bg-surface-800"
        >
          Back to scan
        </Link>
      </header>

      {loading ? <PageSkeleton rows={6} /> : null}
      {error ? <ErrorAlert message={error} /> : null}

      {!loading && !error && report ? (
        <>
          <section className="border-y border-surface-700/70 py-6">
            <p className="font-mono text-[11px] uppercase tracking-[0.22em] text-accent-400">
              Pengu1n AI assessment
            </p>
            <div className="mt-3 flex flex-wrap items-start justify-between gap-4">
              <div>
                <h3 className="font-display text-2xl text-slate-50">{report.target}</h3>
                <p className="mt-1 text-sm text-slate-400">
                  Profile {report.profile} · Generated {formatDateTime(report.generated_at)} ·{' '}
                  {formatDuration(report.duration_seconds)}
                </p>
              </div>
              <div className="text-right">
                <SeverityBadge severity={report.risk.severity} />
                <p className="mt-2 text-xs text-slate-500">
                  {report.ai_enhanced ? 'AI-enhanced prose enabled' : 'Deterministic report'}
                </p>
              </div>
            </div>
            <h4 className="mt-6 text-sm font-semibold text-slate-200">Executive summary</h4>
            <p className="mt-2 text-sm leading-7 text-slate-300">{report.executive_summary}</p>
          </section>

          <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Overall risk" value={report.risk.severity} />
            <StatCard label="Findings" value={report.findings.length} />
            <StatCard label="CVE entries" value={report.cve_summary.length} />
            <StatCard label="Services" value={report.services.length} />
          </section>

          <SeverityBreakdown counts={report.risk.counts} title="Severity counts" />

          <section className="grid gap-8 lg:grid-cols-2">
            <div>
              <h4 className="text-sm font-semibold text-slate-200">Affected services</h4>
              {report.services.length === 0 ? (
                <p className="mt-3 text-sm text-slate-500">No services were recorded.</p>
              ) : (
                <ul className="mt-3 space-y-2 text-sm text-slate-300">
                  {report.services.map((service) => (
                    <li
                      key={`${service.port}-${service.name}`}
                      className="border-t border-surface-700/60 py-2"
                    >
                      {service.name}
                      {service.version ? ` ${service.version}` : ''} on port {service.port}
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div>
              <h4 className="text-sm font-semibold text-slate-200">Recommendations</h4>
              {report.recommendations.length === 0 ? (
                <p className="mt-3 text-sm text-slate-500">
                  No remediation recommendations were generated.
                </p>
              ) : (
                <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm leading-6 text-slate-300">
                  {report.recommendations.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ol>
              )}
            </div>
          </section>

          <section>
            <h4 className="text-sm font-semibold text-slate-200">CVE summary</h4>
            {report.cve_summary.length === 0 ? (
              <p className="mt-3 text-sm text-slate-500">
                No CVE-linked vulnerabilities were identified in this report.
              </p>
            ) : (
              <div className="mt-3 space-y-4">
                {report.cve_summary.map((item) => (
                  <article
                    key={`${item.cve_id}-${item.finding_id}`}
                    className="border-t border-surface-700/70 py-3"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={item.severity} />
                      <span className="font-mono text-sm text-accent-400">{item.cve_id}</span>
                      {item.confidence ? (
                        <span className="text-xs text-slate-500">Confidence {item.confidence}</span>
                      ) : null}
                    </div>
                    <p className="mt-2 text-sm text-slate-200">{item.title}</p>
                    <p className="mt-1 text-xs text-slate-500">
                      {[
                        item.service_name,
                        item.service_version,
                        item.port != null ? `port ${item.port}` : null,
                      ]
                        .filter(Boolean)
                        .join(' · ')}
                    </p>
                    {item.references.length > 0 ? (
                      <ul className="mt-2 space-y-1">
                        {item.references.map((reference) => (
                          <li key={reference}>
                            <a
                              href={reference}
                              target="_blank"
                              rel="noreferrer"
                              className="break-all text-xs text-accent-400 hover:text-accent-500"
                            >
                              {reference}
                            </a>
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </article>
                ))}
              </div>
            )}
          </section>

          <section className="space-y-3">
            <div>
              <h4 className="text-sm font-semibold text-slate-200">Prioritized findings</h4>
              <p className="mt-1 text-xs text-slate-500">
                Observations are hygiene findings. Confirmed vulnerabilities include CVE identifiers
                from vulnerability intelligence.
              </p>
            </div>
            {report.prioritized_findings.length === 0 ? (
              <EmptyState
                title="No findings identified"
                description="The stored report contains a clean assessment with no findings."
              />
            ) : (
              report.prioritized_findings.map((finding) => (
                <FindingCard key={`${finding.id}-${finding.port ?? 'na'}`} finding={finding} />
              ))
            )}
          </section>
        </>
      ) : null}
    </div>
  )
}
