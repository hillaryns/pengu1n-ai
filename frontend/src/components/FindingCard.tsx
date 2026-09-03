import type { Finding } from '../api/types'
import { SeverityBadge } from './SeverityBadge'

interface FindingCardProps {
  finding: Finding
}

export function FindingCard({ finding }: FindingCardProps) {
  const isConfirmedVulnerability = Boolean(finding.cve_id)

  return (
    <article className="border-t border-surface-700/70 py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <span className="border border-surface-700 px-2 py-0.5 text-[11px] uppercase tracking-wide text-slate-400">
              {isConfirmedVulnerability ? 'Confirmed vulnerability' : 'Observation'}
            </span>
            <span className="font-mono text-xs text-slate-500">{finding.id}</span>
          </div>
          <h3 className="mt-2 text-base font-semibold text-slate-100">{finding.title}</h3>
          <p className="mt-1 text-sm leading-6 text-slate-400">{finding.description}</p>
        </div>
        <div className="text-right text-xs text-slate-500">
          <p>{finding.category}</p>
          {finding.port != null ? <p className="mt-1 font-mono">Port {finding.port}</p> : null}
        </div>
      </div>

      <dl className="mt-4 grid gap-3 text-sm md:grid-cols-2">
        {finding.evidence ? (
          <div>
            <dt className="text-xs uppercase tracking-wide text-slate-500">Evidence</dt>
            <dd className="mt-1 text-slate-300">{finding.evidence}</dd>
          </div>
        ) : null}
        <div>
          <dt className="text-xs uppercase tracking-wide text-slate-500">Recommendation</dt>
          <dd className="mt-1 text-slate-300">{finding.recommendation}</dd>
        </div>
        {finding.cve_id ? (
          <div>
            <dt className="text-xs uppercase tracking-wide text-slate-500">CVE</dt>
            <dd className="mt-1 font-mono text-accent-400">{finding.cve_id}</dd>
          </div>
        ) : null}
        {finding.confidence ? (
          <div>
            <dt className="text-xs uppercase tracking-wide text-slate-500">Confidence</dt>
            <dd className="mt-1 text-slate-300">{finding.confidence}</dd>
          </div>
        ) : null}
      </dl>

      {finding.references.length > 0 ? (
        <div className="mt-4">
          <p className="text-xs uppercase tracking-wide text-slate-500">References</p>
          <ul className="mt-1 space-y-1">
            {finding.references.map((reference) => (
              <li key={reference}>
                <a
                  href={reference}
                  target="_blank"
                  rel="noreferrer"
                  className="break-all text-sm text-accent-400 hover:text-accent-500"
                >
                  {reference}
                </a>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </article>
  )
}
