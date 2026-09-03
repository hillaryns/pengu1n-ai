import type { Severity } from '../api/types'
import { SEVERITY_ORDER } from '../utils/severity'
import { SeverityBadge } from './SeverityBadge'

interface SeverityBreakdownProps {
  counts: Record<string, number>
  title?: string
}

const BAR_CLASS: Record<Severity, string> = {
  CRITICAL: 'bg-critical',
  HIGH: 'bg-high',
  MEDIUM: 'bg-medium',
  LOW: 'bg-low',
  INFO: 'bg-info',
}

export function SeverityBreakdown({
  counts,
  title = 'Finding counts by severity',
}: SeverityBreakdownProps) {
  const maxCount = Math.max(1, ...SEVERITY_ORDER.map((severity) => counts[severity] ?? 0))

  return (
    <section className="border-y border-surface-700/70 py-5">
      <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
      <div className="mt-4 space-y-3">
        {SEVERITY_ORDER.map((severity: Severity) => {
          const count = counts[severity] ?? 0
          const width = `${Math.max(count > 0 ? 8 : 0, (count / maxCount) * 100)}%`
          return (
            <div key={severity} className="grid grid-cols-[7.5rem_1fr_2rem] items-center gap-3">
              <SeverityBadge severity={severity} />
              <div className="h-1.5 overflow-hidden bg-surface-800">
                <div className={`h-full ${BAR_CLASS[severity]}`} style={{ width }} />
              </div>
              <span className="text-right font-mono text-sm text-slate-200">{count}</span>
            </div>
          )
        })}
      </div>
    </section>
  )
}
