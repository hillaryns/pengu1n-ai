import { normalizeSeverity, severityBadgeClass } from '../utils/severity'

interface SeverityBadgeProps {
  severity: string
  className?: string
}

export function SeverityBadge({ severity, className = '' }: SeverityBadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-semibold tracking-wide ${severityBadgeClass(severity)} ${className}`}
    >
      {normalizeSeverity(severity)}
    </span>
  )
}
