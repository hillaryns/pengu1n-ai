import type { Severity } from '../api/types'

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export function normalizeSeverity(value: string | null | undefined): Severity {
  const upper = (value ?? 'INFO').toUpperCase()
  if (SEVERITY_ORDER.includes(upper as Severity)) {
    return upper as Severity
  }
  return 'INFO'
}

export function severityBadgeClass(severity: string): string {
  switch (normalizeSeverity(severity)) {
    case 'CRITICAL':
      return 'bg-critical/15 text-critical border-critical/30'
    case 'HIGH':
      return 'bg-high/15 text-high border-high/30'
    case 'MEDIUM':
      return 'bg-medium/15 text-medium border-medium/30'
    case 'LOW':
      return 'bg-low/15 text-low border-low/30'
    default:
      return 'bg-info/15 text-info border-info/30'
  }
}

export function emptySeverityCounts(): Record<Severity, number> {
  return {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  }
}
