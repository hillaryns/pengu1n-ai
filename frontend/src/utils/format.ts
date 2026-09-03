export function formatDateTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) {
    return '—'
  }
  if (seconds < 1) {
    return `${Math.round(seconds * 1000)} ms`
  }
  if (seconds < 60) {
    return `${seconds.toFixed(1)} s`
  }
  const minutes = Math.floor(seconds / 60)
  const remaining = Math.round(seconds % 60)
  return `${minutes}m ${remaining}s`
}

export function shortId(value: string, size = 8): string {
  if (value.length <= size) {
    return value
  }
  return `${value.slice(0, size)}…`
}
