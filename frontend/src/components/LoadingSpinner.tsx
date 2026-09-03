export function LoadingSpinner({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 text-slate-300" role="status">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-accent-500 border-t-transparent" />
      <span className="text-sm">{label}</span>
    </div>
  )
}

export function PageSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, index) => (
        <div
          key={index}
          className="h-14 animate-pulse border border-surface-700/50 bg-surface-850/50"
        />
      ))}
    </div>
  )
}
