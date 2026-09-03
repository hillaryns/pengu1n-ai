import { useMemo, useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ApiError } from '../api/client'
import { createScan } from '../api/scans'
import type { ScanProfile } from '../api/types'
import { ErrorAlert } from '../components/ErrorAlert'
import { LoadingSpinner } from '../components/LoadingSpinner'

const PROFILES: ScanProfile[] = ['quick', 'standard', 'deep', 'bug_bounty']

function parseHostList(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function NewScanPage() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [profile, setProfile] = useState<ScanProfile>('standard')
  const [allowedHosts, setAllowedHosts] = useState('')
  const [excludedHosts, setExcludedHosts] = useState('')
  const [requestsPerSecond, setRequestsPerSecond] = useState('2')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [successId, setSuccessId] = useState<string | null>(null)

  const showScope = profile === 'bug_bounty'

  const clientValidationError = useMemo(() => {
    if (!target.trim()) {
      return 'Target is required.'
    }
    if (showScope && parseHostList(allowedHosts).length === 0) {
      return 'bug_bounty requires at least one allowed host.'
    }
    if (showScope && requestsPerSecond.trim()) {
      const rate = Number(requestsPerSecond)
      if (!Number.isFinite(rate) || rate <= 0) {
        return 'requests_per_second must be greater than zero.'
      }
    }
    return null
  }, [target, showScope, allowedHosts, requestsPerSecond])

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setSuccessId(null)

    if (clientValidationError) {
      setError(clientValidationError)
      return
    }

    setSubmitting(true)
    try {
      const payload = {
        target: target.trim(),
        profile,
        ...(showScope
          ? {
              scope: {
                allowed_hosts: parseHostList(allowedHosts),
                excluded_hosts: parseHostList(excludedHosts),
                requests_per_second: requestsPerSecond.trim()
                  ? Number(requestsPerSecond)
                  : null,
              },
            }
          : {}),
      }
      const result = await createScan(payload)
      setSuccessId(result.scan_id)
      navigate(`/scans/${result.scan_id}`)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Scan request failed.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-8">
      <header>
        <h2 className="font-display text-3xl tracking-tight text-slate-50">New scan</h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          Submit an authorized target to FastAPI. Hostname, IPv4, or localhost only — no URL
          schemes.
        </p>
      </header>

      <form onSubmit={handleSubmit} className="space-y-5">
        <label className="block space-y-2">
          <span className="text-sm font-medium text-slate-200">Target</span>
          <input
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="hostname, IPv4, or localhost"
            className="w-full border border-surface-700 bg-surface-900 px-3 py-2 font-mono text-sm text-slate-100 outline-none focus:border-accent-500"
          />
        </label>

        <label className="block space-y-2">
          <span className="text-sm font-medium text-slate-200">Profile</span>
          <select
            value={profile}
            onChange={(event) => setProfile(event.target.value as ScanProfile)}
            className="w-full border border-surface-700 bg-surface-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-accent-500"
          >
            {PROFILES.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>

        {showScope ? (
          <fieldset className="space-y-4 border-y border-surface-700/70 py-4">
            <legend className="text-sm font-semibold text-slate-200">Bug bounty scope</legend>
            <label className="block space-y-2">
              <span className="text-sm text-slate-300">Allowed hosts</span>
              <textarea
                value={allowedHosts}
                onChange={(event) => setAllowedHosts(event.target.value)}
                rows={3}
                placeholder="example.com, *.example.com"
                className="w-full border border-surface-700 bg-surface-950 px-3 py-2 font-mono text-sm text-slate-100 outline-none focus:border-accent-500"
              />
            </label>
            <label className="block space-y-2">
              <span className="text-sm text-slate-300">Excluded hosts</span>
              <textarea
                value={excludedHosts}
                onChange={(event) => setExcludedHosts(event.target.value)}
                rows={2}
                placeholder="optional exclusions"
                className="w-full border border-surface-700 bg-surface-950 px-3 py-2 font-mono text-sm text-slate-100 outline-none focus:border-accent-500"
              />
            </label>
            <label className="block space-y-2">
              <span className="text-sm text-slate-300">Requests per second</span>
              <input
                value={requestsPerSecond}
                onChange={(event) => setRequestsPerSecond(event.target.value)}
                type="number"
                min="0.1"
                step="0.1"
                className="w-full border border-surface-700 bg-surface-950 px-3 py-2 font-mono text-sm text-slate-100 outline-none focus:border-accent-500"
              />
            </label>
          </fieldset>
        ) : null}

        {error ? <ErrorAlert title="Unable to start scan" message={error} /> : null}
        {successId ? (
          <div className="border-l-2 border-accent-500 bg-accent-500/10 px-4 py-3 text-sm text-teal-100">
            Scan created successfully.{' '}
            <Link to={`/scans/${successId}`} className="underline">
              Open details
            </Link>
          </div>
        ) : null}

        <div className="flex flex-wrap items-center gap-4">
          <button
            type="submit"
            disabled={submitting}
            className="bg-accent-500 px-4 py-2 text-sm font-semibold text-surface-950 hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? 'Scanning…' : 'Run scan'}
          </button>
          {submitting ? <LoadingSpinner label="Waiting for scanner response…" /> : null}
        </div>
      </form>
    </div>
  )
}
