import { useState, type FormEvent } from 'react'
import { getApiBaseUrl, getApiKey } from '../api/client'
import { useApiConfig } from '../context/ApiConfigContext'

export function SettingsPage() {
  const { storedApiKey, saveStoredApiKey } = useApiConfig()
  const [apiKey, setApiKey] = useState(storedApiKey)
  const [saved, setSaved] = useState(false)
  const envConfigured = Boolean(import.meta.env.VITE_API_KEY?.trim())

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    saveStoredApiKey(apiKey)
    setSaved(true)
  }

  return (
    <div className="mx-auto max-w-2xl space-y-8">
      <header>
        <h2 className="font-display text-3xl tracking-tight text-slate-50">Settings</h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          Local API access only. Keys stay in this browser or in a local `.env` file and are never
          committed.
        </p>
      </header>

      <section className="space-y-3 border-y border-surface-700/70 py-5 text-sm">
        <h3 className="text-sm font-semibold text-slate-200">Connection</h3>
        <dl className="space-y-2">
          <div className="flex justify-between gap-4">
            <dt className="text-slate-500">API base URL</dt>
            <dd className="font-mono text-slate-300">{getApiBaseUrl()}</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-slate-500">Effective API key</dt>
            <dd className="text-slate-300">{getApiKey() ? 'Configured' : 'Missing'}</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-slate-500">VITE_API_KEY</dt>
            <dd className="text-slate-300">{envConfigured ? 'Present in env' : 'Not set'}</dd>
          </div>
        </dl>
      </section>

      <form onSubmit={handleSubmit} className="space-y-4">
        <label className="block space-y-2">
          <span className="text-sm font-medium text-slate-200">Local API key override</span>
          <input
            type="password"
            value={apiKey}
            onChange={(event) => {
              setApiKey(event.target.value)
              setSaved(false)
            }}
            placeholder="Paste X-API-Key value for local development"
            className="w-full border border-surface-700 bg-surface-900 px-3 py-2 font-mono text-sm text-slate-100 outline-none focus:border-accent-500"
            autoComplete="off"
          />
          <span className="text-xs text-slate-500">
            Stored only in this browser&apos;s localStorage. Leave blank to use VITE_API_KEY.
          </span>
        </label>

        <button
          type="submit"
          className="bg-accent-500 px-4 py-2 text-sm font-semibold text-surface-950 hover:bg-accent-400"
        >
          Save API key
        </button>
        {saved ? (
          <p className="text-sm text-accent-400">API key saved for this browser.</p>
        ) : null}
      </form>
    </div>
  )
}
