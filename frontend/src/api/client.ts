const API_KEY_STORAGE_KEY = 'pengu1n_api_key'

export class ApiError extends Error {
  status: number
  details: unknown

  constructor(message: string, status: number, details?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.details = details
  }
}

export function getApiBaseUrl(): string {
  const baseUrl = import.meta.env.VITE_API_BASE_URL?.trim()
  return baseUrl && baseUrl.length > 0 ? baseUrl.replace(/\/$/, '') : 'http://127.0.0.1:8000'
}

export function getStoredApiKey(): string {
  if (typeof window === 'undefined') {
    return ''
  }
  return window.localStorage.getItem(API_KEY_STORAGE_KEY)?.trim() ?? ''
}

export function setStoredApiKey(apiKey: string): void {
  const trimmed = apiKey.trim()
  if (!trimmed) {
    window.localStorage.removeItem(API_KEY_STORAGE_KEY)
    return
  }
  window.localStorage.setItem(API_KEY_STORAGE_KEY, trimmed)
}

export function getApiKey(): string {
  const fromEnv = import.meta.env.VITE_API_KEY?.trim() ?? ''
  const fromStorage = getStoredApiKey()
  return fromStorage || fromEnv
}

function formatValidationDetail(details: unknown): string {
  if (!Array.isArray(details)) {
    return 'Request validation failed.'
  }

  return details
    .map((item) => {
      if (typeof item !== 'object' || item === null) {
        return 'Invalid request value.'
      }
      const entry = item as { loc?: unknown[]; msg?: string }
      const location = Array.isArray(entry.loc)
        ? entry.loc.filter((part) => part !== 'body').join('.')
        : ''
      const message = entry.msg ?? 'Invalid value'
      return location ? `${location}: ${message}` : message
    })
    .join(' ')
}

async function parseError(response: Response): Promise<ApiError> {
  let payload: unknown = null
  try {
    payload = await response.json()
  } catch {
    payload = null
  }

  const detail =
    typeof payload === 'object' && payload !== null && 'detail' in payload
      ? (payload as { detail: unknown }).detail
      : null

  if (response.status === 401) {
    return new ApiError('Unauthorized. Check your API key in Settings.', 401, detail)
  }
  if (response.status === 404) {
    return new ApiError(
      typeof detail === 'string' ? detail : 'Resource not found.',
      404,
      detail,
    )
  }
  if (response.status === 422) {
    return new ApiError(formatValidationDetail(detail), 422, detail)
  }
  if (response.status >= 500) {
    return new ApiError(
      typeof detail === 'string' ? detail : 'Server error. Please try again.',
      response.status,
      detail,
    )
  }

  return new ApiError(
    typeof detail === 'string' ? detail : `Request failed with status ${response.status}.`,
    response.status,
    detail,
  )
}

export async function apiRequest<T>(
  path: string,
  options: RequestInit = {},
  requireAuth = true,
): Promise<T> {
  const headers = new Headers(options.headers ?? {})
  if (!headers.has('Content-Type') && options.body) {
    headers.set('Content-Type', 'application/json')
  }

  if (requireAuth) {
    const apiKey = getApiKey()
    if (!apiKey) {
      throw new ApiError(
        'API key is not configured. Set VITE_API_KEY or save a key in Settings.',
        401,
      )
    }
    headers.set('X-API-Key', apiKey)
  }

  let response: Response
  try {
    response = await fetch(`${getApiBaseUrl()}${path}`, {
      ...options,
      headers,
    })
  } catch {
    throw new ApiError(
      `Unable to reach the API at ${getApiBaseUrl()}. Is the FastAPI server running?`,
      0,
    )
  }

  if (!response.ok) {
    throw await parseError(response)
  }

  if (response.status === 204) {
    return undefined as T
  }

  return (await response.json()) as T
}
