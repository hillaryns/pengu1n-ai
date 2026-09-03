import { createContext, useContext, useState, type ReactNode } from 'react'
import { getApiKey, getStoredApiKey, setStoredApiKey } from '../api/client'

interface ApiConfigContextValue {
  apiKeyConfigured: boolean
  storedApiKey: string
  saveStoredApiKey: (apiKey: string) => void
}

const ApiConfigContext = createContext<ApiConfigContextValue | null>(null)

export function ApiConfigProvider({ children }: { children: ReactNode }) {
  const [storedApiKey, setStoredApiKeyState] = useState(getStoredApiKey)
  const apiKeyConfigured = Boolean(getApiKey())

  function saveStoredApiKey(apiKey: string) {
    setStoredApiKey(apiKey)
    setStoredApiKeyState(getStoredApiKey())
  }

  return (
    <ApiConfigContext.Provider
      value={{
        apiKeyConfigured,
        storedApiKey,
        saveStoredApiKey,
      }}
    >
      {children}
    </ApiConfigContext.Provider>
  )
}

export function useApiConfig(): ApiConfigContextValue {
  const value = useContext(ApiConfigContext)
  if (!value) {
    throw new Error('useApiConfig must be used within ApiConfigProvider')
  }
  return value
}
