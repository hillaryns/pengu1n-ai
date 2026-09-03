import { apiRequest } from './client'
import type { ScanRequest, ScanResult, ScanSummary, SecurityReport } from './types'

export function createScan(payload: ScanRequest): Promise<ScanResult> {
  return apiRequest<ScanResult>('/scan', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function listScans(): Promise<ScanSummary[]> {
  return apiRequest<ScanSummary[]>('/scans')
}

export function getScan(scanId: string): Promise<ScanResult> {
  return apiRequest<ScanResult>(`/scans/${encodeURIComponent(scanId)}`)
}

export function getScanReport(scanId: string): Promise<SecurityReport> {
  return apiRequest<SecurityReport>(`/scan/${encodeURIComponent(scanId)}/report`)
}

export function getHealth(): Promise<{ status: string }> {
  return apiRequest<{ status: string }>('/health', {}, false)
}
