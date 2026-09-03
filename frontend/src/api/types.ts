export type ScanProfile = 'quick' | 'standard' | 'deep' | 'bug_bounty'

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export interface ScopeConfig {
  allowed_hosts: string[]
  excluded_hosts: string[]
  requests_per_second?: number | null
}

export interface ScanRequest {
  target: string
  profile: ScanProfile
  scope?: ScopeConfig
}

export interface Finding {
  id: string
  title: string
  description: string
  severity: string
  category: string
  recommendation: string
  target?: string | null
  port?: number | null
  evidence?: string | null
  cve_id?: string | null
  confidence?: string | null
  references: string[]
}

export interface Service {
  port: number
  name: string
  version?: string | null
}

export interface RiskSummary {
  severity: string
  counts: Record<string, number>
}

export interface ScanSummary {
  scan_id: string
  target: string
  profile: string
  status: string
  started_at: string
  completed_at: string
  duration_seconds: number
  risk_severity: string
  finding_count: number
  risk_counts?: Record<string, number>
}

export interface ScanResult {
  scan_id: string
  target: string
  profile: ScanProfile
  status: string
  requests_per_second?: number | null
  started_at: string
  completed_at: string
  duration_seconds: number
  findings: Finding[]
  open_ports: number[]
  services: Service[]
  risk: RiskSummary
}

export interface CveSummaryItem {
  cve_id: string
  finding_id: string
  title: string
  severity: string
  confidence?: string | null
  service_name?: string | null
  service_version?: string | null
  port?: number | null
  references: string[]
}

export interface SecurityReport {
  report_id: string
  scan_id: string
  target: string
  profile: string
  generated_at: string
  duration_seconds: number
  risk: RiskSummary
  services: Service[]
  findings: Finding[]
  prioritized_findings: Finding[]
  cve_summary: CveSummaryItem[]
  executive_summary: string
  recommendations: string[]
  ai_enhanced: boolean
}
