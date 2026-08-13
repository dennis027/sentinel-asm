// These mirror the DRF serializers in apps/*/serializers.py exactly --
// keep them in sync when a backend field changes. UUID fields are
// typed as `string`, matching how they arrive over JSON.

export interface Organization {
  id: string;
  name: string;
  root_domain: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export type AssetType = 'domain' | 'subdomain' | 'ip' | 'url';

export interface Technology {
  id: string;
  name: string;
  version: string;
  category: string;
  first_seen: string;
  last_seen: string;
}

export interface Asset {
  id: string;
  organization: string;
  organization_name: string;
  asset_type: AssetType;
  value: string;
  is_active: boolean;
  first_seen: string;
  last_seen: string;
  technologies: Technology[];
  risk_score: number;
  risk_grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
}

export type ScanJobStatus = 'pending' | 'running' | 'retrying' | 'success' | 'failed';

export interface ScanJob {
  id: string;
  organization: string;
  organization_name: string;
  asset: string | null;
  asset_value: string | null;
  scanner_name: string;
  status: ScanJobStatus;
  error_message: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface TriggerScanRequest {
  scanner_name: string;
  asset_id?: string;
  organization_id?: string;
  force?: boolean;
}

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type FindingType =
  | 'open_port'
  | 'missing_header'
  | 'expired_ssl'
  | 'exposed_service'
  | 'nuclei_match'
  | 'subdomain_discovered'
  | 'dns_change'
  | 'screenshot';

export interface Finding {
  id: string;
  asset: string;
  asset_value: string;
  finding_type: FindingType;
  severity: Severity;
  title: string;
  description: string;
  raw_data: Record<string, unknown>;
  is_active: boolean;
  first_seen: string;
  last_seen: string;
}

export interface ScannerInfo {
  name: string;
  applies_to: 'asset' | 'organization';
  owned_finding_types: FindingType[];
}

export interface NotificationRule {
  id: string;
  organization: string;
  organization_name: string;
  recipient_email: string;
  min_severity: Severity;
  is_active: boolean;
  created_at: string;
}

export interface RiskSummary {
  organization: string;
  asset_count: number;
  average_risk_score: number | null;
  average_risk_grade: string | null;
  grade_distribution: Record<string, number>;
  active_findings_by_severity: Record<Severity, number>;
}

// DRF's PageNumberPagination shape -- every list endpoint returns this.
export interface Paginated<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}