// These mirror the DRF serializers in apps/*/serializers.py exactly --
// keep them in sync when a backend field changes. UUID fields are
// typed as `string`, matching how they arrive over JSON.

// Each role can do everything the ones before it can:
// viewer (read-only) < analyst (scan, triage) < admin (settings) < owner (delete).
export type OrgRole = 'viewer' | 'analyst' | 'admin' | 'owner';

export interface Organization {
  id: string;
  name: string;
  root_domain: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  // The logged-in user's own role in this organization.
  my_role: OrgRole | null;
  domain_verified: boolean;
  domain_verified_at: string | null;
  // Whether this server insists on domain verification before scanning.
  verification_required: boolean;
  // The DNS TXT record that proves control of root_domain.
  verification_record_name: string;
  verification_record_value: string;
  scans_allowed: boolean;
  // Days to fix an issue, by severity: the policy in force.
  sla_days: Record<'critical' | 'high' | 'medium' | 'low', number>;
  // Host names never to scan; "*.name" covers everything under name.
  scope_exclusions: string[];
  // How long server logs are kept, in days.
  log_retention_days: number;
}

/** The signed-in account. */
export interface Profile {
  id: number;
  username: string;
  email: string;
  first_name: string;
  last_name: string;
  date_joined: string;
  last_login: string | null;
  two_factor_enabled: boolean;
}

/** An invitation still waiting to be accepted, as admins see it. */
export interface Invitation {
  id: string;
  email: string;
  role: OrgRole;
  role_label: string;
  status: 'pending' | 'accepted' | 'revoked' | 'expired';
  invited_by: string | null;
  created_at: string;
  expires_at: string;
  // Only right after creating or resending: the link, shown once.
  invite_link?: string;
  email_sent?: boolean;
}

/** What an invitation link is for, as the invited person sees it. */
export interface InvitationDetail {
  organization: string;
  email: string;
  role: OrgRole;
  role_label: string;
  invited_by: string | null;
  expires_at: string;
  status: Invitation['status'];
  detail: string;
  account_exists: boolean;
}

export interface Member {
  // Membership id, not the user's id.
  id: string;
  // The account's id -- what a finding is assigned to.
  user_id: number;
  username: string;
  email: string;
  role: OrgRole;
  created_at: string;
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

// How much it would hurt if the host were compromised; set by people.
export type Criticality = 'low' | 'normal' | 'high' | 'crown_jewel';

export interface Asset {
  id: string;
  organization: string;
  organization_name: string;
  asset_type: AssetType;
  value: string;
  source: 'discovered' | 'manual';
  is_active: boolean;
  first_seen: string;
  last_seen: string;
  technologies: Technology[];
  risk_score: number;
  risk_grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  criticality: Criticality;
  tags: string[];
  // On the organization's never-scan list.
  out_of_scope: boolean;
  // The member who answers for this host; new issues are assigned to them.
  owner: number | null;
  owner_name: string | null;
  // What the last scans saw of the host itself (empty until scanned).
  web: AssetWeb;
  hosting: AssetHosting;
}

export interface AssetWeb {
  status?: number;
  title?: string;
  final_url?: string;
  response_ms?: number;
  server?: string;
  checked_at?: string;
}

export interface AssetHosting {
  ips?: string[];
  cnames?: string[];
  reverse_names?: string[];
  provider?: string;
  checked_at?: string;
}

export type ScanJobStatus = 'pending' | 'running' | 'retrying' | 'success' | 'failed' | 'skipped';

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
  trigger: ScanTrigger;
  trigger_label: string;
  // Who started it; null for the daily schedule.
  triggered_by: string | null;
  // Shared by every scan started together.
  run_id: string;
}

/** Where a scan came from. */
export type ScanTrigger = 'schedule' | 'domain' | 'recheck' | 'single';

/** Scans started together (a night's schedule, a Run scan click, a re-check), as one. */
export interface ScanRun {
  run_id: string;
  trigger: ScanTrigger;
  trigger_label: string;
  triggered_by: string | null;
  // Set when the whole run was one scanner / one host.
  scanner_name: string | null;
  scanner_label: string | null;
  host: string | null;
  scanners: number;
  hosts: number;
  organization_level: boolean;
  jobs: number;
  succeeded: number;
  failed: number;
  // Not run because the host no longer exists in DNS; not a failure.
  skipped: number;
  unfinished: number;
  new_findings: number;
  started: string;
  finished: string | null;
}

export interface TriggerScanRequest {
  scanner_name: string;
  asset_id?: string;
  organization_id?: string;
  force?: boolean;
  // Several scans started together share a run id; "recheck" marks a host re-check.
  run_id?: string;
  reason?: 'recheck' | 'single';
}

// Reply to starting a scanner for a whole organization.
export interface DomainScanStarted {
  batch_id: string;
  scanner_name: string;
  // How many scans the run performs: 1, or one per asset.
  target_count: number;
}

// Where one scanner's most recent domain-wide run stands.
export interface ScanProgress {
  scanner_name: string;
  batch_id: string;
  started_at: string;
  total: number;
  pending: number;
  running: number;
  success: number;
  failed: number;
  skipped: number;
  finished: boolean;
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
  | 'screenshot'
  | 'email_security'
  | 'subdomain_takeover'
  | 'weak_tls'
  | 'outdated_software'
  | 'security_txt'
  | 'exposed_file'
  | 'zone_transfer'
  | 'cors_misconfiguration'
  | 'insecure_cookie'
  | 'https_not_enforced'
  | 'lookalike_domain'
  | 'exposed_panel'
  | 'api_exposure'
  | 'dns_hygiene'
  | 'cert_issued'
  | 'unusual_certificate'
  | 'exposed_secret'
  | 'public_bucket'
  | 'domain_registration'
  | 'policy_violation';

export type FindingStatus = 'open' | 'accepted' | 'false_positive';

export interface Finding {
  id: string;
  asset: string;
  asset_value: string;
  finding_type: FindingType;
  severity: Severity;
  title: string;
  description: string;
  // Plain-language context; both empty for inventory findings.
  impact: string;
  remediation: string;
  raw_data: Record<string, unknown>;
  // is_active: what the scanner last saw. status: what an analyst decided.
  is_active: boolean;
  status: FindingStatus;
  status_note: string;
  status_changed_at: string | null;
  status_changed_by: string | null;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  // Remediation workflow.
  assignee: number | null;
  assignee_username: string | null;
  // Fix-by date from the severity's SLA; null for info and inventory.
  due_at: string | null;
  overdue: boolean;
  // Framework controls this kind of issue relates to (indicative).
  controls: ControlRef[];
  // Set when a risk acceptance runs out on a date (YYYY-MM-DD).
  accepted_until: string | null;
  // Times a scan found it again after it had been fixed.
  reopened_count: number;
  reopened_at: string | null;
  asset_criticality: Criticality;
  // CVE ids the finding is about.
  cves: string[];
  // Set when one of them is in CISA's Known Exploited Vulnerabilities catalogue.
  known_exploited: KnownExploited | null;
}

export interface KnownExploited {
  cve: string;
  name: string;
  date_added: string | null;
  due_date: string | null;
  ransomware: boolean;
  required_action: string;
}

export interface FindingComment {
  id: string;
  author_name: string;
  body: string;
  created_at: string;
}

export interface TimelineEntry {
  // "detected", "comment", "seen", "resolved" or an activity verb.
  kind: string;
  at: string;
  actor: string;
  text: string;
}

export interface FixPlanStep {
  action: string;
  finding_type: FindingType;
  severity: Severity;
  remediation: string;
  issues: number;
  hosts: number;
  crown_jewels: number;
  overdue: number;
  known_exploited: number;
  items: { finding: string; asset: string; asset_value: string; title: string; severity: Severity }[];
  // The organization's score and grade once this and every earlier step is done.
  score_after: number | null;
  grade_after: string | null;
}

export interface FixPlan {
  current_score: number | null;
  current_grade: string | null;
  open_issues: number;
  steps: FixPlanStep[];
}

// Open issues by kind (rows) and severity (columns).
export interface Heatmap {
  severities: Severity[];
  rows: { finding_type: FindingType; label: string; counts: Partial<Record<Severity, number>>; total: number }[];
}

export interface HostRef {
  id: string;
  value: string;
}

export interface TechnologyRow {
  name: string;
  version: string;
  category: string;
  hosts: HostRef[];
  host_count: number;
}

export interface ServiceRow {
  port: number | string;
  protocol: string;
  service: string;
  severity: Severity;
  hosts: (HostRef & { product: string; finding: string; status: FindingStatus })[];
  host_count: number;
}

export interface CertificateRow {
  asset: string;
  asset_value: string;
  finding: string;
  not_after: string;
  days_remaining: number;
  severity: Severity;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
  // Only in the reply that creates it.
  key?: string;
}

export interface SignInEvent {
  id: string;
  event_type: string;
  label: string;
  ip_address: string | null;
  user_agent: string;
  created_at: string;
}

export interface TwoFactorSetup {
  secret: string;
  otpauth_uri: string;
  qr_svg: string;
}

export interface ControlRef {
  id: string; // e.g. "owasp:A05"
  framework: string;
  code: string;
  name: string;
}

export interface ScannerInfo {
  // Internal id (what scan jobs store); `label` is what people read.
  name: string;
  label: string;
  description: string;
  category: 'discovery' | 'network' | 'web' | 'encryption' | 'email_domain';
  applies_to: 'asset' | 'organization';
  owned_finding_types: FindingType[];
}

export type NotificationChannel = 'email' | 'webhook';

export interface NotificationRule {
  id: string;
  organization: string;
  organization_name: string;
  channel: NotificationChannel;
  // Exactly one of these is set, depending on the channel.
  recipient_email: string;
  webhook_url: string;
  min_severity: Severity;
  is_active: boolean;
  // Email rules only: also receives the Monday PDF report.
  weekly_report: boolean;
  created_at: string;
}

export interface AssetAtRisk {
  id: string;
  value: string;
  risk_score: number;
  risk_grade: string;
  open_findings: number;
}

export interface RiskSummary {
  organization: string;
  asset_count: number;
  // Assets with at least one open issue; the grade is averaged over these.
  assets_at_risk: number;
  worst_assets: AssetAtRisk[];
  remediation: Remediation;
  // The same numbers as a few plain sentences.
  narrative: string[];
  average_risk_score: number | null;
  average_risk_grade: string | null;
  grade_distribution: Record<string, number>;
  active_findings_by_severity: Record<Severity, number>;
}

// Matches the backend's default page size (config/pagination.py).
export const PAGE_SIZE = 25;

export interface Remediation {
  overdue: number;
  unassigned_critical_high: number;
  assigned: number;
  fixed_last_90_days: number;
  mean_days_to_fix: number | null;
  sla_days: Partial<Record<Severity, number>>;
}

export interface TrendPoint {
  date: string;
  score: number | null;
  grade: string;
  open_issues: number;
  critical_high: number;
  asset_count: number;
}

export interface ComplianceControl {
  id: string;
  code: string;
  name: string;
  open_issues: number;
  checks: number;
  inventory_only: boolean;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  controls: ComplianceControl[];
  controls_with_issues: number;
}

export interface ActivityEvent {
  id: string;
  actor: string;
  verb: string;
  summary: string;
  created_at: string;
}

export interface SurfaceNode {
  id: string;
  value: string;
  risk_score: number;
  risk_grade: string;
  open_findings: number;
  critical_high: number;
  clean: boolean;
  // Hosting provider, "" when not identified.
  provider: string;
}

export interface SurfaceMap {
  root_domain: string;
  total_assets: number;
  assets_at_risk: number;
  nodes: SurfaceNode[];
  hidden: number;
}

export interface ChangedFinding {
  id: string;
  title: string;
  severity: Severity;
  asset: string;
  asset_value: string;
}

// What is different from `days` ago.
export interface Changes {
  days: number;
  since: string;
  new_assets: { count: number; items: { id: string; value: string }[] };
  new_issues: { count: number; by_severity: Record<Severity, number>; items: ChangedFinding[] };
  resolved_issues: { count: number; items: ChangedFinding[] };
}

// DRF's PageNumberPagination shape -- every list endpoint returns this.
export interface Paginated<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}
// ---------------- Server logs ----------------

export type LogSourceStatus = 'waiting' | 'receiving' | 'silent';
export type LogSourceKind =
  | 'linux'
  | 'windows'
  | 'python'
  | 'node'
  | 'php'
  | 'ruby'
  | 'go'
  | 'java'
  | 'dotnet'
  | 'other';

export interface LogSource {
  id: string;
  organization: string;
  name: string;
  // A server's operating system, or an application's runtime.
  os: LogSourceKind;
  is_application: boolean;
  key_prefix: string;
  created_at: string;
  last_seen_at: string | null;
  last_host: string;
  events_received: number;
  status: LogSourceStatus;
  open_detections: number;
  // Only when the server is connected or its key replaced.
  key?: string;
  ingest_url?: string;
}

export type LogCategory =
  | 'auth_success'
  | 'auth_failure'
  | 'privilege'
  | 'account_change'
  | 'log_tampering'
  | 'service'
  | 'app_error'
  | 'http_request'
  | 'other';

export interface LogEventRow {
  id: number;
  source: string;
  source_name: string;
  occurred_at: string;
  received_at: string;
  host: string;
  program: string;
  event_id: number | null;
  level: 'info' | 'warning' | 'error';
  category: LogCategory;
  category_label: string;
  action: string;
  user: string;
  src_ip: string | null;
  message: string;
  raw: Record<string, unknown>;
  service: string;
  http_status: number | null;
  fingerprint: string;
  // Kinds of secret masked out before storing.
  redacted: string[];
  release: string;
}

export interface ErrorGroup {
  id: string;
  source: string;
  source_name: string;
  fingerprint: string;
  exception_type: string;
  title: string;
  culprit: string;
  service: string;
  count: number;
  first_seen: string;
  last_seen: string;
  stacktrace: string;
  status: 'unresolved' | 'resolved' | 'ignored';
  resolved_at: string | null;
  regressions: number;
  first_release: string;
  last_release: string;
}

/** How many events each option of each search filter would give, with the other filters applied. */
export interface LogFacets {
  source: Record<string, number>;
  category: Partial<Record<LogCategory, number>>;
  level: Partial<Record<'info' | 'warning' | 'error', number>>;
  service: [string, number][];
  release: [string, number][];
  host: [string, number][];
  status: Record<'2xx' | '3xx' | '4xx' | '5xx', number>;
}

/** Matching events over time, split by level. */
export interface LogTimeline {
  start: string;
  end: string;
  bucket_seconds: number;
  buckets: { t: string; error: number; warning: number; info: number }[];
}

/** An application release seen in the logs (last 30 days). */
export interface AppRelease {
  source: string;
  source_name: string;
  release: string;
  first_seen: string;
  last_seen: string;
  events: number;
  errors: number;
  new_errors: number;
}

/** An organization's own log alert: "<contains> seen <threshold> times within <window_minutes>". */
export interface LogAlertRule {
  id: string;
  organization: string;
  name: string;
  contains: string;
  source: string | null;
  source_name: string | null;
  category: LogCategory | '';
  level: '' | 'warning' | 'error';
  threshold: number;
  window_minutes: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  created_by: string | null;
  created_at: string;
  last_fired_at: string | null;
  matches_24h: number;
}

export interface LogDetection {
  id: string;
  source: string;
  source_name: string;
  rule: string;
  severity: Severity;
  title: string;
  description: string;
  user: string;
  src_ip: string | null;
  event_count: number;
  first_seen: string;
  last_seen: string;
  status: 'open' | 'resolved';
  resolved_at: string | null;
  resolved_by: string | null;
}

export interface LogOverview {
  events_24h: number;
  by_category_24h: Record<LogCategory, number>;
  failed_signins_24h: number;
  sources: { total: number; receiving: number; silent: number; waiting: number };
  open_detections: number;
  applications: number;
  errors_24h: number;
  server_errors_24h: number;
  unresolved_errors: number;
  open_by_severity: Partial<Record<Severity, number>>;
  top_attackers_24h: { ip: string; failures: number }[];
  retention_days: number;
  rules: { rule: string; severity: Severity; title: string; description: string }[];
}

/** Why a run's scans failed or were skipped, grouped by cause. */
export interface ScanRunReason {
  status: 'failed' | 'skipped';
  reason: string;
  count: number;
  scanners: string[];
  hosts: string[];
}

/** The check before a scan (GET /organizations/{id}/preflight/). */
export interface Preflight {
  scans_allowed: boolean;
  hosts: {
    active: number;
    in_scope: number;
    excluded: number;
    checked: number;
    resolves: number;
    missing: number;
    private: number;
    unknown: number;
    missing_hosts: string[];
    private_hosts: string[];
    checked_at: string;
  };
  scanners: {
    name: string;
    label: string;
    applies_to: 'asset' | 'organization';
    targets: number;
    likely_skipped: number;
    missing_tools: string[];
    running: boolean;
    typical_seconds: number;
  }[];
  jobs: number;
  estimated_seconds: number;
  worker_seen_at: string | null;
  warnings: string[];
  ready: boolean;
}

export type SurfaceChangeKind =
  | 'host_added'
  | 'host_gone'
  | 'port_opened'
  | 'port_closed'
  | 'software_seen'
  | 'certificate'
  | 'dns_changed';

export interface SurfaceChangeEvent {
  kind: SurfaceChangeKind;
  label: string;
  at: string;
  asset: string;
  asset_value: string;
  detail: string;
}

export interface SurfaceChanges {
  days: number;
  since: string;
  counts: Record<SurfaceChangeKind, number>;
  kinds: Record<SurfaceChangeKind, string>;
  total: number;
  events: SurfaceChangeEvent[];
}

export interface EmergingThreat {
  cve: string;
  name: string;
  vendor: string;
  product: string;
  description: string;
  required_action: string;
  date_added: string;
  due_date: string | null;
  ransomware: boolean;
  software: string;
  hosts: { id: string; value: string; version: string; confirmed: boolean }[];
  // A scan already found this CVE on one of the hosts.
  confirmed: boolean;
}

export interface EmergingThreats {
  days: number;
  catalogue_recent: number;
  software_checked: number;
  items: EmergingThreat[];
}

export interface Hosting {
  providers: { provider: string; count: number; hosts: string[] }[];
  unknown: { count: number; hosts: string[] };
  unchecked: number;
  addresses: number;
  shared_addresses: { address: string; count: number; hosts: string[] }[];
}

export interface GettingStartedStep {
  key: string;
  title: string;
  detail: string;
  done: boolean;
  link: string;
}

export interface GettingStarted {
  steps: GettingStartedStep[];
  done: number;
  total: number;
  complete: boolean;
}

export type PolicyKind = 'port' | 'technology' | 'hostname' | 'provider';

export interface SurfacePolicy {
  id: string;
  organization: string;
  name: string;
  kind: PolicyKind;
  kind_label: string;
  value: string;
  severity: Severity;
  guidance: string;
  enabled: boolean;
  rule: string;
  // Hosts breaking it right now.
  breaking: number;
  created_at: string;
}

export interface SavedView {
  id: string;
  organization: string;
  page: 'findings' | 'assets';
  name: string;
  filters: Record<string, string>;
  shared: boolean;
  owner_name: string;
  is_mine: boolean;
  created_at: string;
}

