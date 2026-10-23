import { AssetWeb, Criticality, FindingStatus, FindingType, OrgRole } from './models/models';

// Plain-language names for values the API sends as identifiers.

const FINDING_TYPE_LABELS: Record<FindingType, string> = {
  open_port: 'Open port',
  missing_header: 'Missing security header',
  expired_ssl: 'TLS certificate',
  exposed_service: 'Exposed service',
  nuclei_match: 'Vulnerability',
  subdomain_discovered: 'Subdomain',
  dns_change: 'DNS record',
  screenshot: 'Screenshot',
  email_security: 'Email spoofing protection',
  subdomain_takeover: 'Subdomain takeover',
  weak_tls: 'TLS configuration',
  outdated_software: 'Outdated software',
  security_txt: 'Security contact',
  exposed_file: 'Exposed file',
  zone_transfer: 'DNS zone transfer',
  cors_misconfiguration: 'CORS',
  insecure_cookie: 'Cookie security',
  https_not_enforced: 'HTTPS enforcement',
  lookalike_domain: 'Lookalike domain',
  exposed_panel: 'Exposed admin panel',
  api_exposure: 'API exposure',
  dns_hygiene: 'DNS hygiene',
  cert_issued: 'Certificate',
  unusual_certificate: 'Unusual certificate',
  exposed_secret: 'Secret in public code',
  public_bucket: 'Public cloud storage',
  domain_registration: 'Domain registration',
  policy_violation: 'Breaks a policy',
};

export function findingTypeLabel(type: string): string {
  return FINDING_TYPE_LABELS[type as FindingType] ?? type;
}

export const FINDING_STATUS_LABELS: Record<FindingStatus, string> = {
  open: 'Open',
  accepted: 'Risk accepted',
  false_positive: 'False positive',
};

export const FRAMEWORK_SHORT_NAMES: Record<string, string> = {
  owasp: 'OWASP',
  cis: 'CIS',
  iso27001: 'ISO 27001',
  pci: 'PCI DSS',
  attack: 'ATT&CK',
};

export const CRITICALITIES: { value: Criticality; label: string; hint: string }[] = [
  { value: 'crown_jewel', label: 'Crown jewel', hint: 'Payments, customer data, sign-in: a breach here is a headline' },
  { value: 'high', label: 'High', hint: 'Important to the business or holds sensitive data' },
  { value: 'normal', label: 'Normal', hint: 'An ordinary production host' },
  { value: 'low', label: 'Low', hint: 'Test, staging or marketing; little at stake' },
];

export function criticalityLabel(value: Criticality | string): string {
  return CRITICALITIES.find((c) => c.value === value)?.label ?? value;
}

export const SCANNER_CATEGORIES: { id: string; label: string; blurb: string }[] = [
  { id: 'discovery', label: 'Discovery & inventory', blurb: 'Find out what you have online.' },
  { id: 'web', label: 'Web applications', blurb: 'Weaknesses in the sites and APIs themselves.' },
  { id: 'encryption', label: 'Encryption', blurb: 'Certificates, TLS and HTTPS.' },
  { id: 'network', label: 'Network', blurb: 'Services and DNS reachable from the internet.' },
  { id: 'email_domain', label: 'Email & domain', blurb: 'Spoofing, lookalike domains, takeovers and how to reach you.' },
];

export const ROLES: { value: OrgRole; label: string; can: string }[] = [
  { value: 'viewer', label: 'Viewer', can: 'See assets, findings and scan history' },
  { value: 'analyst', label: 'Analyst', can: 'Also run scans and triage findings' },
  { value: 'admin', label: 'Admin', can: 'Also manage members, notifications and settings' },
  { value: 'owner', label: 'Owner', can: 'Also delete the organization' },
];

export function roleLabel(role: OrgRole | null | undefined): string {
  return ROLES.find((r) => r.value === role)?.label ?? 'No role';
}

/** The first human-readable message in a DRF error body, if there is one. */
export function apiErrorMessage(error: unknown, fallback: string): string {
  const body = (error as { error?: unknown })?.error;
  if (!body || typeof body !== 'object') return fallback;
  for (const value of Object.values(body as Record<string, unknown>)) {
    if (typeof value === 'string') return value;
    if (Array.isArray(value) && typeof value[0] === 'string') return value[0];
  }
  return fallback;
}

/** The last web response as a short label and a tone for its pill. */
export function webStatus(web: AssetWeb | undefined): { text: string; tone: 'ok' | 'redirect' | 'client' | 'server' | 'none'; hint: string } {
  const status = web?.status;
  if (!status) {
    return { text: 'No reply', tone: 'none', hint: 'No web response recorded yet, or the site did not answer on HTTPS.' };
  }
  const hint = [web.title, web.response_ms !== undefined ? `${web.response_ms} ms` : ''].filter(Boolean).join(' · ');
  if (status < 300) return { text: String(status), tone: 'ok', hint };
  if (status < 400) return { text: `${status} →`, tone: 'redirect', hint: web.final_url ? `Goes to ${web.final_url}` : hint };
  if (status < 500) return { text: String(status), tone: 'client', hint };
  return { text: String(status), tone: 'server', hint };
}
