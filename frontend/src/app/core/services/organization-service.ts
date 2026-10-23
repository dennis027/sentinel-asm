import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import {
  ActivityEvent,
  CertificateRow,
  Changes,
  ComplianceFramework,
  EmergingThreats,
  GettingStarted,
  Hosting,
  Preflight,
  SurfaceChangeKind,
  SurfaceChanges,
  FixPlan,
  Heatmap,
  Invitation,
  Member,
  OrgRole,
  Organization,
  Paginated,
  RiskSummary,
  ServiceRow,
  Severity,
  SurfaceMap,
  TechnologyRow,
  TrendPoint,
} from '../models/models';

@Injectable({ providedIn: 'root' })
export class OrganizationService {
  private readonly http = inject(HttpClient);
  private readonly base = `${environment.apiBaseUrl}/organizations`;

  list(): Observable<Paginated<Organization>> {
    // One page is the whole list for any realistic number of
    // organizations a single user belongs to.
    return this.http.get<Paginated<Organization>>(this.base + '/', {
      params: { page_size: 200 },
    });
  }

  /** The creator becomes the new organization's owner. */
  create(name: string, rootDomain: string): Observable<Organization> {
    return this.http.post<Organization>(this.base + '/', { name, root_domain: rootDomain });
  }

  /**
   * Permanently removes the organization and everything under it:
   * assets, findings, scan history, screenshots, rules and memberships.
   * Owner only.
   */
  delete(id: string): Observable<void> {
    return this.http.delete<void>(`${this.base}/${id}/`);
  }

  /** Admin or higher. */
  update(
    id: string,
    change: Partial<Pick<Organization, 'name' | 'sla_days' | 'scope_exclusions' | 'log_retention_days'>>,
  ): Observable<Organization> {
    return this.http.patch<Organization>(`${this.base}/${id}/`, change);
  }

  /** Open issues grouped into the actions that fix them, most urgent first. */
  fixPlan(id: string): Observable<FixPlan> {
    return this.http.get<FixPlan>(`${this.base}/${id}/fix-plan/`);
  }

  /** New issues of the last 30 days by severity: how busy an alert threshold would be. */
  alertVolume(id: string): Observable<{ days: number; new_issues: Record<Severity, number> }> {
    return this.http.get<{ days: number; new_issues: Record<Severity, number> }>(`${this.base}/${id}/alert-volume/`);
  }

  heatmap(id: string): Observable<Heatmap> {
    return this.http.get<Heatmap>(`${this.base}/${id}/heatmap/`);
  }

  technologies(id: string): Observable<TechnologyRow[]> {
    return this.http.get<TechnologyRow[]>(`${this.base}/${id}/technologies/`);
  }

  services(id: string): Observable<ServiceRow[]> {
    return this.http.get<ServiceRow[]>(`${this.base}/${id}/services/`);
  }

  certificates(id: string): Observable<CertificateRow[]> {
    return this.http.get<CertificateRow[]>(`${this.base}/${id}/certificates/`);
  }

  members(id: string): Observable<Member[]> {
    return this.http.get<Member[]>(`${this.base}/${id}/members/`);
  }

  /** `identifier` is the username or email of an existing account. */
  addMember(id: string, identifier: string, role: OrgRole): Observable<Member> {
    return this.http.post<Member>(`${this.base}/${id}/members/`, { identifier, role });
  }

  invitations(id: string): Observable<Invitation[]> {
    return this.http.get<Invitation[]>(`${this.base}/${id}/invitations/`);
  }

  invite(id: string, email: string, role: OrgRole): Observable<Invitation> {
    return this.http.post<Invitation>(`${this.base}/${id}/invitations/`, { email, role });
  }

  resendInvitation(id: string, invitationId: string): Observable<Invitation> {
    return this.http.post<Invitation>(`${this.base}/${id}/invitations/${invitationId}/resend/`, {});
  }

  cancelInvitation(id: string, invitationId: string): Observable<void> {
    return this.http.delete<void>(`${this.base}/${id}/invitations/${invitationId}/`);
  }

  updateMemberRole(id: string, membershipId: string, role: OrgRole): Observable<Member> {
    return this.http.patch<Member>(`${this.base}/${id}/members/${membershipId}/`, { role });
  }

  removeMember(id: string, membershipId: string): Observable<void> {
    return this.http.delete<void>(`${this.base}/${id}/members/${membershipId}/`);
  }

  /** Asks the server to look for the organization's verification TXT record. */
  verifyDomain(id: string): Observable<Organization> {
    return this.http.post<Organization>(`${this.base}/${id}/verify-domain/`, {});
  }

  riskSummary(id: string): Observable<RiskSummary> {
    return this.http.get<RiskSummary>(`${this.base}/${id}/risk-summary/`);
  }

  /** New hosts, new issues and resolved issues over the last `days`. */
  changes(id: string, days = 7): Observable<Changes> {
    return this.http.get<Changes>(`${this.base}/${id}/changes/`, { params: { days } });
  }

  /** One point per recorded day: score, grade, open issues. */
  trend(id: string, days = 90): Observable<{ days: number; points: TrendPoint[] }> {
    return this.http.get<{ days: number; points: TrendPoint[] }>(`${this.base}/${id}/trend/`, {
      params: { days },
    });
  }

  compliance(id: string): Observable<{ frameworks: ComplianceFramework[]; disclaimer: string }> {
    return this.http.get<{ frameworks: ComplianceFramework[]; disclaimer: string }>(
      `${this.base}/${id}/compliance/`,
    );
  }

  activity(id: string, page = 1): Observable<Paginated<ActivityEvent>> {
    return this.http.get<Paginated<ActivityEvent>>(`${this.base}/${id}/activity/`, { params: { page } });
  }

  surfaceMap(id: string): Observable<SurfaceMap> {
    return this.http.get<SurfaceMap>(`${this.base}/${id}/surface-map/`);
  }

  /** The short PDF for someone who won't log in: grade, changes, top risks. */
  report(id: string, days = 7): Observable<Blob> {
    return this.http.get(`${this.base}/${id}/report/`, { params: { days }, responseType: 'blob' });
  }

  export(id: string, format: 'csv' | 'json' | 'pdf'): Observable<Blob> {
    // NOT "format" as the query param -- that's DRF's own reserved
    // content-negotiation parameter (see the backend's export action
    // docstring).
    return this.http.get(`${this.base}/${id}/export/`, {
      params: { export_format: format },
      responseType: 'blob',
    });
  }

  /** The check before a scan; all scanners when none are named. */
  preflight(id: string, scanners: string[] = []): Observable<Preflight> {
    const params: Record<string, string> = scanners.length ? { scanners: scanners.join(',') } : {};
    return this.http.get<Preflight>(`${this.base}/${id}/preflight/`, { params });
  }

  /** What appeared on and went from the attack surface, newest first. */
  surfaceChanges(id: string, days = 30, kind: SurfaceChangeKind | '' = ''): Observable<SurfaceChanges> {
    const params: Record<string, string | number> = { days };
    if (kind) {
      params['kind'] = kind;
    }
    return this.http.get<SurfaceChanges>(`${this.base}/${id}/surface-changes/`, { params });
  }

  /** Recently exploited vulnerabilities (CISA KEV) in software the organization runs. */
  emergingThreats(id: string): Observable<EmergingThreats> {
    return this.http.get<EmergingThreats>(`${this.base}/${id}/emerging-threats/`);
  }

  hosting(id: string): Observable<Hosting> {
    return this.http.get<Hosting>(`${this.base}/${id}/hosting/`);
  }

  gettingStarted(id: string): Observable<GettingStarted> {
    return this.http.get<GettingStarted>(`${this.base}/${id}/getting-started/`);
  }
}
