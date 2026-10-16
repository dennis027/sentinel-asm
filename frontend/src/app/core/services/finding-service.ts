import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import {
  Criticality,
  Finding,
  FindingComment,
  FindingStatus,
  Paginated,
  Severity,
  TimelineEntry,
} from '../models/models';

export interface FindingFilters {
  organization?: string;
  asset?: string;
  finding_type?: string;
  // issue: something wrong. inventory: subdomains, DNS records, screenshots.
  kind?: 'issue' | 'inventory';
  severity?: Severity;
  is_active?: boolean;
  // true: accepted / false-positive findings; false: still open.
  triaged?: boolean;
  search?: string;
  page?: number;
  page_size?: number;
  // "me", "none" or a user id.
  assignee?: string;
  overdue?: boolean;
  // A framework control id such as "owasp:A05".
  control?: string;
  // Fixed once, then found again.
  regressed?: boolean;
  asset_criticality?: Criticality;
}

export type BulkAction =
  | { action: 'triage'; status: FindingStatus; note?: string; accepted_until?: string | null }
  | { action: 'assign'; assignee: number | null };

@Injectable({ providedIn: 'root' })
export class FindingService {
  private readonly http = inject(HttpClient);
  private readonly base = `${environment.apiBaseUrl}/findings`;

  list(filters: FindingFilters = {}): Observable<Paginated<Finding>> {
    let params = new HttpParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== null && value !== '') {
        params = params.set(key, String(value));
      }
    }
    return this.http.get<Paginated<Finding>>(this.base + '/', { params });
  }

  get(id: string): Observable<Finding> {
    return this.http.get<Finding>(`${this.base}/${id}/`);
  }

  /** Makes a member responsible for fixing it; null removes the assignee. */
  assign(id: string, assignee: number | null): Observable<Finding> {
    return this.http.post<Finding>(`${this.base}/${id}/assign/`, { assignee });
  }

  /** `acceptedUntil` (YYYY-MM-DD) only with "accepted": the date it opens again. */
  triage(id: string, status: FindingStatus, note = '', acceptedUntil: string | null = null): Observable<Finding> {
    return this.http.post<Finding>(`${this.base}/${id}/triage/`, {
      status,
      note,
      ...(acceptedUntil ? { accepted_until: acceptedUntil } : {}),
    });
  }

  /** One triage or assignment for many findings of one organization. */
  bulk(ids: string[], change: BulkAction): Observable<{ updated: number }> {
    return this.http.post<{ updated: number }>(`${this.base}/bulk/`, { ids, ...change });
  }

  comments(id: string): Observable<FindingComment[]> {
    return this.http.get<FindingComment[]>(`${this.base}/${id}/comments/`);
  }

  addComment(id: string, body: string): Observable<FindingComment> {
    return this.http.post<FindingComment>(`${this.base}/${id}/comments/`, { body });
  }

  /** Everything that happened to the finding, oldest first. */
  timeline(id: string): Observable<TimelineEntry[]> {
    return this.http.get<TimelineEntry[]>(`${this.base}/${id}/timeline/`);
  }

  /**
   * The image behind a screenshot finding. Fetched as a blob through
   * HttpClient (rather than pointing an <img> at a URL) because the
   * endpoint needs the Authorization header like every other API call.
   */
  screenshot(id: string): Observable<Blob> {
    return this.http.get(`${this.base}/${id}/screenshot/`, { responseType: 'blob' });
  }
}
