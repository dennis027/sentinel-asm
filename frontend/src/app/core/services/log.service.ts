import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import {
  AppRelease,
  ErrorGroup,
  LogAlertRule,
  LogDetection,
  LogEventRow,
  LogFacets,
  LogOverview,
  LogSource,
  LogSourceKind,
  LogTimeline,
  Paginated,
} from '../models/models';

export type LogAlertRuleInput = Pick<
  LogAlertRule,
  'organization' | 'name' | 'contains' | 'source' | 'category' | 'level' | 'threshold' | 'window_minutes' | 'severity'
>;

export interface LogSearch {
  organization: string;
  source?: string;
  category?: string;
  // info, warning, error, or "problems" for warnings and errors
  level?: string;
  service?: string;
  release?: string;
  host?: string;
  user?: string;
  ip?: string;
  fingerprint?: string;
  // "5xx", "4xx" or an exact code
  status?: string;
  q?: string;
  // 1h, 24h, 7d, 30d, all, or custom (with after/before)
  since?: string;
  after?: string;
  before?: string;
  page?: number;
  page_size?: number;
  // Live updates: only events stored after this one.
  after_id?: number;
}

export interface DetectionFilters {
  severity?: string;
  source?: string;
  // a built-in rule, or "custom" for the organization's own alerts
  rule?: string;
  q?: string;
}

function params(values: object): HttpParams {
  let result = new HttpParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== null && value !== '') result = result.set(key, String(value));
  }
  return result;
}

/** Server logs: connected servers, the events they send, and what the detections found. */
@Injectable({ providedIn: 'root' })
export class LogService {
  private readonly http = inject(HttpClient);
  private readonly api = environment.apiBaseUrl;

  overview(organization: string): Observable<LogOverview> {
    return this.http.get<LogOverview>(`${this.api}/logs/overview/`, { params: { organization } });
  }

  sources(organization: string): Observable<LogSource[]> {
    return this.http.get<LogSource[]>(`${this.api}/log-sources/`, { params: { organization } });
  }

  /** Admin only. The reply's `key` is the only time it is shown. */
  connect(organization: string, name: string, os: LogSourceKind): Observable<LogSource> {
    return this.http.post<LogSource>(`${this.api}/log-sources/`, { organization, name, os });
  }

  replaceKey(id: string): Observable<LogSource> {
    return this.http.post<LogSource>(`${this.api}/log-sources/${id}/replace-key/`, {});
  }

  disconnect(id: string): Observable<void> {
    return this.http.delete<void>(`${this.api}/log-sources/${id}/`);
  }

  events(search: LogSearch): Observable<Paginated<LogEventRow>> {
    return this.http.get<Paginated<LogEventRow>>(`${this.api}/log-events/`, { params: params(search) });
  }

  facets(search: LogSearch): Observable<LogFacets> {
    return this.http.get<LogFacets>(`${this.api}/log-events/facets/`, { params: params(search) });
  }

  timeline(search: LogSearch): Observable<LogTimeline> {
    return this.http.get<LogTimeline>(`${this.api}/log-events/timeline/`, { params: params(search) });
  }

  /** The matching events as a CSV file (at most 50,000). */
  exportCsv(search: LogSearch): Observable<Blob> {
    return this.http.get(`${this.api}/log-events/export/`, { params: params(search), responseType: 'blob' });
  }

  detections(
    organization: string,
    status: 'open' | 'resolved',
    page = 1,
    filters: DetectionFilters = {},
  ): Observable<Paginated<LogDetection>> {
    return this.http.get<Paginated<LogDetection>>(`${this.api}/log-detections/`, {
      params: params({ organization, status, page, ...filters }),
    });
  }

  errorGroups(
    organization: string,
    status: ErrorGroup['status'],
    options: { q?: string; sort?: 'recent' | 'count' | 'new'; page?: number; release?: string; source?: string } = {},
  ): Observable<Paginated<ErrorGroup>> {
    return this.http.get<Paginated<ErrorGroup>>(`${this.api}/error-groups/`, {
      params: params({ organization, status, ...options }),
    });
  }

  setErrorStatus(id: string, status: ErrorGroup['status']): Observable<ErrorGroup> {
    return this.http.post<ErrorGroup>(`${this.api}/error-groups/${id}/set-status/`, { status });
  }

  resolve(id: string, reopen = false): Observable<LogDetection> {
    return this.http.post<LogDetection>(`${this.api}/log-detections/${id}/resolve/`, reopen ? { reopen: true } : {});
  }

  releases(organization: string): Observable<AppRelease[]> {
    return this.http.get<AppRelease[]>(`${this.api}/error-groups/releases/`, { params: { organization } });
  }

  alertRules(organization: string): Observable<LogAlertRule[]> {
    return this.http.get<LogAlertRule[]>(`${this.api}/log-alert-rules/`, { params: { organization } });
  }

  createAlertRule(rule: LogAlertRuleInput): Observable<LogAlertRule> {
    return this.http.post<LogAlertRule>(`${this.api}/log-alert-rules/`, rule);
  }

  updateAlertRule(id: string, changes: Partial<LogAlertRuleInput & { enabled: boolean }>): Observable<LogAlertRule> {
    return this.http.patch<LogAlertRule>(`${this.api}/log-alert-rules/${id}/`, changes);
  }

  deleteAlertRule(id: string): Observable<void> {
    return this.http.delete<void>(`${this.api}/log-alert-rules/${id}/`);
  }

  /** What a rule (not yet saved) would have matched in the last 24 hours. */
  previewAlertRule(rule: LogAlertRuleInput): Observable<{ matches_24h: number; examples: LogEventRow[] }> {
    return this.http.post<{ matches_24h: number; examples: LogEventRow[] }>(`${this.api}/log-alert-rules/preview/`, rule);
  }
}
