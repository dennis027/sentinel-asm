import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { NotificationChannel, NotificationRule, Paginated, Severity } from '../models/models';

export interface CreateNotificationRuleRequest {
  organization: string;
  channel: NotificationChannel;
  recipient_email?: string;
  webhook_url?: string;
  min_severity: Severity;
  is_active?: boolean;
  weekly_report?: boolean;
}

@Injectable({ providedIn: 'root' })
export class NotificationRuleService {
  private readonly http = inject(HttpClient);
  private readonly base = `${environment.apiBaseUrl}/notification-rules`;

  list(organizationId?: string): Observable<Paginated<NotificationRule>> {
    let params = new HttpParams();
    if (organizationId) {
      params = params.set('organization', organizationId);
    }
    return this.http.get<Paginated<NotificationRule>>(this.base + '/', { params });
  }

  create(request: CreateNotificationRuleRequest): Observable<NotificationRule> {
    return this.http.post<NotificationRule>(this.base + '/', request);
  }

  update(id: string, changes: Partial<NotificationRule>): Observable<NotificationRule> {
    return this.http.patch<NotificationRule>(`${this.base}/${id}/`, changes);
  }

  /** Emails the weekly report to this rule's address now. */
  sendReport(id: string): Observable<{ detail: string }> {
    return this.http.post<{ detail: string }>(`${this.base}/${id}/send-report/`, {});
  }

  /** Sends a test alert now; `delivered` says whether it got through. */
  test(id: string): Observable<{ delivered: boolean; detail: string }> {
    return this.http.post<{ delivered: boolean; detail: string }>(`${this.base}/${id}/test/`, {});
  }

  delete(id: string): Observable<void> {
    return this.http.delete<void>(`${this.base}/${id}/`);
  }
}