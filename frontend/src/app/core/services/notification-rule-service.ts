import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { NotificationRule, Paginated, Severity } from '../models/models';

export interface CreateNotificationRuleRequest {
  organization: string;
  recipient_email: string;
  min_severity: Severity;
  is_active?: boolean;
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

  delete(id: string): Observable<void> {
    return this.http.delete<void>(`${this.base}/${id}/`);
  }
}