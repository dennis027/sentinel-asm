import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { Organization, Paginated, RiskSummary } from '../models/models';

@Injectable({ providedIn: 'root' })
export class OrganizationService {
  private readonly http = inject(HttpClient);
  private readonly base = `${environment.apiBaseUrl}/organizations`;

  list(): Observable<Paginated<Organization>> {
    return this.http.get<Paginated<Organization>>(this.base + '/');
  }

  riskSummary(id: string): Observable<RiskSummary> {
    return this.http.get<RiskSummary>(`${this.base}/${id}/risk-summary/`);
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
}