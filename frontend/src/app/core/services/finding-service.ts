import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { Finding, Paginated, Severity } from '../models/models';

export interface FindingFilters {
  asset?: string;
  finding_type?: string;
  severity?: Severity;
  is_active?: boolean;
  search?: string;
}

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
}