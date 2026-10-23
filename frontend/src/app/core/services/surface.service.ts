import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { SavedView, SurfacePolicy } from '../models/models';

export type PolicyInput = Pick<SurfacePolicy, 'name' | 'kind' | 'value' | 'severity' | 'guidance' | 'enabled'>;
export type SavedViewInput = Pick<SavedView, 'page' | 'name' | 'filters' | 'shared'>;

/**
 * The organization's own settings for its attack surface: policies
 * (rules a host must not break) and saved views (named filters on the
 * Findings and Assets pages).
 */
@Injectable({ providedIn: 'root' })
export class SurfaceService {
  private readonly http = inject(HttpClient);
  private readonly policies = `${environment.apiBaseUrl}/surface-policies`;
  private readonly views = `${environment.apiBaseUrl}/saved-views`;

  listPolicies(organization: string): Observable<SurfacePolicy[]> {
    return this.http.get<SurfacePolicy[]>(this.policies + '/', { params: { organization } });
  }

  /** Admin or higher; every host is checked against it straight away. */
  createPolicy(organization: string, policy: PolicyInput): Observable<SurfacePolicy> {
    return this.http.post<SurfacePolicy>(this.policies + '/', { organization, ...policy });
  }

  updatePolicy(id: string, change: Partial<PolicyInput>): Observable<SurfacePolicy> {
    return this.http.patch<SurfacePolicy>(`${this.policies}/${id}/`, change);
  }

  deletePolicy(id: string): Observable<void> {
    return this.http.delete<void>(`${this.policies}/${id}/`);
  }

  listViews(organization: string, page: SavedView['page']): Observable<SavedView[]> {
    return this.http.get<SavedView[]>(this.views + '/', { params: { organization, page } });
  }

  createView(organization: string, view: SavedViewInput): Observable<SavedView> {
    return this.http.post<SavedView>(this.views + '/', { organization, ...view });
  }

  deleteView(id: string): Observable<void> {
    return this.http.delete<void>(`${this.views}/${id}/`);
  }
}
