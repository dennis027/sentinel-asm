import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { Asset, AssetType, Criticality, Paginated } from '../models/models';

export interface AssetFilters {
  organization?: string;
  asset_type?: AssetType;
  is_active?: boolean;
  criticality?: Criticality;
  tag?: string;
  search?: string;
  page?: number;
  page_size?: number;
}

@Injectable({ providedIn: 'root' })
export class AssetService {
  private readonly http = inject(HttpClient);
  private readonly base = `${environment.apiBaseUrl}/assets`;

  list(filters: AssetFilters = {}): Observable<Paginated<Asset>> {
    let params = new HttpParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== null && value !== '') {
        params = params.set(key, String(value));
      }
    }
    return this.http.get<Paginated<Asset>>(this.base + '/', { params });
  }

  /** Adds a host under the organization's domain that discovery hasn't found. */
  create(organization: string, value: string): Observable<Asset> {
    return this.http.post<Asset>(this.base + '/', { organization, value });
  }

  get(id: string): Observable<Asset> {
    return this.http.get<Asset>(`${this.base}/${id}/`);
  }

  /** Business context: how much the host matters, and labels. */
  update(id: string, change: { criticality?: Criticality; tags?: string[] }): Observable<Asset> {
    return this.http.patch<Asset>(`${this.base}/${id}/`, change);
  }

  /** Adds many hosts; each one that can't be added comes back with the reason. */
  bulkCreate(
    organization: string,
    values: string[],
  ): Observable<{ added: string[]; skipped: { value: string; reason: string }[] }> {
    return this.http.post<{ added: string[]; skipped: { value: string; reason: string }[] }>(
      `${this.base}/bulk/`,
      { organization, values },
    );
  }
}