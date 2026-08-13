import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { Asset, AssetType, Paginated } from '../models/models';

export interface AssetFilters {
  organization?: string;
  asset_type?: AssetType;
  is_active?: boolean;
  search?: string;
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

  get(id: string): Observable<Asset> {
    return this.http.get<Asset>(`${this.base}/${id}/`);
  }
}