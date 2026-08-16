import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { ScannerInfo } from '../models/models';

@Injectable({ providedIn: 'root' })
export class ScannerService {
  private readonly http = inject(HttpClient);

  /** Not paginated -- returns the full plugin registry as a plain array. */
  list(): Observable<ScannerInfo[]> {
    return this.http.get<ScannerInfo[]>(`${environment.apiBaseUrl}/scanners/`);
  }
}