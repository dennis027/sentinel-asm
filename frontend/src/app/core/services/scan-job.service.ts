import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import {
  DomainScanStarted,
  Paginated,
  ScanJob,
  ScanProgress,
  TriggerScanRequest,
} from '../models/models';

/**
 * Pattern used by every other resource service (AssetService,
 * FindingService, NotificationRuleService, ...) -- same shape, swap
 * the model type and endpoint path.
 */
@Injectable({ providedIn: 'root' })
export class ScanJobService {
  private readonly http = inject(HttpClient);
  private readonly base = `${environment.apiBaseUrl}/scan-jobs`;

  list(
    filters: { organization?: string; asset?: string; status?: string; page?: number } = {},
  ): Observable<Paginated<ScanJob>> {
    let params = new HttpParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value) params = params.set(key, String(value));
    }
    return this.http.get<Paginated<ScanJob>>(this.base + '/', { params });
  }

  get(id: string): Observable<ScanJob> {
    return this.http.get<ScanJob>(`${this.base}/${id}/`);
  }

  /** Runs a scanner on ONE asset. */
  trigger(request: TriggerScanRequest): Observable<ScanJob> {
    return this.http.post<ScanJob>(`${this.base}/trigger/`, request);
  }

  /**
   * Runs a scanner for the whole domain: once for an organization-level
   * scanner, once per asset for the others. Returns straight away;
   * follow it with progress().
   */
  runForOrganization(scannerName: string, organizationId: string): Observable<DomainScanStarted> {
    return this.http.post<DomainScanStarted>(`${this.base}/trigger/`, {
      scanner_name: scannerName,
      organization_id: organizationId,
    });
  }

  /** Each scanner's most recent domain-wide run for this organization. */
  progress(organizationId: string): Observable<ScanProgress[]> {
    return this.http.get<ScanProgress[]>(`${this.base}/progress/`, {
      params: { organization: organizationId },
    });
  }

  /**
   * Polls a scan job every `intervalMs` until it reaches a terminal
   * status (success/failed) -- scans run async on Celery, so the
   * trigger response comes back immediately as "pending"/"running".
   * Caller subscribes and takes updates until they see a terminal
   * status, then unsubscribes (or use `take(1)` after a filter, per
   * caller's preference).
   */
  pollUntilComplete(id: string, intervalMs = 3000): Observable<ScanJob> {
    return new Observable<ScanJob>((subscriber) => {
      const poll = () => {
        this.get(id).subscribe({
          next: (job) => {
            subscriber.next(job);
            if (job.status === 'success' || job.status === 'failed') {
              subscriber.complete();
            } else {
              timeoutId = setTimeout(poll, intervalMs);
            }
          },
          error: (err) => subscriber.error(err),
        });
      };
      let timeoutId = setTimeout(poll, 0);
      return () => clearTimeout(timeoutId);
    });
  }


  /**
   * Re-runs a past scan. An asset scan is repeated on that asset
   * (force: true, so it really runs even if it already did today); an
   * organization-level one is started again for the organization.
   */
  rerun(job: ScanJob): Observable<ScanJob | DomainScanStarted> {
    if (!job.asset) {
      return this.runForOrganization(job.scanner_name, job.organization);
    }
    return this.trigger({ scanner_name: job.scanner_name, asset_id: job.asset, force: true });
  }
}
