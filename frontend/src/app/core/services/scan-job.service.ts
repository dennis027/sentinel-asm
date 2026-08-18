import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { Paginated, ScanJob, TriggerScanRequest } from '../models/models';

/**
 * Pattern used by every other resource service (AssetService,
 * FindingService, NotificationRuleService, ...) -- same shape, swap
 * the model type and endpoint path.
 */
@Injectable({ providedIn: 'root' })
export class ScanJobService {
  private readonly http = inject(HttpClient);
  private readonly base = `${environment.apiBaseUrl}/scan-jobs`;

  list(filters: { organization?: string; asset?: string; status?: string } = {}): Observable<Paginated<ScanJob>> {
    let params = new HttpParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value) params = params.set(key, value);
    }
    return this.http.get<Paginated<ScanJob>>(this.base + '/', { params });
  }

  get(id: string): Observable<ScanJob> {
    return this.http.get<ScanJob>(`${this.base}/${id}/`);
  }

  trigger(request: TriggerScanRequest): Observable<ScanJob> {
    return this.http.post<ScanJob>(`${this.base}/trigger/`, request);
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


    /** Re-runs a past scan job with the exact same target, bypassing
   * same-day idempotency (force: true) so it genuinely re-executes
   * even if it already ran today. */
  rerun(job: ScanJob): Observable<ScanJob> {
    return this.trigger({
      scanner_name: job.scanner_name,
      asset_id: job.asset ?? undefined,
      organization_id: job.asset ? undefined : job.organization,
      force: true,
    });
  }

  
}