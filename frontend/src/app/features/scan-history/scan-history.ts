import { Component, OnDestroy, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ScanJob, ScanJobStatus } from '../../core/models/models';
import { ScanJobService } from '../../core/services/scan-job.service';
import { ScannerService } from '../../core/services/scanner-service';
import { ToastService } from '../../core/services/toast.service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { Pager } from '../../shared/components/pager/pager';
import { EmptyState } from '../../shared/components/empty-state/empty-state';

// How often the list re-checks itself while a scan is still in progress.
const REFRESH_MS = 5000;

@Component({
  selector: 'app-scan-history',
  imports: [FormsModule, DatePipe, Pager, RouterLink, EmptyState],
  templateUrl: './scan-history.html',
  styleUrl: './scan-history.scss',
})
export class ScanHistory implements OnDestroy {
  private readonly scanJobService = inject(ScanJobService);
  private readonly toasts = inject(ToastService);
  private refreshHandle: ReturnType<typeof setTimeout> | undefined;

  // scanner name -> human label ("ssl_expiry" -> "TLS certificate")
  readonly scannerLabels = signal<Record<string, string>>({});
  protected readonly orgContext = inject(OrganizationContextService);

  readonly jobs = signal<ScanJob[]>([]);
  readonly totalCount = signal(0);
  readonly page = signal(1);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);
  readonly statusFilter = signal<ScanJobStatus | ''>('');
  // job.id currently being re-run, so only that row shows a spinner
  readonly rerunningJobId = signal<string | null>(null);

  constructor() {
    inject(ScannerService)
      .list()
      .subscribe({
        next: (scanners) =>
          this.scannerLabels.set(Object.fromEntries(scanners.map((s) => [s.name, s.label]))),
        // Labels are a nicety; the raw scanner name is shown without them.
        error: () => undefined,
      });

    effect(() => {
      const org = this.orgContext.selectedOrganization();
      if (org) {
        untracked(() => {
          this.page.set(1);
          this.fetchJobs(org.id);
        });
      }
    });
  }

  ngOnDestroy(): void {
    clearTimeout(this.refreshHandle);
  }

  labelFor(job: ScanJob): string {
    return this.scannerLabels()[job.scanner_name] ?? job.scanner_name;
  }

  onStatusChange(value: string): void {
    this.statusFilter.set(value as ScanJobStatus | '');
    this.page.set(1);
    const org = this.orgContext.selectedOrganization();
    if (org) this.fetchJobs(org.id);
  }

  onPageChange(page: number): void {
    this.page.set(page);
    const org = this.orgContext.selectedOrganization();
    if (org) this.fetchJobs(org.id);
  }

  rerun(job: ScanJob): void {
    this.rerunningJobId.set(job.id);
    this.scanJobService.rerun(job).subscribe({
      next: () => {
        this.rerunningJobId.set(null);
        this.toasts.success(`${this.labelFor(job)} started again.`);
        this.page.set(1);
        this.fetchJobs(job.organization, { quiet: true });
      },
      error: (err) => {
        this.rerunningJobId.set(null);
        this.toasts.error(err.error?.detail ?? `Could not re-run ${this.labelFor(job)}.`);
      },
    });
  }

  /**
   * While anything on this page is still pending or running, quietly
   * reload it every few seconds so statuses change without a manual
   * refresh. Stops by itself once everything shown has finished.
   */
  private scheduleRefresh(): void {
    clearTimeout(this.refreshHandle);
    const unfinished = this.jobs().some((j) => j.status !== 'success' && j.status !== 'failed');
    if (!unfinished) return;

    this.refreshHandle = setTimeout(() => {
      const org = this.orgContext.selectedOrganization();
      if (org) this.fetchJobs(org.id, { quiet: true });
    }, REFRESH_MS);
  }

  private fetchJobs(orgId: string, { quiet = false } = {}): void {
    // A background refresh must not flash the table away.
    if (!quiet) {
      this.isLoading.set(true);
      this.errorMessage.set(null);
    }

    this.scanJobService
      .list({ organization: orgId, status: this.statusFilter() || undefined, page: this.page() })
      .subscribe({
        next: (page) => {
          this.jobs.set(page.results);
          this.totalCount.set(page.count);
          this.isLoading.set(false);
          this.scheduleRefresh();
        },
        error: () => {
          if (quiet) return;
          this.errorMessage.set('Could not load scan history. Check your connection and reload.');
          this.isLoading.set(false);
        },
      });
  }
}