import { Component, effect, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ScanJob, ScanJobStatus } from '../../core/models/models';
import { ScanJobService } from '../../core/services/scan-job.service';
import { OrganizationContextService } from '../../core/services/organization-context-service';

@Component({
  selector: 'app-scan-history',
  imports: [FormsModule, DatePipe],
  templateUrl: './scan-history.html',
  styleUrl: './scan-history.scss',
})
export class ScanHistory {
  private readonly scanJobService = inject(ScanJobService);
  protected readonly orgContext = inject(OrganizationContextService);

  readonly jobs = signal<ScanJob[]>([]);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);
  readonly statusFilter = signal<ScanJobStatus | ''>('');
  // job.id currently being re-run, so only that row shows a spinner
  readonly rerunningJobId = signal<string | null>(null);

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      if (org) {
        this.fetchJobs(org.id);
      }
    });
  }

  onStatusChange(value: string): void {
    this.statusFilter.set(value as ScanJobStatus | '');
    const org = this.orgContext.selectedOrganization();
    if (org) this.fetchJobs(org.id);
  }

  rerun(job: ScanJob): void {
    this.rerunningJobId.set(job.id);
    this.scanJobService.rerun(job).subscribe({
      next: (newJob) => {
        this.rerunningJobId.set(null);
        this.jobs.update((jobs) => [newJob, ...jobs]);
        this.pollJob(newJob.id);
      },
      error: () => {
        this.rerunningJobId.set(null);
        this.errorMessage.set(`Could not re-run ${job.scanner_name}.`);
      },
    });
  }

  private pollJob(jobId: string): void {
    this.scanJobService.pollUntilComplete(jobId).subscribe({
      next: (updated) => {
        this.jobs.update((jobs) => jobs.map((j) => (j.id === updated.id ? updated : j)));
      },
    });
  }

  private fetchJobs(orgId: string): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);

    this.scanJobService
      .list({ organization: orgId, status: this.statusFilter() || undefined })
      .subscribe({
        next: (page) => {
          this.jobs.set(page.results);
          this.isLoading.set(false);
        },
        error: () => {
          this.errorMessage.set('Could not load scan history.');
          this.isLoading.set(false);
        },
      });
  }
}