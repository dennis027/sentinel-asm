import { Component, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe, DecimalPipe, NgTemplateOutlet } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ScanJob, ScanJobStatus, ScanRun, ScanTrigger } from '../../core/models/models';
import { ScanJobService } from '../../core/services/scan-job.service';
import { ScannerService } from '../../core/services/scanner-service';
import { ToastService } from '../../core/services/toast.service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { Icon, IconName } from '../../shared/components/icon/icon';
import { Pager } from '../../shared/components/pager/pager';
import { EmptyState } from '../../shared/components/empty-state/empty-state';
import { every } from '../../shared/live';

// How often the page re-checks itself while a scan is still in progress.
const REFRESH_MS = 5000;

export const ORIGINS: { value: ScanTrigger | ''; label: string }[] = [
  { value: '', label: 'Everything' },
  { value: 'schedule', label: 'Daily schedule' },
  { value: 'domain', label: 'Run scan' },
  { value: 'recheck', label: 'Re-checks' },
  { value: 'single', label: 'Single scans' },
];

const ORIGIN_ICONS: Record<ScanTrigger, IconName> = {
  schedule: 'calendar',
  domain: 'play',
  recheck: 'repeat',
  single: 'scanners',
};

/**
 * Scan history, grouped by where each scan came from: the nightly
 * schedule, someone's "Run scan" across the domain, a host re-check, a
 * single scan. Each run shows how far it got and what it found, and
 * opens to its scans. "Every scan" shows the plain list instead.
 */
@Component({
  selector: 'app-scan-history',
  imports: [FormsModule, DatePipe, DecimalPipe, NgTemplateOutlet, Pager, RouterLink, EmptyState, Icon],
  templateUrl: './scan-history.html',
  styleUrl: './scan-history.scss',
})
export class ScanHistory {
  private readonly scanJobService = inject(ScanJobService);
  private readonly toasts = inject(ToastService);
  protected readonly orgContext = inject(OrganizationContextService);
  protected readonly origins = ORIGINS;

  // scanner name -> human label ("ssl_expiry" -> "TLS certificate")
  readonly scannerLabels = signal<Record<string, string>>({});

  readonly view = signal<'runs' | 'jobs'>('runs');
  readonly origin = signal<ScanTrigger | ''>('');
  readonly runStatus = signal<'running' | 'failed' | ''>('');
  readonly statusFilter = signal<ScanJobStatus | ''>('');
  readonly page = signal(1);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  // Grouped view
  readonly runs = signal<ScanRun[]>([]);
  readonly runCount = signal(0);
  readonly openRun = signal<string | null>(null);
  readonly runJobs = signal<ScanJob[]>([]);
  readonly runJobCount = signal(0);
  readonly runJobPage = signal(1);

  // Plain list
  readonly jobs = signal<ScanJob[]>([]);
  readonly totalCount = signal(0);

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
          this.openRun.set(null);
          this.load();
        });
      }
    });

    // While anything shown is still running, statuses update by themselves.
    every(REFRESH_MS, () => {
      const busy =
        this.view() === 'runs'
          ? this.runs().some((r) => r.unfinished > 0)
          : this.jobs().some((j) => j.status !== 'success' && j.status !== 'failed');
      if (busy) this.load({ quiet: true });
    });
  }

  // ---------------- view and filters ----------------

  setView(view: 'runs' | 'jobs'): void {
    this.view.set(view);
    this.page.set(1);
    this.load();
  }

  setOrigin(origin: ScanTrigger | ''): void {
    this.origin.set(origin);
    this.page.set(1);
    this.openRun.set(null);
    this.load();
  }

  onRunStatusChange(value: string): void {
    this.runStatus.set(value as 'running' | 'failed' | '');
    this.page.set(1);
    this.load();
  }

  onStatusChange(value: string): void {
    this.statusFilter.set(value as ScanJobStatus | '');
    this.page.set(1);
    this.load();
  }

  onPageChange(page: number): void {
    this.page.set(page);
    this.openRun.set(null);
    this.load();
  }

  // ---------------- runs ----------------

  iconFor(run: ScanRun): IconName {
    return ORIGIN_ICONS[run.trigger];
  }

  /** What a run was, in a few words. */
  titleFor(run: ScanRun): string {
    const org = this.orgContext.selectedOrganization();
    const where = run.host ?? (run.hosts > 1 ? `${run.hosts.toLocaleString()} hosts` : org?.root_domain ?? 'the domain');
    switch (run.trigger) {
      case 'schedule':
        return 'Daily scan of everything';
      case 'recheck':
        return `Re-check of ${run.host ?? where}`;
      default:
        return `${run.scanner_label ?? `${run.scanners} scanners`} on ${where}`;
    }
  }

  /** Who or what started it. */
  originFor(run: ScanRun): string {
    if (run.trigger === 'schedule') return 'Started automatically by the daily schedule';
    const who = run.triggered_by ?? 'someone on the team';
    return run.trigger === 'domain' ? `Run scan by ${who}` : `Started by ${who}`;
  }

  /** "12 scanners on 46 hosts and the domain" */
  coverage(run: ScanRun): string {
    const parts = [`${run.scanners} ${run.scanners === 1 ? 'scanner' : 'scanners'}`];
    if (run.hosts) parts.push(`on ${run.hosts.toLocaleString()} ${run.hosts === 1 ? 'host' : 'hosts'}`);
    if (run.organization_level) parts.push(run.hosts ? 'and the domain' : 'on the domain');
    return parts.join(' ');
  }

  duration(run: ScanRun): string {
    if (!run.finished) return '';
    const minutes = Math.round((new Date(run.finished).getTime() - new Date(run.started).getTime()) / 60000);
    if (minutes < 1) return 'took under a minute';
    if (minutes < 90) return `took ${minutes} min`;
    return `took ${Math.round(minutes / 6) / 10} h`;
  }

  percent(run: ScanRun, part: number): number {
    return run.jobs ? (part / run.jobs) * 100 : 0;
  }

  toggleRun(run: ScanRun): void {
    if (this.openRun() === run.run_id) {
      this.openRun.set(null);
      return;
    }
    this.openRun.set(run.run_id);
    this.runJobPage.set(1);
    this.loadRunJobs();
  }

  onRunJobPage(page: number): void {
    this.runJobPage.set(page);
    this.loadRunJobs();
  }

  // ---------------- scans ----------------

  labelFor(job: ScanJob): string {
    return this.scannerLabels()[job.scanner_name] ?? job.scanner_name;
  }

  rerun(job: ScanJob): void {
    this.rerunningJobId.set(job.id);
    this.scanJobService.rerun(job).subscribe({
      next: () => {
        this.rerunningJobId.set(null);
        this.toasts.success(`${this.labelFor(job)} started again.`);
        this.page.set(1);
        this.load({ quiet: true });
      },
      error: (err) => {
        this.rerunningJobId.set(null);
        this.toasts.error(err.error?.detail ?? `Could not re-run ${this.labelFor(job)}.`);
      },
    });
  }

  // ---------------- loading ----------------

  private load({ quiet = false } = {}): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) return;
    // A background refresh must not flash the page away.
    if (!quiet) {
      this.isLoading.set(true);
      this.errorMessage.set(null);
    }
    const failed = () => {
      if (quiet) return;
      this.errorMessage.set('Could not load scan history. Check your connection and reload.');
      this.isLoading.set(false);
    };

    if (this.view() === 'runs') {
      this.scanJobService
        .runs(org.id, { trigger: this.origin(), status: this.runStatus(), page: this.page() })
        .subscribe({
          next: (page) => {
            this.runs.set(page.results);
            this.runCount.set(page.count);
            this.isLoading.set(false);
            if (quiet && this.openRun()) this.loadRunJobs();
          },
          error: failed,
        });
      return;
    }
    this.scanJobService
      .list({
        organization: org.id,
        status: this.statusFilter() || undefined,
        trigger: this.origin() || undefined,
        page: this.page(),
      })
      .subscribe({
        next: (page) => {
          this.jobs.set(page.results);
          this.totalCount.set(page.count);
          this.isLoading.set(false);
        },
        error: failed,
      });
  }

  private loadRunJobs(): void {
    const org = this.orgContext.selectedOrganization();
    const run = this.openRun();
    if (!org || !run) return;
    this.scanJobService.list({ organization: org.id, run_id: run, page: this.runJobPage() }).subscribe({
      next: (page) => {
        this.runJobs.set(page.results);
        this.runJobCount.set(page.count);
      },
      error: () => this.toasts.error('Could not load the scans in this run.'),
    });
  }
}
