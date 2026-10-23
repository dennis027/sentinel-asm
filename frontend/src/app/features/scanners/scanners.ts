import { HttpErrorResponse } from '@angular/common/http';
import { Component, OnDestroy, computed, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe, DecimalPipe } from '@angular/common';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { ScanProgress, ScannerInfo } from '../../core/models/models';
import { AssetService } from '../../core/services/asset-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { ScanJobService } from '../../core/services/scan-job.service';
import { ScannerService } from '../../core/services/scanner-service';
import { ToastService } from '../../core/services/toast.service';
import { Icon, scannerIcon } from '../../shared/components/icon/icon';
import { PreflightDialog } from '../../shared/components/preflight-dialog/preflight-dialog';
import { SCANNER_CATEGORIES } from '../../core/labels';
import { firstValueFrom } from 'rxjs';

// How often progress is re-read while a run is under way.
const PROGRESS_REFRESH_MS = 4000;

/**
 * Every scanner here runs against the whole domain: one click starts
 * it for the organization (subdomain discovery) or for every asset in
 * it (everything else). There is no per-asset choice on this page.
 */
@Component({
  selector: 'app-scanners',
  imports: [RouterLink, Icon, DecimalPipe, DatePipe, PreflightDialog],
  templateUrl: './scanners.html',
  styleUrl: './scanners.scss',
})
export class Scanners implements OnDestroy {
  private readonly scannerService = inject(ScannerService);
  private readonly assetService = inject(AssetService);
  private readonly scanJobService = inject(ScanJobService);
  private readonly orgService = inject(OrganizationService);
  private readonly toasts = inject(ToastService);
  private readonly router = inject(Router);
  protected readonly orgContext = inject(OrganizationContextService);
  private refreshHandle: ReturnType<typeof setTimeout> | undefined;

  protected readonly scannerIcon = scannerIcon;

  readonly scanners = signal<ScannerInfo[]>([]);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  // How many assets the organization has -- what an asset-level
  // scanner is about to be run on.
  readonly assetCount = signal<number | null>(null);
  // scanner name -> its latest run for this organization
  readonly progress = signal<Record<string, ScanProgress>>({});
  // scanner name whose start request is in flight
  readonly startingScanner = signal<string | null>(null);

  // Scanners grouped for display: discovery first, then by what they look at.
  readonly groups = computed(() =>
    SCANNER_CATEGORIES.map((category) => ({
      ...category,
      scanners: this.scanners().filter((scanner) => (scanner.category ?? 'web') === category.id),
    })).filter((group) => group.scanners.length),
  );

  readonly isRunningAll = signal(false);

  readonly canRun = computed(
    () =>
      this.orgContext.canTriggerScans() &&
      (this.orgContext.selectedOrganization()?.scans_allowed ?? false),
  );

  // The check before a scan: which scanners it is for, and how to answer.
  readonly preflightFor = signal<string[] | null>(null);
  private answerPreflight: ((go: boolean) => void) | null = null;

  readonly isVerifying = signal(false);
  readonly verifyMessage = signal<string | null>(null);

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      untracked(() => {
        clearTimeout(this.refreshHandle);
        this.progress.set({});
        this.assetCount.set(null);
        if (!org) return;

        this.loadProgress(org.id);
        this.assetService.list({ organization: org.id, is_active: true, page_size: 1 }).subscribe({
          next: (page) => this.assetCount.set(page.count),
        });
      });
    });

    // The dashboard's "Run a scan" lands here with ?run=all.
    const runAllOnLoad = inject(ActivatedRoute).snapshot.queryParamMap.get('run') === 'all';

    this.scannerService.list().subscribe({
      next: (scanners) => {
        // Discovery first: it is what produces the assets the others run on.
        this.scanners.set(
          [...scanners].sort(
            (a, b) =>
              Number(b.applies_to === 'organization') - Number(a.applies_to === 'organization') ||
              a.label.localeCompare(b.label),
          ),
        );
        this.isLoading.set(false);
        if (runAllOnLoad) {
          this.router.navigate([], { queryParams: { run: null }, replaceUrl: true });
          this.runAll();
        }
      },
      error: () => {
        this.errorMessage.set('Could not load scanners.');
        this.isLoading.set(false);
      },
    });
  }

  ngOnDestroy(): void {
    clearTimeout(this.refreshHandle);
  }

  verifyDomain(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) return;

    this.isVerifying.set(true);
    this.verifyMessage.set(null);
    this.orgService.verifyDomain(org.id).subscribe({
      next: (updated) => {
        this.isVerifying.set(false);
        this.orgContext.updateOrganization(updated);
        this.toasts.success(`${updated.root_domain} is verified. You can start scanning.`);
      },
      error: (err: HttpErrorResponse) => {
        this.isVerifying.set(false);
        this.verifyMessage.set(err.error?.detail ?? 'Could not verify the domain.');
      },
    });
  }

  /** What one click on this scanner will cover, in words. */
  scopeText(scanner: ScannerInfo): string {
    const org = this.orgContext.selectedOrganization();
    if (scanner.applies_to === 'organization') {
      return `Runs once on ${org?.root_domain ?? 'the domain'}`;
    }
    const count = this.assetCount();
    if (count === null) return 'Runs on every asset';
    return `Runs on all ${count.toLocaleString()} asset${count === 1 ? '' : 's'}`;
  }

  /** Starts every scanner that isn't already running, after one confirmation. */
  async runAll(): Promise<void> {
    const org = this.orgContext.selectedOrganization();
    if (!org || this.isRunningAll()) return;

    const toStart = this.scanners().filter((scanner) => !this.isRunning(scanner));
    if (!toStart.length) return;
    if (!(await this.checkFirst(toStart.map((s) => s.name)))) return;

    this.isRunningAll.set(true);
    let started = 0;
    for (const scanner of toStart) {
      try {
        await firstValueFrom(this.scanJobService.runForOrganization(scanner.name, org.id));
        started++;
      } catch {
        // Already running, or refused: carry on with the others.
      }
    }
    this.isRunningAll.set(false);
    this.toasts.success(`${started} of ${toStart.length} scanners started. Progress shows on each card.`);
    this.loadProgress(org.id);
  }

  /** Shows the check before a scan; resolves true to go ahead. */
  private checkFirst(names: string[]): Promise<boolean> {
    return new Promise((resolve) => {
      this.answerPreflight = resolve;
      this.preflightFor.set(names);
    });
  }

  onPreflight(go: boolean): void {
    this.preflightFor.set(null);
    this.answerPreflight?.(go);
    this.answerPreflight = null;
  }

  isRunning(scanner: ScannerInfo): boolean {
    const run = this.progress()[scanner.name];
    return !!run && !run.finished;
  }

  /** Share of a run that has finished (succeeded, failed or skipped), 0-100. */
  percentDone(run: ScanProgress): number {
    return run.total ? ((run.success + run.failed + run.skipped) / run.total) * 100 : 0;
  }

  async runScan(scanner: ScannerInfo): Promise<void> {
    const org = this.orgContext.selectedOrganization();
    if (!org || this.startingScanner()) return;

    // One click can mean tens of thousands of scans: check what it will
    // cover (and what will stop it) first.
    if (scanner.applies_to === 'asset' && !(await this.checkFirst([scanner.name]))) return;

    this.startingScanner.set(scanner.name);
    this.errorMessage.set(null);
    this.scanJobService.runForOrganization(scanner.name, org.id).subscribe({
      next: (started) => {
        this.startingScanner.set(null);
        this.toasts.success(
          started.target_count > 1
            ? `${scanner.label} started on ${started.target_count.toLocaleString()} assets.`
            : `${scanner.label} started.`,
        );
        // Show it as running straight away; the server fills in real
        // numbers on the next refresh.
        this.progress.update((progress) => ({
          ...progress,
          [scanner.name]: {
            scanner_name: scanner.name,
            batch_id: started.batch_id,
            started_at: new Date().toISOString(),
            total: started.target_count,
            pending: started.target_count,
            running: 0,
            success: 0,
            failed: 0,
            skipped: 0,
            finished: false,
          },
        }));
        this.scheduleRefresh(org.id);
      },
      error: (err: HttpErrorResponse) => {
        this.startingScanner.set(null);
        // 403 and 409 carry the reason (role, unverified domain, already running).
        this.errorMessage.set(err.error?.detail ?? `Could not start ${scanner.label}.`);
        this.loadProgress(org.id);
      },
    });
  }

  private loadProgress(orgId: string): void {
    this.scanJobService.progress(orgId).subscribe({
      next: (runs) => {
        if (this.orgContext.selectedOrganization()?.id !== orgId) return;
        const fromServer = Object.fromEntries(runs.map((run) => [run.scanner_name, run]));
        // Keep a just-started run the server hasn't written a job for yet.
        const waiting = Object.fromEntries(
          Object.entries(this.progress()).filter(
            ([name, run]) => !run.finished && fromServer[name]?.batch_id !== run.batch_id,
          ),
        );
        this.progress.set({ ...fromServer, ...waiting });
        this.scheduleRefresh(orgId);
      },
      // Progress is a nicety; the page still works without it.
      error: () => undefined,
    });
  }

  /** Keeps refreshing for as long as anything is still running. */
  private scheduleRefresh(orgId: string): void {
    clearTimeout(this.refreshHandle);
    if (!Object.values(this.progress()).some((run) => !run.finished)) return;
    this.refreshHandle = setTimeout(() => this.loadProgress(orgId), PROGRESS_REFRESH_MS);
  }
}
