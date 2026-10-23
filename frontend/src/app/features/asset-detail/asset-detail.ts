import { Component, OnDestroy, computed, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { forkJoin, map } from 'rxjs';
import { CRITICALITIES, apiErrorMessage, criticalityLabel, findingTypeLabel, webStatus } from '../../core/labels';
import { Asset, Criticality, Finding, Member, ScanJob, Severity } from '../../core/models/models';
import { AssetService } from '../../core/services/asset-service';
import { FindingService } from '../../core/services/finding-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { ScanJobService } from '../../core/services/scan-job.service';
import { ScannerService } from '../../core/services/scanner-service';
import { ToastService } from '../../core/services/toast.service';
import { Icon } from '../../shared/components/icon/icon';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Everything known about one host on one page: its grade and open
 * issues, what runs on it (services, software, certificate), what it
 * looks like, its recent scans, and the business context people add
 * (how much it matters, labels). "Re-check this host" runs every
 * host-level scanner on it, which is how a fix gets confirmed.
 */
@Component({
  selector: 'app-asset-detail',
  imports: [DatePipe, FormsModule, RouterLink, Icon],
  templateUrl: './asset-detail.html',
  styleUrl: './asset-detail.scss',
})
export class AssetDetail implements OnDestroy {
  private readonly assetService = inject(AssetService);
  private readonly findingService = inject(FindingService);
  private readonly scanJobService = inject(ScanJobService);
  private readonly scannerService = inject(ScannerService);
  private readonly toasts = inject(ToastService);
  private readonly orgService = inject(OrganizationService);
  protected readonly orgContext = inject(OrganizationContextService);
  private readonly assetId = toSignal(inject(ActivatedRoute).paramMap.pipe(map((p) => p.get('id'))));

  protected readonly criticalities = CRITICALITIES;
  protected readonly criticalityLabel = criticalityLabel;
  protected readonly typeLabel = findingTypeLabel;
  protected readonly severities = SEVERITIES;

  readonly asset = signal<Asset | null>(null);
  readonly findings = signal<Finding[]>([]);
  readonly scans = signal<ScanJob[]>([]);
  readonly screenshotUrl = signal<string | null>(null);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly editCriticality = signal<Criticality>('normal');
  readonly editTags = signal('');
  readonly editOwner = signal<number | ''>('');
  readonly members = signal<Member[]>([]);
  protected readonly webStatus = webStatus;
  readonly isSaving = signal(false);
  readonly isRescanning = signal(false);
  // scanner name -> what people call it
  readonly scannerLabels = signal<Record<string, string>>({});
  readonly criticalityHint = computed(() => CRITICALITIES.find((c) => c.value === this.editCriticality())?.hint ?? '');

  readonly issues = computed(() =>
    this.findings().filter((f) => !['subdomain_discovered', 'dns_change', 'screenshot'].includes(f.finding_type)),
  );
  readonly openIssues = computed(() =>
    this.issues().filter((f) => f.status === 'open' && f.severity !== 'info'),
  );
  readonly bySeverity = computed(() => {
    const counts: Record<string, number> = {};
    for (const f of this.issues()) {
      if (f.status === 'open') counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    }
    return counts;
  });
  readonly ports = computed(() =>
    this.findings()
      .filter((f) => f.finding_type === 'open_port')
      .map((f) => ({ finding: f, port: f.raw_data['port'], service: f.raw_data['service'], product: f.raw_data['product'] })),
  );
  readonly certificate = computed(() => {
    const f = this.findings().find((x) => x.finding_type === 'expired_ssl');
    if (!f) return null;
    const notAfter = f.raw_data['not_after'];
    if (typeof notAfter !== 'string') return { finding: f, notAfter: null, days: null };
    const left = (new Date(notAfter).getTime() - Date.now()) / 86_400_000;
    // Whole days either way: "expired 12 days ago", not 13 because of the hours.
    return { finding: f, notAfter, days: left >= 0 ? Math.floor(left) : -Math.floor(-left) };
  });
  readonly dnsRecords = computed(() => this.findings().filter((f) => f.finding_type === 'dns_change'));
  readonly screenshot = computed(() => this.findings().find((f) => f.finding_type === 'screenshot') ?? null);

  constructor() {
    effect(() => {
      const id = this.assetId();
      untracked(() => {
        if (id) this.load(id);
      });
    });
  }

  ngOnDestroy(): void {
    this.releaseScreenshot();
  }

  save(): void {
    const asset = this.asset();
    if (!asset) return;
    const tags = this.editTags()
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);
    this.isSaving.set(true);
    const owner = this.editOwner() === '' ? null : Number(this.editOwner());
    this.assetService.update(asset.id, { criticality: this.editCriticality(), tags, owner }).subscribe({
      next: (updated) => {
        this.isSaving.set(false);
        this.setAsset(updated);
        this.toasts.success(`Saved. ${updated.value} is now ${criticalityLabel(updated.criticality).toLowerCase()} importance.`);
      },
      error: (err) => {
        this.isSaving.set(false);
        this.toasts.error(apiErrorMessage(err, 'Could not save.'));
      },
    });
  }

  /** Runs every host-level scanner on this host again, e.g. to confirm a fix. */
  rescan(): void {
    const asset = this.asset();
    if (!asset) return;
    this.isRescanning.set(true);
    this.scannerService.list().subscribe({
      next: (scanners) => {
        const hostScanners = scanners.filter((s) => s.applies_to === 'asset');
        // One run id for all of them: Scan history shows them as one re-check.
        const run = crypto.randomUUID();
        forkJoin(
          hostScanners.map((s) =>
            this.scanJobService.trigger({ scanner_name: s.name, asset_id: asset.id, force: true, run_id: run, reason: 'recheck' }),
          ),
        ).subscribe({
          next: () => {
            this.isRescanning.set(false);
            this.toasts.success(
              `Started ${hostScanners.length} checks on ${asset.value}. Results appear here as each one finishes.`,
            );
            this.loadScans(asset.id);
          },
          error: (err) => {
            this.isRescanning.set(false);
            this.toasts.error(apiErrorMessage(err, 'Could not start the checks.'));
          },
        });
      },
      error: () => {
        this.isRescanning.set(false);
        this.toasts.error('Could not start the checks.');
      },
    });
  }

  private load(id: string): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);
    this.releaseScreenshot();
    forkJoin({
      asset: this.assetService.get(id),
      findings: this.findingService.list({ asset: id, is_active: true, page_size: 200 }),
    }).subscribe({
      next: ({ asset, findings }) => {
        this.setAsset(asset);
        this.findings.set(findings.results);
        this.isLoading.set(false);
        this.loadScans(id);
        const shot = this.screenshot();
        if (shot) {
          this.findingService.screenshot(shot.id).subscribe({
            next: (blob) => this.screenshotUrl.set(URL.createObjectURL(blob)),
            error: () => undefined,
          });
        }
      },
      error: (err) => {
        this.errorMessage.set(
          err.status === 404 ? 'This host does not exist, or is not in one of your organizations.' : 'Could not load this host.',
        );
        this.isLoading.set(false);
      },
    });
  }

  private loadScans(id: string): void {
    if (!Object.keys(this.scannerLabels()).length) {
      this.scannerService.list().subscribe({
        next: (scanners) => this.scannerLabels.set(Object.fromEntries(scanners.map((s) => [s.name, s.label]))),
        error: () => undefined,
      });
    }
    this.scanJobService.list({ asset: id }).subscribe({
      next: (page) => this.scans.set(page.results.slice(0, 10)),
      error: () => undefined,
    });
  }

  private releaseScreenshot(): void {
    const url = this.screenshotUrl();
    if (url) URL.revokeObjectURL(url);
    this.screenshotUrl.set(null);
  }

  private setAsset(asset: Asset): void {
    this.asset.set(asset);
    this.editCriticality.set(asset.criticality);
    this.editTags.set(asset.tags.join(', '));
    this.editOwner.set(asset.owner ?? '');
    if (!this.members().length && this.orgContext.canTriageFindings()) {
      this.orgService.members(asset.organization).subscribe({ next: (m) => this.members.set(m), error: () => undefined });
    }
  }
}
