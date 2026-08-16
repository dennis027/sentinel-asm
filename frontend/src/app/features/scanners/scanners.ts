import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Asset, Organization, ScanJob, ScannerInfo } from '../../core/models/models';
import { AssetService } from '../../core/services/asset-service';
import { OrganizationService } from '../../core/services/organization-service';
import { ScanJobService } from '../../core/services/scan-job.service';
import { ScannerService } from '../../core/services/scanner-service';
@Component({
  selector: 'app-scanners',
  imports: [FormsModule],
  templateUrl: './scanners.html',
  styleUrl: './scanners.scss',
})
export class Scanners implements OnInit {
  private readonly scannerService = inject(ScannerService);
  private readonly assetService = inject(AssetService);
  private readonly orgService = inject(OrganizationService);
  private readonly scanJobService = inject(ScanJobService);

  readonly scanners = signal<ScannerInfo[]>([]);
  readonly assets = signal<Asset[]>([]);
  readonly organization = signal<Organization | null>(null);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly pickingAssetFor = signal<string | null>(null);
  readonly activeJobs = signal<Record<string, ScanJob>>({});

  ngOnInit(): void {
    this.orgService.list().subscribe({
      next: (page) => {
        const org = page.results[0] ?? null;
        this.organization.set(org);
        if (org) {
          this.assetService.list({ organization: org.id }).subscribe({
            next: (assetPage) => this.assets.set(assetPage.results),
          });
        }
      },
    });

    this.scannerService.list().subscribe({
      next: (scanners) => {
        this.scanners.set(scanners);
        this.isLoading.set(false);
      },
      error: () => {
        this.errorMessage.set('Could not load scanners.');
        this.isLoading.set(false);
      },
    });
  }

  runScan(scanner: ScannerInfo): void {
    if (scanner.applies_to === 'organization') {
      const org = this.organization();
      if (!org) return;
      this.triggerScan(scanner.name, { scanner_name: scanner.name, organization_id: org.id });
      return;
    }
    this.pickingAssetFor.set(scanner.name);
  }

  confirmAssetPick(scannerName: string, assetId: string): void {
    if (!assetId) return;
    this.triggerScan(scannerName, { scanner_name: scannerName, asset_id: assetId });
    this.pickingAssetFor.set(null);
  }

  cancelAssetPick(): void {
    this.pickingAssetFor.set(null);
  }

  private triggerScan(scannerName: string, request: { scanner_name: string; asset_id?: string; organization_id?: string }): void {
    this.scanJobService.trigger(request).subscribe({
      next: (job) => {
        this.setActiveJob(scannerName, job);
        this.scanJobService.pollUntilComplete(job.id).subscribe({
          next: (updated) => this.setActiveJob(scannerName, updated),
        });
      },
      error: () => {
        this.errorMessage.set(`Could not start ${scannerName} scan.`);
      },
    });
  }

  private setActiveJob(scannerName: string, job: ScanJob): void {
    this.activeJobs.update((jobs) => ({ ...jobs, [scannerName]: job }));
  }
}