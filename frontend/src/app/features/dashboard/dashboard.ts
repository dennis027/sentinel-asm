import { Component, OnInit, computed, effect, inject, signal } from '@angular/core';
import { DatePipe, UpperCasePipe } from '@angular/common';
import { Finding, Organization, RiskSummary } from '../../core/models/models';
import { AssetService } from '../../core/services/asset-service';
import { FindingService } from '../../core/services/finding-service';
import { OrganizationService } from '../../core/services/organization-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
@Component({
  selector: 'app-dashboard',
  imports: [DatePipe, UpperCasePipe],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.scss',
})
export class Dashboard implements OnInit {
  private readonly orgService = inject(OrganizationService);
  private readonly findingService = inject(FindingService);
  private readonly assetService = inject(AssetService);
  protected readonly orgContext = inject(OrganizationContextService);


  readonly riskSummary = signal<RiskSummary | null>(null);
  readonly recentFindings = signal<Finding[]>([]);
  readonly assetCount = signal<number>(0);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly activeFindingsTotal = computed(() => {
    const bySeverity = this.riskSummary()?.active_findings_by_severity;
    if (!bySeverity) return 0;
    return Object.values(bySeverity).reduce((sum, count) => sum + count, 0);
  });


  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      if (org) {
        this.loadOrgData(org.id);
      }
    });
  }

  ngOnInit(): void {
    
  }

  private loadOrgData(orgId: string): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);

    this.orgService.riskSummary(orgId).subscribe({
      next: (summary) => this.riskSummary.set(summary),
      error: () => this.errorMessage.set('Could not load risk summary.'),
    });

    this.assetService.list({ organization: orgId }).subscribe({
      next: (page) => this.assetCount.set(page.count),
    });

    this.findingService.list({ is_active: true }).subscribe({
      next: (page) => {
        this.recentFindings.set(page.results.slice(0, 5));
        this.isLoading.set(false);
      },
      error: () => {
        this.errorMessage.set('Could not load findings.');
        this.isLoading.set(false);
      },
    });
  }
}
