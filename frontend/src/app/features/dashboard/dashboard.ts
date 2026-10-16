import { PluralPipe } from '../../shared/pipes/plural';
import { Component, computed, effect, inject, signal } from '@angular/core';
import { DatePipe, DecimalPipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { Changes, Finding, Heatmap, RiskSummary, TrendPoint } from '../../core/models/models';
import { TrendChart } from '../../shared/components/trend-chart/trend-chart';
import { GradeCalendar } from '../../shared/components/grade-calendar/grade-calendar';
import { RiskHeatmap } from '../../shared/components/risk-heatmap/risk-heatmap';
import { ToastService } from '../../core/services/toast.service';
import { AssetService } from '../../core/services/asset-service';
import { FindingService } from '../../core/services/finding-service';
import { OrganizationService } from '../../core/services/organization-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { Icon } from '../../shared/components/icon/icon';
@Component({
  selector: 'app-dashboard',
  imports: [PluralPipe, DatePipe, DecimalPipe, RouterLink, Icon, TrendChart, GradeCalendar, RiskHeatmap],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.scss',
})
export class Dashboard {
  private readonly orgService = inject(OrganizationService);
  private readonly findingService = inject(FindingService);
  private readonly assetService = inject(AssetService);
  protected readonly orgContext = inject(OrganizationContextService);


  private readonly toasts = inject(ToastService);

  readonly riskSummary = signal<RiskSummary | null>(null);
  readonly changes = signal<Changes | null>(null);
  readonly trend = signal<TrendPoint[]>([]);
  readonly heatmap = signal<Heatmap | null>(null);
  readonly isBuildingReport = signal(false);
  readonly recentFindings = signal<Finding[]>([]);
  readonly assetCount = signal<number>(0);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly activeFindingsTotal = computed(() => {
    const bySeverity = this.riskSummary()?.active_findings_by_severity;
    if (!bySeverity) return 0;
    return Object.values(bySeverity).reduce((sum, count) => sum + count, 0);
  });


  // The setup steps a new organization still has ahead of it. Empty
  // once the domain is verified and discovery has found something.
  readonly nextSteps = computed(() => {
    const org = this.orgContext.selectedOrganization();
    if (!org) return [];
    const steps: { text: string; link: string; action: string }[] = [];
    if (org.verification_required && !org.domain_verified) {
      steps.push({
        text: `Prove you control ${org.root_domain} so it can be scanned.`,
        link: '/organization',
        action: 'Verify domain',
      });
    }
    // 1 = just the root domain that every organization starts with.
    if (this.assetCount() <= 1) {
      steps.push({
        text: 'Run Subdomain discovery to find the hosts under your domain.',
        link: '/scanners',
        action: 'Go to Scanners',
      });
    }
    return steps;
  });

  // One row per severity for the breakdown: its count and its bar
  // length relative to the largest count, so the longest bar fills the
  // track.
  readonly severityRows = computed(() => {
    const counts = this.riskSummary()?.active_findings_by_severity;
    const order = ['critical', 'high', 'medium', 'low', 'info'] as const;
    const max = Math.max(1, ...order.map((s) => counts?.[s] ?? 0));
    return order.map((severity) => {
      const count = counts?.[severity] ?? 0;
      return { severity, count, width: (count / max) * 100 };
    });
  });

  downloadReport(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org || this.isBuildingReport()) return;

    this.isBuildingReport.set(true);
    this.orgService.report(org.id).subscribe({
      next: (blob) => {
        this.isBuildingReport.set(false);
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${org.root_domain}-report.pdf`;
        link.click();
        URL.revokeObjectURL(url);
      },
      error: () => {
        this.isBuildingReport.set(false);
        this.toasts.error('Could not build the report. Try again.');
      },
    });
  }

  // Change in score across the trend, for the panel's headline.
  readonly trendDelta = computed(() => {
    const scored = this.trend().filter((point) => point.score !== null);
    if (scored.length < 2) return null;
    return {
      delta: Math.round(((scored[scored.length - 1].score ?? 0) - (scored[0].score ?? 0)) * 10) / 10,
      days: scored.length - 1,
    };
  });

  readonly cleanAssets = computed(() => Math.max(0, this.assetCount() - (this.riskSummary()?.assets_at_risk ?? 0)));

  readonly urgentCount = computed(() => {
    const counts = this.riskSummary()?.active_findings_by_severity;
    return (counts?.critical ?? 0) + (counts?.high ?? 0);
  });

  readonly gradeMeaning = computed(() => {
    const grade = this.riskSummary()?.average_risk_grade;
    if (!grade) return 'Not scored yet';
    // A perfect grade on an organization that hasn't been scanned yet
    // says nothing about its exposure.
    if (this.nextSteps().length > 0) return 'Not enough scanned yet';
    if (grade.startsWith('A')) return 'Little exposure found';
    if (grade === 'B') return 'Some issues to review';
    if (grade === 'C') return 'Needs attention';
    return 'Serious exposure';
  });

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      if (org) {
        this.loadOrgData(org.id);
      }
    });
  }

  private loadOrgData(orgId: string): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);

    this.changes.set(null);
    this.trend.set([]);
    this.orgService.trend(orgId, 90).subscribe({
      next: (trend) => this.trend.set(trend.points),
      error: () => undefined,
    });
    this.heatmap.set(null);
    this.orgService.heatmap(orgId).subscribe({
      next: (heatmap) => this.heatmap.set(heatmap),
      error: () => undefined,
    });
    this.orgService.changes(orgId).subscribe({
      next: (changes) => this.changes.set(changes),
      // The dashboard is still useful without this panel.
      error: () => undefined,
    });

    this.orgService.riskSummary(orgId).subscribe({
      next: (summary) => this.riskSummary.set(summary),
      error: () => this.errorMessage.set('Could not load risk summary.'),
    });

    this.assetService.list({ organization: orgId }).subscribe({
      next: (page) => this.assetCount.set(page.count),
    });

    this.findingService
      .list({ organization: orgId, is_active: true, triaged: false, kind: 'issue' })
      .subscribe({
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
