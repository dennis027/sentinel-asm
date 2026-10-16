import { LogoMark } from '../../shared/components/logo-mark/logo-mark';
import { Component, OnDestroy, computed, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe, DecimalPipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { Changes, FixPlan, RiskSummary, TrendPoint } from '../../core/models/models';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { GradeCalendar } from '../../shared/components/grade-calendar/grade-calendar';
import { Icon } from '../../shared/components/icon/icon';
import { TrendChart } from '../../shared/components/trend-chart/trend-chart';

const REFRESH_MS = 60_000;
const RING = 2 * Math.PI * 88;

/**
 * The security picture for a meeting-room or wall screen: the grade,
 * what it means, the trend, the next three fixes and what changed this
 * week, in type big enough to read across a room. Refreshes itself
 * every minute; no sidebar, no buttons to press.
 */
@Component({
  selector: 'app-board',
  imports: [LogoMark, DatePipe, DecimalPipe, RouterLink, Icon, TrendChart, GradeCalendar],
  templateUrl: './board.html',
  styleUrl: './board.scss',
})
export class Board implements OnDestroy {
  private readonly orgService = inject(OrganizationService);
  protected readonly orgContext = inject(OrganizationContextService);
  private refreshHandle: ReturnType<typeof setInterval> | undefined;
  private clockHandle: ReturnType<typeof setInterval> | undefined;

  readonly summary = signal<RiskSummary | null>(null);
  readonly trend = signal<TrendPoint[]>([]);
  readonly plan = signal<FixPlan | null>(null);
  readonly changes = signal<Changes | null>(null);
  readonly updatedAt = signal<Date | null>(null);
  readonly now = signal(new Date());
  readonly isFullscreen = signal(false);

  protected readonly ringLength = RING;
  readonly ringOffset = computed(() => RING * (1 - (this.summary()?.average_risk_score ?? 0) / 100));
  readonly urgent = computed(() => {
    const counts = this.summary()?.active_findings_by_severity;
    return (counts?.critical ?? 0) + (counts?.high ?? 0);
  });
  readonly nextFixes = computed(() => this.plan()?.steps.slice(0, 3) ?? []);
  readonly gradeClass = computed(() => 'grade-' + (this.summary()?.average_risk_grade ?? 'none').replace('+', 'plus'));

  constructor() {
    if (!this.orgContext.isLoaded()) this.orgContext.loadOrganizations();
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      untracked(() => {
        clearInterval(this.refreshHandle);
        if (!org) return;
        this.load(org.id);
        this.refreshHandle = setInterval(() => this.load(org.id), REFRESH_MS);
      });
    });
    this.clockHandle = setInterval(() => this.now.set(new Date()), 15_000);
  }

  ngOnDestroy(): void {
    clearInterval(this.refreshHandle);
    clearInterval(this.clockHandle);
    if (document.fullscreenElement) document.exitFullscreen().catch(() => undefined);
  }

  toggleFullscreen(): void {
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => undefined);
      this.isFullscreen.set(false);
    } else {
      document.documentElement.requestFullscreen?.().then(
        () => this.isFullscreen.set(true),
        () => undefined,
      );
    }
  }

  private load(orgId: string): void {
    this.orgService.riskSummary(orgId).subscribe({
      next: (summary) => {
        this.summary.set(summary);
        this.updatedAt.set(new Date());
      },
      error: () => undefined,
    });
    this.orgService.trend(orgId, 90).subscribe({ next: (t) => this.trend.set(t.points), error: () => undefined });
    this.orgService.fixPlan(orgId).subscribe({ next: (p) => this.plan.set(p), error: () => undefined });
    this.orgService.changes(orgId).subscribe({ next: (c) => this.changes.set(c), error: () => undefined });
  }
}
