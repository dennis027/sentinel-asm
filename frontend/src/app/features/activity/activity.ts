import { Component, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { ActivityEvent } from '../../core/models/models';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { EmptyState } from '../../shared/components/empty-state/empty-state';
import { Icon, IconName } from '../../shared/components/icon/icon';
import { Pager } from '../../shared/components/pager/pager';

const VERB_ICONS: Record<string, IconName> = {
  org_created: 'plus',
  org_updated: 'users',
  domain_verified: 'shield-check',
  member_added: 'users',
  member_role_changed: 'users',
  member_removed: 'users',
  scan_started: 'play',
  finding_triaged: 'check',
  finding_assigned: 'clipboard',
  asset_added: 'assets',
  rule_created: 'bell',
  rule_deleted: 'bell',
  report_downloaded: 'download',
};

/** The organization's audit trail: who did what, and when. */
@Component({
  selector: 'app-activity',
  imports: [DatePipe, EmptyState, Icon, Pager],
  templateUrl: './activity.html',
  styleUrl: './activity.scss',
})
export class Activity {
  private readonly orgService = inject(OrganizationService);
  protected readonly orgContext = inject(OrganizationContextService);

  readonly events = signal<ActivityEvent[]>([]);
  readonly totalCount = signal(0);
  readonly page = signal(1);
  readonly isLoading = signal(true);

  constructor() {
    effect(() => {
      this.orgContext.selectedOrganization();
      untracked(() => {
        this.page.set(1);
        this.fetch();
      });
    });
  }

  iconFor(verb: string): IconName {
    return VERB_ICONS[verb] ?? 'activity';
  }

  onPageChange(page: number): void {
    this.page.set(page);
    this.fetch();
  }

  private fetch(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) return;
    this.isLoading.set(true);
    this.orgService.activity(org.id, this.page()).subscribe({
      next: (page) => {
        this.events.set(page.results);
        this.totalCount.set(page.count);
        this.isLoading.set(false);
      },
      error: () => this.isLoading.set(false),
    });
  }
}
