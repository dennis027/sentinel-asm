import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { findingTypeLabel } from '../../core/labels';
import { Finding } from '../../core/models/models';
import { FindingService } from '../../core/services/finding-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { EmptyState } from '../../shared/components/empty-state/empty-state';
import { Icon } from '../../shared/components/icon/icon';

const DAY = 86_400_000;
// Plenty for one person's open work; the findings page lists any more.
const LIMIT = 200;

interface Bucket {
  id: string;
  title: string;
  hint: string;
  findings: Finding[];
}

/**
 * The signed-in person's open issues in the selected organization,
 * grouped by when they are due: what to do today, this week, later.
 */
@Component({
  selector: 'app-my-work',
  imports: [DatePipe, RouterLink, Icon, EmptyState],
  templateUrl: './my-work.html',
  styleUrl: './my-work.scss',
})
export class MyWork {
  private readonly findingService = inject(FindingService);
  protected readonly orgContext = inject(OrganizationContextService);
  protected readonly typeLabel = findingTypeLabel;

  readonly findings = signal<Finding[]>([]);
  readonly total = signal(0);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly buckets = computed<Bucket[]>(() => {
    const now = Date.now();
    const buckets: Bucket[] = [
      { id: 'overdue', title: 'Overdue', hint: 'Past the fix-by date', findings: [] },
      { id: 'week', title: 'Due this week', hint: 'Within 7 days', findings: [] },
      { id: 'later', title: 'Due later', hint: '', findings: [] },
      { id: 'none', title: 'No deadline', hint: 'Info-level findings', findings: [] },
    ];
    for (const finding of this.findings()) {
      const due = finding.due_at ? new Date(finding.due_at).getTime() : null;
      const bucket =
        due === null ? buckets[3] : finding.overdue ? buckets[0] : due - now <= 7 * DAY ? buckets[1] : buckets[2];
      bucket.findings.push(finding);
    }
    for (const bucket of buckets) {
      bucket.findings.sort((a, b) => (a.due_at ?? '9').localeCompare(b.due_at ?? '9'));
    }
    return buckets.filter((b) => b.findings.length);
  });

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      untracked(() => {
        if (!org) return;
        this.isLoading.set(true);
        this.errorMessage.set(null);
        this.findingService
          .list({
            organization: org.id,
            assignee: 'me',
            is_active: true,
            triaged: false,
            kind: 'issue',
            page_size: LIMIT,
          })
          .subscribe({
            next: (page) => {
              this.findings.set(page.results);
              this.total.set(page.count);
              this.isLoading.set(false);
            },
            error: () => {
              this.errorMessage.set('Could not load your work.');
              this.isLoading.set(false);
            },
          });
      });
    });
  }

  daysLeft(finding: Finding): string {
    if (!finding.due_at) return '';
    const days = Math.round((new Date(finding.due_at).getTime() - Date.now()) / DAY);
    if (days < 0) return `${-days} day${days === -1 ? '' : 's'} late`;
    if (days === 0) return 'due today';
    return `${days} day${days === 1 ? '' : 's'} left`;
  }
}
