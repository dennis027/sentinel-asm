import { Component, OnInit, inject, input, output, signal } from '@angular/core';
import { DatePipe, DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { AppRelease, ErrorGroup, LogSource } from '../../../core/models/models';
import { LogService } from '../../../core/services/log.service';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { ToastService } from '../../../core/services/toast.service';
import { EmptyState } from '../../../shared/components/empty-state/empty-state';
import { Icon } from '../../../shared/components/icon/icon';
import { Pager } from '../../../shared/components/pager/pager';
import { every } from '../../../shared/live';

/**
 * The Errors tab: each distinct application error once, with its count,
 * stack trace and the release it appeared in; the recent releases above
 * it, each with the errors it introduced.
 */
@Component({
  selector: 'app-error-groups',
  imports: [DatePipe, DecimalPipe, FormsModule, Icon, EmptyState, Pager],
  templateUrl: './error-groups.html',
  styleUrl: './error-groups.scss',
})
export class ErrorGroups implements OnInit {
  private readonly logService = inject(LogService);
  private readonly orgContext = inject(OrganizationContextService);
  private readonly toasts = inject(ToastService);

  readonly canTriage = input(false);
  readonly sources = input<LogSource[]>([]);
  /** "Every occurrence": the page shows them in its search. */
  readonly occurrences = output<ErrorGroup>();
  /** An error's status changed, so the page's counts did too. */
  readonly changed = output<void>();

  readonly errorGroups = signal<ErrorGroup[]>([]);
  readonly errorCount = signal(0);
  readonly errorStatus = signal<ErrorGroup['status']>('unresolved');
  readonly errorSort = signal<'recent' | 'count' | 'new'>('recent');
  readonly errorPage = signal(1);
  readonly expandedError = signal<string | null>(null);
  readonly releases = signal<AppRelease[]>([]);
  // Only errors that first appeared in this release ("" for all).
  readonly releaseFilter = signal('');
  readonly sourceFilter = signal('');
  readonly text = signal('');
  private query = '';

  constructor() {
    // New errors and new counts appear without reloading.
    every(15_000, () => {
      if (this.errorPage() === 1 && this.expandedError() === null) this.loadErrors();
    });
  }

  ngOnInit(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) return;
    this.loadErrors();
    this.logService.releases(org.id).subscribe({
      next: (releases) => this.releases.set(releases),
      error: () => undefined,
    });
  }

  showErrors(status: ErrorGroup['status']): void {
    this.errorStatus.set(status);
    this.errorPage.set(1);
    this.loadErrors();
  }

  filterRelease(release: string): void {
    this.releaseFilter.set(this.releaseFilter() === release ? '' : release);
    this.errorPage.set(1);
    this.loadErrors();
  }

  filterSource(source: string): void {
    this.sourceFilter.set(source);
    this.errorPage.set(1);
    this.loadErrors();
  }

  search(): void {
    this.query = this.text().trim();
    this.errorPage.set(1);
    this.loadErrors();
  }

  sortErrors(sort: string): void {
    this.errorSort.set(sort as 'recent' | 'count' | 'new');
    this.errorPage.set(1);
    this.loadErrors();
  }

  onErrorPage(page: number): void {
    this.errorPage.set(page);
    this.loadErrors();
  }

  toggleError(id: string): void {
    this.expandedError.set(this.expandedError() === id ? null : id);
  }

  setErrorStatus(group: ErrorGroup, status: ErrorGroup['status']): void {
    this.logService.setErrorStatus(group.id, status).subscribe({
      next: () => {
        this.toasts.success(
          status === 'resolved'
            ? 'Marked as resolved. If it happens again, it reopens and you are told.'
            : status === 'ignored'
              ? 'Ignored: it keeps counting but stays out of the list.'
              : 'Back on the list.',
        );
        this.loadErrors();
        this.changed.emit();
      },
      error: () => this.toasts.error('Could not change it.'),
    });
  }

  private loadErrors(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) return;
    this.logService
      .errorGroups(org.id, this.errorStatus(), {
        sort: this.errorSort(),
        page: this.errorPage(),
        release: this.releaseFilter(),
        source: this.sourceFilter() || undefined,
        q: this.query || undefined,
      })
      .subscribe({
        next: (page) => {
          this.errorGroups.set(page.results);
          this.errorCount.set(page.count);
        },
        error: () => undefined,
      });
  }
}
