import { PluralPipe } from '../../shared/pipes/plural';
import { Component, OnDestroy, computed, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { FINDING_STATUS_LABELS, FRAMEWORK_SHORT_NAMES, findingTypeLabel } from '../../core/labels';
import { Finding, FindingStatus, Member, Severity } from '../../core/models/models';
import { BulkAction, FindingService } from '../../core/services/finding-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { ToastService } from '../../core/services/toast.service';
import { ticketText } from '../../core/ticket';
import { Pager } from '../../shared/components/pager/pager';
import { Icon } from '../../shared/components/icon/icon';
import { EmptyArt, EmptyState } from '../../shared/components/empty-state/empty-state';

// open: still detected, nobody has ruled on it
// triaged: still detected, but accepted or marked a false positive
// resolved: no longer detected by the scanner
type FindingView = 'open' | 'triaged' | 'resolved';
// Which findings to list: real problems (the default), the inventory the
// scanners record along the way, or both.
type FindingKind = 'issue' | 'inventory' | '';
// Remediation views: everything, mine, nobody's, past the fix-by date,
// fixed once and found again, or on the hosts that matter most.
type Workflow = '' | 'mine' | 'unassigned' | 'overdue' | 'regressed' | 'crown' | 'kev';

const SEARCH_DEBOUNCE_MS = 300;

const EMPTY_STATES: Record<FindingView, { art: EmptyArt; title: string; message: string }> = {
  open: {
    art: 'shield',
    title: 'No open findings',
    message: 'No security issues are open. Run a scan from the Scanners page to check again.',
  },
  triaged: {
    art: 'radar',
    title: 'Nothing triaged yet',
    message: 'Findings you mark as an accepted risk or a false positive are kept here.',
  },
  resolved: {
    art: 'radar',
    title: 'Nothing resolved yet',
    message: 'A finding moves here when a scan stops detecting it.',
  },
};

@Component({
  selector: 'app-findings',
  imports: [PluralPipe, FormsModule, Pager, DatePipe, Icon, EmptyState, RouterLink],
  templateUrl: './findings.html',
  styleUrl: './findings.scss',
})
export class Findings implements OnDestroy {
  private readonly findingService = inject(FindingService);
  private readonly orgService = inject(OrganizationService);
  private readonly toasts = inject(ToastService);
  private readonly router = inject(Router);
  private readonly queryParams = toSignal(inject(ActivatedRoute).queryParamMap);
  protected readonly orgContext = inject(OrganizationContextService);
  private searchDebounceHandle: ReturnType<typeof setTimeout> | undefined;

  protected readonly typeLabel = findingTypeLabel;
  protected readonly statusLabels = FINDING_STATUS_LABELS;
  protected readonly frameworkNames = FRAMEWORK_SHORT_NAMES;

  readonly findings = signal<Finding[]>([]);
  readonly totalCount = signal(0);
  readonly page = signal(1);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly severityFilter = signal<Severity | ''>('');
  readonly searchTerm = signal('');
  readonly kind = signal<FindingKind>('issue');
  readonly view = signal<FindingView>('open');
  readonly workflow = signal<Workflow>('');

  // People a finding can be assigned to.
  readonly members = signal<Member[]>([]);

  // Set when arriving from the compliance page (?control=owasp:A05&controlName=...).
  readonly controlFilter = computed(() => {
    const id = this.queryParams()?.get('control');
    return id ? { id, name: this.queryParams()?.get('controlName') ?? id } : null;
  });

  // Set when arriving from a heatmap cell (?type=open_port&severity=high).
  readonly typeFilter = computed(() => this.queryParams()?.get('type') ?? null);

  // Set when arriving from an asset's "findings" link (?asset=<id>&assetName=<host>).
  readonly assetFilter = computed(() => {
    const id = this.queryParams()?.get('asset');
    return id ? { id, name: this.queryParams()?.get('assetName') ?? 'one asset' } : null;
  });

  readonly isFiltered = computed(
    () =>
      !!this.severityFilter() ||
      !!this.searchTerm() ||
      !!this.assetFilter() ||
      !!this.controlFilter() ||
      !!this.typeFilter() ||
      !!this.workflow(),
  );
  readonly emptyState = computed(() =>
    this.isFiltered()
      ? {
          art: 'search' as EmptyArt,
          title: 'No findings match',
          message: 'Try a different search or severity.',
        }
      : EMPTY_STATES[this.view()],
  );

  // The one finding whose details are open, and the note typed for it.
  readonly expandedId = signal<string | null>(null);
  readonly triageNote = signal('');

  // finding id -> object URL of its screenshot, filled in as each loads
  readonly screenshotUrls = signal<Record<string, string>>({});
  // finding id currently being triaged, so only that row's buttons disable
  readonly triagingId = signal<string | null>(null);
  // Optional end date for an acceptance typed under the open finding.
  readonly acceptUntil = signal('');
  readonly minAcceptDate = new Date(Date.now() + 86_400_000).toISOString().slice(0, 10);

  // Findings ticked for a bulk action (this page only).
  readonly selected = signal<ReadonlySet<string>>(new Set());
  readonly isBulkWorking = signal(false);
  readonly canBulkEdit = computed(() => this.orgContext.canTriageFindings() && this.view() !== 'resolved');
  readonly allSelected = computed(
    () => this.findings().length > 0 && this.findings().every((f) => this.selected().has(f.id)),
  );

  constructor() {
    effect(() => {
      // Only the selected organization and the asset link should
      // retrigger this -- the other filters call fetchFindings()
      // themselves, and reading them inside a tracked effect would
      // fetch twice on every change.
      const org = this.orgContext.selectedOrganization();
      this.assetFilter();
      this.controlFilter();
      this.typeFilter();
      const params = this.queryParams();
      untracked(() => {
        const severity = params?.get('severity');
        if (severity) this.severityFilter.set(severity as Severity);
        // Links from the dashboard open a remediation view directly.
        if (params?.get('overdue')) this.workflow.set('overdue');
        else if (params?.get('regressed')) this.workflow.set('regressed');
        else if (params?.get('kev')) this.workflow.set('kev');
        else if (params?.get('assignee') === 'me') this.workflow.set('mine');
        else if (params?.get('assignee') === 'none') this.workflow.set('unassigned');
        this.page.set(1);
        this.fetchFindings();
        this.members.set([]);
        if (org && this.orgContext.canTriageFindings()) {
          this.orgService.members(org.id).subscribe({
            next: (members) => this.members.set(members),
            error: () => undefined,
          });
        }
      });
    });
  }

  onWorkflowChange(value: string): void {
    this.workflow.set(value as Workflow);
    this.page.set(1);
    this.fetchFindings();
  }

  toggleSelected(id: string): void {
    const next = new Set(this.selected());
    if (next.has(id)) next.delete(id);
    else next.add(id);
    this.selected.set(next);
  }

  clearSelection(): void {
    this.selected.set(new Set());
  }

  toggleAll(): void {
    this.selected.set(this.allSelected() ? new Set() : new Set(this.findings().map((f) => f.id)));
  }

  bulkAssign(value: string): void {
    if (value === '') return;
    const assignee = value === 'none' ? null : Number(value);
    this.runBulk({ action: 'assign', assignee }, (n) =>
      assignee === null
        ? `${n} finding(s) now have nobody assigned.`
        : `Assigned ${n} finding(s) to ${this.members().find((m) => m.user_id === assignee)?.username ?? 'them'}.`,
    );
  }

  bulkTriage(status: FindingStatus): void {
    this.runBulk({ action: 'triage', status }, (n) =>
      status === 'open' ? `Reopened ${n} finding(s).` : `Marked ${n} finding(s) as ${this.statusLabels[status].toLowerCase()}.`,
    );
  }

  private runBulk(change: BulkAction, message: (updated: number) => string): void {
    const ids = [...this.selected()];
    if (!ids.length) return;
    this.isBulkWorking.set(true);
    this.findingService.bulk(ids, change).subscribe({
      next: (body) => {
        this.isBulkWorking.set(false);
        this.toasts.success(message(body.updated));
        this.fetchFindings();
      },
      error: () => {
        this.isBulkWorking.set(false);
        this.toasts.error('Could not update those findings.');
      },
    });
  }

  clearTypeFilter(): void {
    this.severityFilter.set('');
    this.router.navigate([], { queryParams: { type: null, severity: null }, queryParamsHandling: 'merge' });
  }

  clearControlFilter(): void {
    this.router.navigate([], { queryParams: { control: null, controlName: null }, queryParamsHandling: 'merge' });
  }

  assign(finding: Finding, value: string): void {
    const assignee = value ? Number(value) : null;
    this.findingService.assign(finding.id, assignee).subscribe({
      next: (updated) => {
        this.findings.update((findings) => findings.map((f) => (f.id === updated.id ? updated : f)));
        this.toasts.success(
          updated.assignee_username
            ? `${updated.assignee_username} is now responsible for fixing this.`
            : 'Nobody is assigned to this any more.',
        );
      },
      error: () => this.toasts.error('Could not change who this is assigned to.'),
    });
  }

  copyAsTicket(finding: Finding): void {
    navigator.clipboard
      ?.writeText(ticketText(finding))
      .then(() => this.toasts.success('Copied as a ticket. Paste it into Jira, GitHub or an email.'))
      .catch(() => this.toasts.error('Could not copy to the clipboard.'));
  }

  ngOnDestroy(): void {
    clearTimeout(this.searchDebounceHandle);
    this.releaseScreenshots();
  }

  onSeverityChange(value: string): void {
    this.severityFilter.set(value as Severity | '');
    this.page.set(1);
    this.fetchFindings();
  }

  onKindChange(value: string): void {
    this.kind.set(value as FindingKind);
    this.page.set(1);
    this.fetchFindings();
  }

  onSearchChange(value: string): void {
    this.searchTerm.set(value);
    clearTimeout(this.searchDebounceHandle);
    this.searchDebounceHandle = setTimeout(() => {
      this.page.set(1);
      this.fetchFindings();
    }, SEARCH_DEBOUNCE_MS);
  }

  onViewChange(view: FindingView): void {
    this.view.set(view);
    this.page.set(1);
    this.fetchFindings();
  }

  onPageChange(page: number): void {
    this.page.set(page);
    this.fetchFindings();
  }

  clearAssetFilter(): void {
    this.router.navigate([], { queryParams: {} });
  }

  toggleDetails(finding: Finding): void {
    const opening = this.expandedId() !== finding.id;
    this.expandedId.set(opening ? finding.id : null);
    this.triageNote.set(opening ? finding.status_note : '');
    this.acceptUntil.set('');
  }

  /** raw_data as label/value rows, skipping fields shown elsewhere. */
  rawDetails(finding: Finding): { key: string; value: string }[] {
    return Object.entries(finding.raw_data ?? {})
      .filter(([key, value]) => key !== 'screenshot_path' && value !== '' && value !== null)
      .filter(([, value]) => !Array.isArray(value) || value.length > 0)
      .map(([key, value]) => ({
        key: key.replace(/_/g, ' '),
        value: Array.isArray(value)
          ? value.join(', ')
          : typeof value === 'object'
            ? JSON.stringify(value)
            : String(value),
      }));
  }

  triage(finding: Finding, status: FindingStatus): void {
    // A note only travels with the finding it was typed under.
    const note = this.expandedId() === finding.id ? this.triageNote().trim() : '';
    const until = status === 'accepted' && this.expandedId() === finding.id ? this.acceptUntil() || null : null;

    this.triagingId.set(finding.id);
    this.findingService.triage(finding.id, status, note, until).subscribe({
      next: () => {
        this.triagingId.set(null);
        this.expandedId.set(null);
        this.toasts.success(
          status === 'open'
            ? 'Finding reopened. It counts toward the risk score again.'
            : `Marked as ${this.statusLabels[status].toLowerCase()}${until ? ' until ' + until : ''}. Find it under Triaged.`,
        );
        // The finding has moved to a different view; reload this one.
        this.fetchFindings();
      },
      error: () => {
        this.triagingId.set(null);
        this.toasts.error('Could not update the finding.');
      },
    });
  }

  downloadExport(format: 'csv' | 'json' | 'pdf'): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) return;

    this.orgService.export(org.id, format).subscribe({
      next: (blob) => {
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${org.root_domain}-findings.${format}`;
        link.click();
        URL.revokeObjectURL(url);
      },
      error: () => this.toasts.error('The export failed. Try again.'),
    });
  }

  private fetchFindings(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) {
      // Organizations haven't loaded yet (or the user has none) -- the
      // effect above runs this again once one is selected.
      this.findings.set([]);
      this.totalCount.set(0);
      this.isLoading.set(!this.orgContext.isLoaded());
      return;
    }

    this.isLoading.set(true);
    this.errorMessage.set(null);

    const view = this.view();
    this.findingService
      .list({
        organization: org.id,
        asset: this.assetFilter()?.id,
        severity: this.severityFilter() || undefined,
        kind: this.kind() || undefined,
        search: this.searchTerm().trim() || undefined,
        control: this.controlFilter()?.id,
        finding_type: this.typeFilter() ?? undefined,
        assignee: { mine: 'me', unassigned: 'none' }[this.workflow() as 'mine' | 'unassigned'],
        overdue: this.workflow() === 'overdue' ? true : undefined,
        regressed: this.workflow() === 'regressed' ? true : undefined,
        asset_criticality: this.workflow() === 'crown' ? 'crown_jewel' : undefined,
        known_exploited: this.workflow() === 'kev' ? true : undefined,
        is_active: view !== 'resolved',
        triaged: view === 'resolved' ? undefined : view === 'triaged',
        page: this.page(),
      })
      .subscribe({
        next: (page) => {
          this.findings.set(page.results);
          this.totalCount.set(page.count);
          this.isLoading.set(false);
          this.selected.set(new Set());
          this.loadScreenshots(page.results);
        },
        error: () => {
          this.errorMessage.set('Could not load findings. Check your connection and reload.');
          this.isLoading.set(false);
        },
      });
  }

  private loadScreenshots(findings: Finding[]): void {
    this.releaseScreenshots();
    for (const finding of findings) {
      if (finding.finding_type !== 'screenshot') continue;
      this.findingService.screenshot(finding.id).subscribe({
        next: (blob) => {
          // A newer page may have loaded while this was in flight.
          if (!this.findings().some((f) => f.id === finding.id)) return;
          this.screenshotUrls.update((urls) => ({
            ...urls,
            [finding.id]: URL.createObjectURL(blob),
          }));
        },
        // A missing image just means no thumbnail -- the finding still lists.
        error: () => undefined,
      });
    }
  }

  private releaseScreenshots(): void {
    for (const url of Object.values(this.screenshotUrls())) {
      URL.revokeObjectURL(url);
    }
    this.screenshotUrls.set({});
  }
}
