import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { map } from 'rxjs';
import { FINDING_STATUS_LABELS, FRAMEWORK_SHORT_NAMES, criticalityLabel, findingTypeLabel } from '../../core/labels';
import { Finding, FindingStatus, Member, TimelineEntry } from '../../core/models/models';
import { FindingService } from '../../core/services/finding-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { ToastService } from '../../core/services/toast.service';
import { ticketText } from '../../core/ticket';
import { Icon, IconName } from '../../shared/components/icon/icon';

const TIMELINE_ICONS: Record<string, IconName> = {
  detected: 'search',
  comment: 'message',
  seen: 'check',
  resolved: 'shield-check',
  finding_assigned: 'users',
  finding_triaged: 'clipboard',
  finding_reopened: 'repeat',
  acceptance_expired: 'calendar',
};

/**
 * One finding on a page of its own: what it is, why it matters and what
 * to do; who owns it and by when; and its whole story -- detection,
 * decisions, discussion, and whether it came back after a fix. The page
 * a ticket or a chat message links to.
 */
@Component({
  selector: 'app-finding-detail',
  imports: [DatePipe, FormsModule, RouterLink, Icon],
  templateUrl: './finding-detail.html',
  styleUrl: './finding-detail.scss',
})
export class FindingDetail {
  private readonly findingService = inject(FindingService);
  private readonly orgService = inject(OrganizationService);
  private readonly toasts = inject(ToastService);
  protected readonly orgContext = inject(OrganizationContextService);
  private readonly findingId = toSignal(inject(ActivatedRoute).paramMap.pipe(map((p) => p.get('id'))));

  protected readonly typeLabel = findingTypeLabel;
  protected readonly statusLabels = FINDING_STATUS_LABELS;
  protected readonly frameworkNames = FRAMEWORK_SHORT_NAMES;
  protected readonly criticalityLabel = criticalityLabel;

  readonly finding = signal<Finding | null>(null);
  readonly timeline = signal<TimelineEntry[]>([]);
  readonly members = signal<Member[]>([]);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly note = signal('');
  readonly acceptUntil = signal('');
  readonly isTriaging = signal(false);
  readonly comment = signal('');
  readonly isPosting = signal(false);

  // ATT&CK first: it says what an attacker would do with this.
  readonly attack = computed(() => this.finding()?.controls.filter((c) => c.framework === 'attack') ?? []);
  readonly otherControls = computed(() => this.finding()?.controls.filter((c) => c.framework !== 'attack') ?? []);
  readonly details = computed(() => {
    const raw = this.finding()?.raw_data ?? {};
    return Object.entries(raw)
      .filter(([key, value]) => key !== 'screenshot_path' && value !== '' && value !== null)
      .filter(([, value]) => !Array.isArray(value) || value.length > 0)
      .map(([key, value]) => ({
        key: key.replace(/_/g, ' '),
        value: Array.isArray(value) ? value.join(', ') : typeof value === 'object' ? JSON.stringify(value) : String(value),
      }));
  });
  // Tomorrow, the earliest date an acceptance can end.
  readonly minDate = new Date(Date.now() + 86_400_000).toISOString().slice(0, 10);

  constructor() {
    effect(() => {
      const id = this.findingId();
      const org = this.orgContext.selectedOrganization();
      untracked(() => {
        if (!id) return;
        this.load(id);
        if (org && this.orgContext.canTriageFindings()) {
          this.orgService.members(org.id).subscribe({ next: (m) => this.members.set(m), error: () => undefined });
        }
      });
    });
  }

  timelineIcon(kind: string): IconName {
    return TIMELINE_ICONS[kind] ?? 'activity';
  }

  triage(status: FindingStatus): void {
    const finding = this.finding();
    if (!finding) return;
    const until = status === 'accepted' && this.acceptUntil() ? this.acceptUntil() : null;
    this.isTriaging.set(true);
    this.findingService.triage(finding.id, status, this.note().trim(), until).subscribe({
      next: (updated) => {
        this.isTriaging.set(false);
        this.finding.set(updated);
        this.note.set('');
        this.acceptUntil.set('');
        this.toasts.success(
          status === 'open'
            ? 'Reopened. It counts toward the risk score again.'
            : `Marked as ${this.statusLabels[status].toLowerCase()}${until ? ' until ' + until : ''}.`,
        );
        this.loadTimeline(updated.id);
      },
      error: (err) => {
        this.isTriaging.set(false);
        this.toasts.error(err.error?.accepted_until?.[0] ?? 'Could not update the finding.');
      },
    });
  }

  assign(value: string): void {
    const finding = this.finding();
    if (!finding) return;
    this.findingService.assign(finding.id, value ? Number(value) : null).subscribe({
      next: (updated) => {
        this.finding.set(updated);
        this.toasts.success(
          updated.assignee_username
            ? `${updated.assignee_username} is now responsible for fixing this.`
            : 'Nobody is assigned to this any more.',
        );
        this.loadTimeline(updated.id);
      },
      error: () => this.toasts.error('Could not change who this is assigned to.'),
    });
  }

  postComment(): void {
    const finding = this.finding();
    const body = this.comment().trim();
    if (!finding || !body || this.isPosting()) return;
    this.isPosting.set(true);
    this.findingService.addComment(finding.id, body).subscribe({
      next: () => {
        this.isPosting.set(false);
        this.comment.set('');
        this.loadTimeline(finding.id);
      },
      error: () => {
        this.isPosting.set(false);
        this.toasts.error('Could not post the comment.');
      },
    });
  }

  copyAsTicket(): void {
    const finding = this.finding();
    if (!finding) return;
    navigator.clipboard
      ?.writeText(ticketText(finding))
      .then(() => this.toasts.success('Copied as a ticket. Paste it into Jira, GitHub or an email.'))
      .catch(() => this.toasts.error('Could not copy to the clipboard.'));
  }

  private load(id: string): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);
    this.findingService.get(id).subscribe({
      next: (finding) => {
        this.finding.set(finding);
        this.isLoading.set(false);
        this.loadTimeline(id);
      },
      error: (err) => {
        this.errorMessage.set(
          err.status === 404
            ? 'This finding does not exist, or belongs to an organization you are not a member of.'
            : 'Could not load the finding.',
        );
        this.isLoading.set(false);
      },
    });
  }

  private loadTimeline(id: string): void {
    this.findingService.timeline(id).subscribe({
      next: (entries) => this.timeline.set(entries),
      error: () => undefined,
    });
  }
}
