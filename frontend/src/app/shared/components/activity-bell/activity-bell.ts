import { Component, ElementRef, HostListener, OnDestroy, computed, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ActivityEvent } from '../../../core/models/models';
import { AuthService } from '../../../core/services/auth.service';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { OrganizationService } from '../../../core/services/organization-service';
import { Icon, IconName } from '../icon/icon';

const REFRESH_MS = 120_000;
const SEEN_KEY = 'sentinel_activity_seen_';

const VERB_ICONS: Record<string, IconName> = {
  finding_assigned: 'users',
  finding_triaged: 'clipboard',
  finding_commented: 'message',
  finding_reopened: 'repeat',
  acceptance_expired: 'calendar',
  scan_started: 'play',
  asset_added: 'plus',
  asset_updated: 'tag',
  scope_changed: 'eye-off',
  report_downloaded: 'download',
};

/**
 * The bell in the sidebar: what the team has done lately in this
 * organization, with a count of what's new since you last looked.
 * Things that name you ("assigned to you") are marked. What you have
 * seen is remembered in this browser only.
 */
@Component({
  selector: 'app-activity-bell',
  imports: [DatePipe, RouterLink, Icon],
  templateUrl: './activity-bell.html',
  styleUrl: './activity-bell.scss',
})
export class ActivityBell implements OnDestroy {
  private readonly orgService = inject(OrganizationService);
  private readonly orgContext = inject(OrganizationContextService);
  private readonly auth = inject(AuthService);
  private readonly host = inject(ElementRef<HTMLElement>);
  private refreshHandle: ReturnType<typeof setInterval> | undefined;

  readonly events = signal<ActivityEvent[]>([]);
  readonly isOpen = signal(false);
  readonly seenAt = signal<string>('');

  readonly unread = computed(() => this.events().filter((e) => e.created_at > this.seenAt()).length);

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      untracked(() => {
        clearInterval(this.refreshHandle);
        this.events.set([]);
        if (!org) return;
        this.seenAt.set(this.readSeen(org.id));
        this.load(org.id);
        this.refreshHandle = setInterval(() => this.load(org.id), REFRESH_MS);
      });
    });
  }

  ngOnDestroy(): void {
    clearInterval(this.refreshHandle);
  }

  toggle(): void {
    const opening = !this.isOpen();
    this.isOpen.set(opening);
    const org = this.orgContext.selectedOrganization();
    if (opening && org) {
      this.load(org.id);
      // Everything listed now counts as seen; the highlight stays until it closes.
      const newest = this.events()[0]?.created_at;
      if (newest) this.writeSeen(org.id, newest);
    } else if (org) {
      this.seenAt.set(this.readSeen(org.id));
    }
  }

  isNew(event: ActivityEvent): boolean {
    return event.created_at > this.seenAt();
  }

  /** Names the signed-in person: "assigned … to dennis". */
  isForMe(event: ActivityEvent): boolean {
    const me = this.auth.currentUsername();
    if (!me || event.actor === me) return false;
    return event.summary.split(/\s+/).some((word) => word.replace(/^[^\w]+|[^\w]+$/g, '') === me);
  }

  icon(event: ActivityEvent): IconName {
    return VERB_ICONS[event.verb] ?? 'activity';
  }

  @HostListener('document:click', ['$event'])
  onDocumentClick(event: MouseEvent): void {
    if (this.isOpen() && !this.host.nativeElement.contains(event.target as Node)) this.toggle();
  }

  @HostListener('document:keydown.escape')
  onEscape(): void {
    if (this.isOpen()) this.toggle();
  }

  private load(orgId: string): void {
    this.orgService.activity(orgId).subscribe({
      next: (page) => this.events.set(page.results.slice(0, 12)),
      error: () => undefined,
    });
  }

  private readSeen(orgId: string): string {
    try {
      return localStorage.getItem(SEEN_KEY + orgId) ?? '';
    } catch {
      return '';
    }
  }

  private writeSeen(orgId: string, at: string): void {
    try {
      localStorage.setItem(SEEN_KEY + orgId, at);
    } catch {
      // Private browsing: the count just won't be remembered.
    }
  }
}
