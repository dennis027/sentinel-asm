import { LogoMark } from '../logo-mark/logo-mark';
import { Component, OnInit, effect, inject, signal, untracked } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from '../../../core/services/auth.service';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { FormsModule } from '@angular/forms';
import { Toasts } from '../toasts/toasts';
import { ConfirmDialog } from '../confirm-dialog/confirm-dialog';
import { CommandPalette } from '../command-palette/command-palette';
import { SearchService } from '../../../core/services/search.service';
import { FindingService } from '../../../core/services/finding-service';
import { Icon, IconName } from '../icon/icon';
import { ActivityBell } from '../activity-bell/activity-bell';
import { KeyboardShortcuts } from '../keyboard-shortcuts/keyboard-shortcuts';
import { ThemePreference, ThemeService } from '../../../core/services/theme.service';

// Pages that make sense before the user has any organization.
const ORG_FREE_PATHS = ['/organization', '/account-settings'];

@Component({
  selector: 'app-shell',
  imports: [LogoMark, 
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    FormsModule,
    Toasts,
    Icon,
    ConfirmDialog,
    CommandPalette,
    ActivityBell,
    KeyboardShortcuts,
  ],
  templateUrl: './shell.html',
  styleUrl: './shell.scss',
})
export class Shell implements OnInit {
  protected readonly auth = inject(AuthService);
  protected readonly orgContext = inject(OrganizationContextService);
  protected readonly theme = inject(ThemeService);
  protected readonly search = inject(SearchService);
  private readonly router = inject(Router);
  private readonly findingService = inject(FindingService);

  // Open issues assigned to the signed-in person in this organization.
  readonly myWorkCount = signal(0);
  // Icons only, to give pages more room; remembered on this browser.
  readonly collapsed = signal(readCollapsed());

  protected readonly themeOptions: { value: ThemePreference; label: string; icon: IconName }[] = [
    { value: 'light', label: 'Light theme', icon: 'sun' },
    { value: 'system', label: 'Match system theme', icon: 'monitor' },
    { value: 'dark', label: 'Dark theme', icon: 'moon' },
  ];

  constructor() {
    // A user with no organization can't do anything on the data pages,
    // so send them to the one place that fixes that.
    effect(() => {
      const hasNone =
        this.orgContext.isLoaded() && this.orgContext.allOrganizations().length === 0;
      if (hasNone && !ORG_FREE_PATHS.some((path) => this.router.url.startsWith(path))) {
        this.router.navigate(['/organization']);
      }
    });

    effect(() => {
      const org = this.orgContext.selectedOrganization();
      untracked(() => {
        this.myWorkCount.set(0);
        if (!org) return;
        this.findingService
          .list({ organization: org.id, assignee: 'me', is_active: true, triaged: false, kind: 'issue', page_size: 1 })
          .subscribe({ next: (page) => this.myWorkCount.set(page.count), error: () => undefined });
      });
    });
  }

  ngOnInit(): void {
    this.orgContext.loadOrganizations();
  }

  onOrgChange(orgId: string): void {
    this.orgContext.selectOrganization(orgId);
  }

  toggleCollapsed(): void {
    this.collapsed.update((value) => !value);
    try {
      localStorage.setItem(COLLAPSED_KEY, this.collapsed() ? '1' : '0');
    } catch {
      // Storage blocked: it just won't be remembered.
    }
  }
}

const COLLAPSED_KEY = 'densight_sidebar_collapsed';

function readCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSED_KEY) === '1';
  } catch {
    return false;
  }
}
