import {
  Component,
  ElementRef,
  HostListener,
  OnDestroy,
  computed,
  effect,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { Router } from '@angular/router';
import { findingTypeLabel } from '../../../core/labels';
import { AssetService } from '../../../core/services/asset-service';
import { FindingService } from '../../../core/services/finding-service';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { SearchService } from '../../../core/services/search.service';
import { Icon, IconName } from '../icon/icon';

interface Result {
  group: 'Pages' | 'Assets' | 'Issues';
  label: string;
  detail: string;
  icon: IconName;
  severity?: string;
  go: () => void;
}

const PAGES: { label: string; path: string; icon: IconName; words: string }[] = [
  { label: 'Dashboard', path: '/dashboard', icon: 'dashboard', words: 'home overview grade score trend' },
  { label: 'Board view', path: '/board', icon: 'monitor', words: 'presentation tv wall screen full screen meeting' },
  { label: 'Fix plan', path: '/fix-plan', icon: 'wrench', words: 'priorities what to fix first todo plan grade' },
  { label: 'My work', path: '/my-work', icon: 'inbox', words: 'assigned to me tasks deadline' },
  { label: 'Findings', path: '/findings', icon: 'findings', words: 'issues vulnerabilities problems' },
  { label: 'Attack surface map', path: '/surface-map', icon: 'map', words: 'graph visual overview' },
  { label: 'Assets', path: '/assets', icon: 'assets', words: 'hosts subdomains crown jewel tags import' },
  { label: 'Software inventory', path: '/inventory', icon: 'package', words: 'technologies versions nginx wordpress' },
  { label: 'Compliance', path: '/compliance', icon: 'shield-check', words: 'owasp cis iso pci mitre attack audit framework' },
  { label: 'Open services', path: '/inventory?tab=services', icon: 'plug', words: 'ports rdp ssh database exposed' },
  { label: 'Certificates', path: '/inventory?tab=certificates', icon: 'lock', words: 'tls ssl expiry expiring' },
  { label: 'Overdue findings', path: '/findings?overdue=1', icon: 'history', words: 'late sla past due fix' },
  { label: 'Issues that came back', path: '/findings?regressed=1', icon: 'repeat', words: 'regressed reopened again' },
  { label: 'Logs', path: '/logs', icon: 'server', words: 'siem events linux ubuntu windows ssh rdp brute force sign-ins detections python node django express errors exceptions stack trace apps' },
  { label: 'Connect a server', path: '/logs?tab=servers', icon: 'plus', words: 'fluent bit agent ship logs linux windows' },
  { label: 'Screenshots', path: '/screenshots', icon: 'camera', words: 'gallery pictures sites' },
  { label: 'Scanners', path: '/scanners', icon: 'scanners', words: 'scan run start' },
  { label: 'Scan history', path: '/scan-history', icon: 'history', words: 'jobs runs' },
  { label: 'Activity log', path: '/activity', icon: 'activity', words: 'audit trail who' },
  { label: 'Alerts & reports', path: '/notification-rules', icon: 'bell', words: 'notifications email slack teams webhook weekly report alerts' },
  { label: 'Organization', path: '/organization', icon: 'users', words: 'team members domain verify settings sla deadlines scope never scan exclusions' },
  { label: 'Account settings', path: '/account-settings', icon: 'users', words: 'password profile two-factor 2fa api keys sign-ins' },
];

const SEARCH_DEBOUNCE_MS = 200;

/**
 * Ctrl/Cmd+K from any signed-in page: jump to a page, a host, or an
 * issue by typing part of its name. Arrow keys move, Enter opens,
 * Escape closes.
 */
@Component({
  selector: 'app-command-palette',
  imports: [Icon],
  templateUrl: './command-palette.html',
  styleUrl: './command-palette.scss',
})
export class CommandPalette implements OnDestroy {
  protected readonly search = inject(SearchService);
  private readonly router = inject(Router);
  private readonly assetService = inject(AssetService);
  private readonly findingService = inject(FindingService);
  private readonly orgContext = inject(OrganizationContextService);
  private readonly input = viewChild<ElementRef<HTMLInputElement>>('input');
  private debounce: ReturnType<typeof setTimeout> | undefined;

  readonly query = signal('');
  readonly assetResults = signal<Result[]>([]);
  readonly issueResults = signal<Result[]>([]);
  readonly active = signal(0);

  readonly pageResults = computed<Result[]>(() => {
    const words = this.query().trim().toLowerCase();
    return PAGES.filter((page) => !words || `${page.label} ${page.words}`.toLowerCase().includes(words))
      .slice(0, words ? 5 : 8)
      .map((page) => ({
        group: 'Pages' as const,
        label: page.label,
        detail: '',
        icon: page.icon,
        go: () => this.router.navigateByUrl(page.path),
      }));
  });

  readonly results = computed(() => [...this.pageResults(), ...this.assetResults(), ...this.issueResults()]);

  constructor() {
    effect(() => {
      if (this.search.isOpen()) {
        this.query.set('');
        this.assetResults.set([]);
        this.issueResults.set([]);
        this.active.set(0);
        setTimeout(() => this.input()?.nativeElement.focus());
      }
    });
  }

  ngOnDestroy(): void {
    clearTimeout(this.debounce);
  }

  @HostListener('document:keydown', ['$event'])
  onGlobalKey(event: KeyboardEvent): void {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      if (this.search.isOpen()) this.search.close();
      else this.search.open();
    }
  }

  onInput(value: string): void {
    this.query.set(value);
    this.active.set(0);
    clearTimeout(this.debounce);
    const org = this.orgContext.selectedOrganization();
    const words = value.trim();
    if (!org || words.length < 2) {
      this.assetResults.set([]);
      this.issueResults.set([]);
      return;
    }
    this.debounce = setTimeout(() => {
      this.assetService.list({ organization: org.id, search: words, page_size: 5 }).subscribe({
        next: (page) =>
          this.assetResults.set(
            page.results.map((asset) => ({
              group: 'Assets' as const,
              label: asset.value,
              detail: `Grade ${asset.risk_grade}`,
              icon: 'assets' as IconName,
              go: () =>
                this.router.navigate(['/findings'], { queryParams: { asset: asset.id, assetName: asset.value } }),
            })),
          ),
      });
      this.findingService
        .list({ organization: org.id, search: words, kind: 'issue', is_active: true, page_size: 5 })
        .subscribe({
          next: (page) =>
            this.issueResults.set(
              page.results.map((finding) => ({
                group: 'Issues' as const,
                label: finding.title,
                detail: `${finding.asset_value} · ${findingTypeLabel(finding.finding_type)}`,
                icon: 'findings' as IconName,
                severity: finding.severity,
                go: () =>
                  this.router.navigate(['/findings'], {
                    queryParams: { asset: finding.asset, assetName: finding.asset_value },
                  }),
              })),
            ),
        });
    }, SEARCH_DEBOUNCE_MS);
  }

  onKey(event: KeyboardEvent): void {
    const count = this.results().length;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      this.active.set(count ? (this.active() + 1) % count : 0);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      this.active.set(count ? (this.active() - 1 + count) % count : 0);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      const result = this.results()[this.active()];
      if (result) this.choose(result);
    } else if (event.key === 'Escape') {
      this.search.close();
    }
  }

  choose(result: Result): void {
    this.search.close();
    result.go();
  }

  /** Index of a result in the flat list, for keyboard highlighting. */
  indexOf(result: Result): number {
    return this.results().indexOf(result);
  }
}
