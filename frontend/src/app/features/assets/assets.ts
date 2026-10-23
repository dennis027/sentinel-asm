import { PluralPipe } from '../../shared/pipes/plural';
import { Component, OnDestroy, computed, effect, inject, signal, untracked } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Asset, AssetType, Criticality, Member } from '../../core/models/models';
import { AssetService } from '../../core/services/asset-service';
import { OrganizationService } from '../../core/services/organization-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { ToastService } from '../../core/services/toast.service';
import { CRITICALITIES, apiErrorMessage, criticalityLabel, webStatus } from '../../core/labels';
import { Icon } from '../../shared/components/icon/icon';
import { Pager } from '../../shared/components/pager/pager';
import { EmptyState } from '../../shared/components/empty-state/empty-state';
import { AssetPeek } from '../../shared/components/asset-peek/asset-peek';
import { SavedViews } from '../../shared/components/saved-views/saved-views';

const SEARCH_DEBOUNCE_MS = 300;

// What the search box understands, with an example of each (apps/assets/query.py).
export const QUERY_HELP: { term: string; meaning: string }[] = [
  { term: 'tech:nginx', meaning: 'runs this software' },
  { term: 'provider:aws', meaning: 'hosted on (provider:none = unknown)' },
  { term: 'owner:me', meaning: 'owned by (a name, me or none)' },
  { term: 'status:5xx', meaning: 'last web reply (2xx…5xx, none)' },
  { term: 'port:22', meaning: 'has this port open' },
  { term: 'severity:high+', meaning: 'has an open issue this bad or worse' },
  { term: 'tag:payments', meaning: 'carries the label' },
  { term: 'new:7', meaning: 'first seen in the last 7 days' },
  { term: '-tag:legacy', meaning: 'a minus excludes' },
];

@Component({
  selector: 'app-assets',
  imports: [PluralPipe, FormsModule, Pager, RouterLink, EmptyState, Icon, AssetPeek, SavedViews],
  templateUrl: './assets.html',
  styleUrl: './assets.scss',
})
export class Assets implements OnDestroy {
  private readonly assetService = inject(AssetService);
  private readonly orgService = inject(OrganizationService);
  protected readonly orgContext = inject(OrganizationContextService);
  private readonly toasts = inject(ToastService);
  private readonly router = inject(Router);
  private readonly queryParams = toSignal(inject(ActivatedRoute).queryParamMap);
  private searchDebounceHandle: ReturnType<typeof setTimeout> | undefined;

  readonly assets = signal<Asset[]>([]);
  readonly totalCount = signal(0);
  readonly page = signal(1);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  // The search box, in the search language; kept in the URL (?q=) so it can be linked to.
  readonly searchTerm = signal(inject(ActivatedRoute).snapshot.queryParamMap.get('q') ?? '');
  readonly showHelp = signal(false);
  protected readonly queryHelp = QUERY_HELP;
  protected readonly webStatus = webStatus;

  // The host open in the side panel, and who can own hosts.
  readonly peeking = signal<Asset | null>(null);
  readonly members = signal<Member[]>([]);
  readonly assetTypeFilter = signal<AssetType | ''>('');
  readonly criticalityFilter = signal<Criticality | ''>('');
  // From a label link (?tag=payments).
  readonly tagFilter = computed(() => this.queryParams()?.get('tag') ?? '');
  // What a saved view stores for this page.
  readonly currentFilters = computed(() => {
    const filters: Record<string, string> = {};
    if (this.searchTerm().trim()) filters['q'] = this.searchTerm().trim();
    if (this.assetTypeFilter()) filters['asset_type'] = this.assetTypeFilter();
    if (this.criticalityFilter()) filters['criticality'] = this.criticalityFilter();
    if (this.tagFilter()) filters['tag'] = this.tagFilter();
    return filters;
  });
  protected readonly criticalities = CRITICALITIES;
  protected readonly criticalityLabel = criticalityLabel;

  // Importing a list of hosts.
  readonly isImporting = signal(false);
  readonly importText = signal('');
  readonly importResult = signal<{ added: string[]; skipped: { value: string; reason: string }[] } | null>(null);

  // Adding a host by hand.
  readonly isAdding = signal(false);
  readonly newHost = signal('');
  readonly addError = signal<string | null>(null);
  readonly isSaving = signal(false);

  constructor() {
    // Refetches whenever the selected org changes, on top of the
    // search/type filters already triggering their own refetch --
    // this is what makes the org switcher actually affect this page.
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      this.tagFilter();
      untracked(() => {
        this.page.set(1);
        this.peeking.set(null);
        this.fetchAssets();
      });
      if (org) {
        untracked(() =>
          this.orgService.members(org.id).subscribe({ next: (m) => this.members.set(m), error: () => this.members.set([]) }),
        );
      }
    });
  }

  ngOnDestroy(): void {
    clearTimeout(this.searchDebounceHandle);
  }

  techNames(asset: Asset): string {
    return asset.technologies.map((t) => t.name).join(', ');
  }

  onSearchChange(value: string): void {
    this.searchTerm.set(value);
    clearTimeout(this.searchDebounceHandle);
    this.searchDebounceHandle = setTimeout(() => {
      this.router.navigate([], { queryParams: { q: value.trim() || null }, queryParamsHandling: 'merge', replaceUrl: true });
      this.page.set(1);
      this.fetchAssets();
    }, SEARCH_DEBOUNCE_MS);
  }

  /** Adds an example term from the help to the search. */
  addTerm(term: string): void {
    const current = this.searchTerm().trim();
    this.onSearchChange(current ? `${current} ${term}` : term);
  }

  applyView(filters: Record<string, string>): void {
    this.searchTerm.set(filters['q'] ?? '');
    this.assetTypeFilter.set((filters['asset_type'] as AssetType) ?? '');
    this.criticalityFilter.set((filters['criticality'] as Criticality) ?? '');
    this.router.navigate([], {
      queryParams: { q: filters['q'] || null, tag: filters['tag'] || null },
      queryParamsHandling: 'merge',
    });
    this.page.set(1);
    this.fetchAssets();
  }

  /** Opens the side panel, unless the click was on a link or button in the row. */
  peek(asset: Asset, event: MouseEvent): void {
    if ((event.target as HTMLElement).closest('a, button')) return;
    this.peeking.set(asset);
  }

  onPeekChanged(asset: Asset): void {
    this.peeking.set(asset);
    this.assets.update((assets) => assets.map((a) => (a.id === asset.id ? asset : a)));
  }

  onTypeFilterChange(value: string): void {
    this.assetTypeFilter.set(value as AssetType | '');
    this.page.set(1);
    this.fetchAssets();
  }

  onCriticalityChange(value: string): void {
    this.criticalityFilter.set(value as Criticality | '');
    this.page.set(1);
    this.fetchAssets();
  }

  clearTagFilter(): void {
    this.router.navigate([], { queryParams: { tag: null }, queryParamsHandling: 'merge' });
  }

  startImport(): void {
    this.isImporting.set(true);
    this.isAdding.set(false);
    this.importText.set('');
    this.importResult.set(null);
  }

  importHosts(): void {
    const org = this.orgContext.selectedOrganization();
    const values = this.importText()
      .split(/[\s,;]+/)
      .map((v) => v.trim())
      .filter(Boolean);
    if (!org || !values.length || this.isSaving()) return;
    this.isSaving.set(true);
    this.assetService.bulkCreate(org.id, values).subscribe({
      next: (result) => {
        this.isSaving.set(false);
        this.importResult.set(result);
        if (result.added.length) {
          this.toasts.success(`${result.added.length} host(s) added. The next scan will check them.`);
          this.fetchAssets();
        }
      },
      error: (err) => {
        this.isSaving.set(false);
        this.toasts.error(apiErrorMessage(err, 'Could not import that list.'));
      },
    });
  }

  onPageChange(page: number): void {
    this.page.set(page);
    this.fetchAssets();
  }

  startAdding(): void {
    this.isAdding.set(true);
    this.addError.set(null);
    this.newHost.set('');
  }

  addAsset(): void {
    const org = this.orgContext.selectedOrganization();
    const host = this.newHost().trim();
    if (!org || !host || this.isSaving()) return;

    this.isSaving.set(true);
    this.addError.set(null);
    this.assetService.create(org.id, host).subscribe({
      next: (asset) => {
        this.isSaving.set(false);
        this.isAdding.set(false);
        this.toasts.success(`${asset.value} is now monitored. The next scan will check it.`);
        this.fetchAssets();
      },
      error: (err) => {
        this.isSaving.set(false);
        this.addError.set(apiErrorMessage(err, 'Could not add that host.'));
      },
    });
  }

  private fetchAssets(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) {
      this.assets.set([]);
      this.totalCount.set(0);
      this.isLoading.set(!this.orgContext.isLoaded());
      return;
    }

    this.isLoading.set(true);
    this.errorMessage.set(null);

    this.assetService
      .list({
        organization: org.id,
        q: this.searchTerm().trim() || undefined,
        asset_type: this.assetTypeFilter() || undefined,
        criticality: this.criticalityFilter() || undefined,
        tag: this.tagFilter() || undefined,
        page: this.page(),
      })
      .subscribe({
        next: (page) => {
          this.assets.set(page.results);
          this.totalCount.set(page.count);
          this.isLoading.set(false);
        },
        error: () => {
          this.errorMessage.set('Could not load assets.');
          this.isLoading.set(false);
        },
      });
  }
}
