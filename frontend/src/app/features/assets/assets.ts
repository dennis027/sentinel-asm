import { PluralPipe } from '../../shared/pipes/plural';
import { Component, OnDestroy, computed, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Asset, AssetType, Criticality } from '../../core/models/models';
import { AssetService } from '../../core/services/asset-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { ToastService } from '../../core/services/toast.service';
import { CRITICALITIES, apiErrorMessage, criticalityLabel } from '../../core/labels';
import { Icon } from '../../shared/components/icon/icon';
import { Pager } from '../../shared/components/pager/pager';
import { EmptyState } from '../../shared/components/empty-state/empty-state';

const SEARCH_DEBOUNCE_MS = 300;

@Component({
  selector: 'app-assets',
  imports: [PluralPipe, FormsModule, DatePipe, Pager, RouterLink, EmptyState, Icon],
  templateUrl: './assets.html',
  styleUrl: './assets.scss',
})
export class Assets implements OnDestroy {
  private readonly assetService = inject(AssetService);
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

  readonly searchTerm = signal('');
  readonly assetTypeFilter = signal<AssetType | ''>('');
  readonly criticalityFilter = signal<Criticality | ''>('');
  // From a label link (?tag=payments).
  readonly tagFilter = computed(() => this.queryParams()?.get('tag') ?? '');
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
      this.orgContext.selectedOrganization();
      this.tagFilter();
      untracked(() => {
        this.page.set(1);
        this.fetchAssets();
      });
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
      this.page.set(1);
      this.fetchAssets();
    }, SEARCH_DEBOUNCE_MS);
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
        search: this.searchTerm() || undefined,
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
