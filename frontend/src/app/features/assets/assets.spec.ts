import { Component, DestroyRef, OnDestroy, effect, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Asset, AssetType } from '../../core/models/models';
import { AssetService } from '../../core/services/asset-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';

const SEARCH_DEBOUNCE_MS = 300;

@Component({
  selector: 'app-assets',
  imports: [FormsModule, DatePipe],
  templateUrl: './assets.html',
  styleUrl: './assets.scss',
})
export class Assets implements OnDestroy {
  private readonly assetService = inject(AssetService);
  protected readonly orgContext = inject(OrganizationContextService);
  private searchDebounceHandle: ReturnType<typeof setTimeout> | undefined;

  readonly assets = signal<Asset[]>([]);
  readonly totalCount = signal(0);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly searchTerm = signal('');
  readonly assetTypeFilter = signal<AssetType | ''>('');

  constructor() {
    // Refetches whenever the selected org changes, on top of the
    // search/type filters already triggering their own refetch --
    // this is what makes the org switcher actually affect this page.
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      if (org) {
        this.fetchAssets(org.id);
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
      const org = this.orgContext.selectedOrganization();
      if (org) this.fetchAssets(org.id);
    }, SEARCH_DEBOUNCE_MS);
  }

  onTypeFilterChange(value: string): void {
    this.assetTypeFilter.set(value as AssetType | '');
    const org = this.orgContext.selectedOrganization();
    if (org) this.fetchAssets(org.id);
  }

  private fetchAssets(orgId: string): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);

    this.assetService
      .list({
        organization: orgId,
        search: this.searchTerm() || undefined,
        asset_type: this.assetTypeFilter() || undefined,
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