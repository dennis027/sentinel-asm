import { Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Asset, AssetType } from '../../core/models/models';
import { AssetService } from '../../core/services/asset-service';

const SEARCH_DEBOUNCE_MS = 300;

@Component({
  selector: 'app-assets',
  imports: [FormsModule, DatePipe],
  templateUrl: './assets.html',
  styleUrl: './assets.scss',
})
export class Assets implements OnInit, OnDestroy {
  private readonly assetService = inject(AssetService);
  private searchDebounceHandle: ReturnType<typeof setTimeout> | undefined;

  readonly assets = signal<Asset[]>([]);
  readonly totalCount = signal(0);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly searchTerm = signal('');
  readonly assetTypeFilter = signal<AssetType | ''>('');

  techNames(asset: Asset): string {
    return asset.technologies.map((t) => t.name).join(', ');
  }

  ngOnInit(): void {
    this.fetchAssets();
  }

  ngOnDestroy(): void {
    clearTimeout(this.searchDebounceHandle);
  }

  onSearchChange(value: string): void {
    this.searchTerm.set(value);
    clearTimeout(this.searchDebounceHandle);
    this.searchDebounceHandle = setTimeout(() => this.fetchAssets(), SEARCH_DEBOUNCE_MS);
  }

  onTypeFilterChange(value: string): void {
    this.assetTypeFilter.set(value as AssetType | '');
    this.fetchAssets();
  }

  private fetchAssets(): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);

    this.assetService
      .list({
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