import { PluralPipe } from '../../shared/pipes/plural';
import {
  Component,
  HostListener,
  computed,
  OnDestroy,
  effect,
  inject,
  signal,
  untracked,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Finding } from '../../core/models/models';
import { FindingService } from '../../core/services/finding-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { EmptyState } from '../../shared/components/empty-state/empty-state';
import { Icon } from '../../shared/components/icon/icon';
import { Pager } from '../../shared/components/pager/pager';

const PAGE_SIZE = 24;
const SEARCH_DEBOUNCE_MS = 300;

/**
 * Everything the Screenshot scanner has captured for the selected
 * organization, as a gallery: one tile per page, searchable by page
 * title or host. Screenshots are findings underneath, but looking for
 * "what does that site look like" in a findings list is the wrong tool.
 */
@Component({
  selector: 'app-screenshots',
  imports: [PluralPipe, FormsModule, DatePipe, RouterLink, Pager, EmptyState, Icon],
  templateUrl: './screenshots.html',
  styleUrl: './screenshots.scss',
})
export class Screenshots implements OnDestroy {
  private readonly findingService = inject(FindingService);
  protected readonly orgContext = inject(OrganizationContextService);
  private searchDebounceHandle: ReturnType<typeof setTimeout> | undefined;

  protected readonly pageSize = PAGE_SIZE;

  readonly shots = signal<Finding[]>([]);
  readonly totalCount = signal(0);
  readonly page = signal(1);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);
  readonly searchTerm = signal('');

  // finding id -> object URL of its image, filled in as each loads
  readonly imageUrls = signal<Record<string, string>>({});
  // ids whose image could not be fetched
  readonly missingImages = signal<ReadonlySet<string>>(new Set());
  // The screenshot opened at full size, if any.
  readonly viewing = signal<Finding | null>(null);
  // Set while the viewer waits for the next/previous gallery page, to
  // open its first or last screenshot once it arrives.
  private openOnLoad: 'first' | 'last' | null = null;

  /** Where the open screenshot sits among all of them, 1-based. */
  readonly viewingPosition = computed(() => {
    const shot = this.viewing();
    const index = shot ? this.shots().findIndex((s) => s.id === shot.id) : -1;
    return index < 0 ? 0 : (this.page() - 1) * PAGE_SIZE + index + 1;
  });
  readonly hasPrevious = computed(() => this.viewingPosition() > 1);
  readonly hasNext = computed(() => {
    const position = this.viewingPosition();
    return position > 0 && position < this.totalCount();
  });

  constructor() {
    effect(() => {
      this.orgContext.selectedOrganization();
      untracked(() => {
        this.page.set(1);
        this.fetch();
      });
    });
  }

  ngOnDestroy(): void {
    clearTimeout(this.searchDebounceHandle);
    this.releaseImages();
  }

  @HostListener('document:keydown.escape')
  close(): void {
    this.viewing.set(null);
  }

  @HostListener('document:keydown.arrowright')
  showNext(): void {
    this.step(1);
  }

  @HostListener('document:keydown.arrowleft')
  showPrevious(): void {
    this.step(-1);
  }

  /**
   * Moves the viewer one screenshot along, loading the neighbouring
   * gallery page when it steps off the end of this one.
   */
  private step(delta: 1 | -1): void {
    const shot = this.viewing();
    if (!shot || this.isLoading()) return;
    if (delta === 1 ? !this.hasNext() : !this.hasPrevious()) return;

    const shots = this.shots();
    const target = shots.findIndex((s) => s.id === shot.id) + delta;
    if (target >= 0 && target < shots.length) {
      this.viewing.set(shots[target]);
      return;
    }
    this.openOnLoad = delta === 1 ? 'first' : 'last';
    this.page.update((p) => p + delta);
    this.fetch();
  }

  onSearchChange(value: string): void {
    this.searchTerm.set(value);
    clearTimeout(this.searchDebounceHandle);
    this.searchDebounceHandle = setTimeout(() => {
      this.page.set(1);
      this.fetch();
    }, SEARCH_DEBOUNCE_MS);
  }

  onPageChange(page: number): void {
    this.page.set(page);
    this.fetch();
  }

  /** The page's own title, falling back to the host it was taken on. */
  titleOf(shot: Finding): string {
    const title = shot.raw_data?.['page_title'];
    return typeof title === 'string' && title.trim() ? title : shot.asset_value;
  }

  /** The address that was captured, without the scheme. */
  urlOf(shot: Finding): string {
    const url = shot.raw_data?.['final_url'];
    return typeof url === 'string' && url ? url.replace(/^https?:\/\//, '') : shot.asset_value;
  }

  private fetch(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) {
      this.shots.set([]);
      this.totalCount.set(0);
      this.isLoading.set(!this.orgContext.isLoaded());
      return;
    }

    this.isLoading.set(true);
    this.errorMessage.set(null);
    this.findingService
      .list({
        organization: org.id,
        finding_type: 'screenshot',
        is_active: true,
        search: this.searchTerm().trim() || undefined,
        page: this.page(),
        page_size: PAGE_SIZE,
      })
      .subscribe({
        next: (page) => {
          this.shots.set(page.results);
          this.totalCount.set(page.count);
          this.isLoading.set(false);
          this.loadImages(page.results);
          if (this.openOnLoad) {
            const results = page.results;
            this.viewing.set(
              (this.openOnLoad === 'first' ? results[0] : results[results.length - 1]) ?? null,
            );
            this.openOnLoad = null;
          }
        },
        error: () => {
          this.openOnLoad = null;
          this.viewing.set(null);
          this.errorMessage.set('Could not load screenshots. Check your connection and reload.');
          this.isLoading.set(false);
        },
      });
  }

  private loadImages(shots: Finding[]): void {
    this.releaseImages();
    for (const shot of shots) {
      this.findingService.screenshot(shot.id).subscribe({
        next: (blob) => {
          // A newer page may have loaded while this was in flight.
          if (!this.shots().some((s) => s.id === shot.id)) return;
          this.imageUrls.update((urls) => ({ ...urls, [shot.id]: URL.createObjectURL(blob) }));
        },
        // The file can be gone (cleaned up, other worker); the tile
        // then shows its placeholder.
        error: () => this.missingImages.update((ids) => new Set(ids).add(shot.id)),
      });
    }
  }

  private releaseImages(): void {
    for (const url of Object.values(this.imageUrls())) {
      URL.revokeObjectURL(url);
    }
    this.imageUrls.set({});
    this.missingImages.set(new Set());
  }
}
