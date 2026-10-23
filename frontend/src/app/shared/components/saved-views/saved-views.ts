import { Component, ElementRef, HostListener, effect, inject, input, output, signal, untracked } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { SavedView } from '../../../core/models/models';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { SurfaceService } from '../../../core/services/surface.service';
import { ToastService } from '../../../core/services/toast.service';
import { apiErrorMessage } from '../../../core/labels';
import { Icon } from '../icon/icon';

/**
 * "Views" menu for a list page: apply one of your saved filter sets (or
 * one a teammate shared), save the current filters under a name, delete
 * your own. The page owns the filters; this only hands them back.
 */
@Component({
  selector: 'app-saved-views',
  imports: [FormsModule, Icon],
  templateUrl: './saved-views.html',
  styleUrl: './saved-views.scss',
})
export class SavedViews {
  private readonly surface = inject(SurfaceService);
  private readonly orgContext = inject(OrganizationContextService);
  private readonly toasts = inject(ToastService);
  private readonly host = inject(ElementRef<HTMLElement>);

  readonly page = input.required<SavedView['page']>();
  // The page's current filters, empty values left out.
  readonly filters = input.required<Record<string, string>>();
  readonly apply = output<Record<string, string>>();

  readonly views = signal<SavedView[]>([]);
  readonly open = signal(false);
  readonly saving = signal(false);
  readonly naming = signal(false);
  readonly name = signal('');
  readonly shared = signal(false);
  readonly active = signal<string | null>(null);

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      untracked(() => (org ? this.load(org.id) : this.views.set([])));
    });
  }

  @HostListener('document:click', ['$event'])
  onDocumentClick(event: MouseEvent): void {
    if (this.open() && !this.host.nativeElement.contains(event.target as Node)) {
      this.close();
    }
  }

  @HostListener('document:keydown.escape')
  close(): void {
    this.open.set(false);
    this.naming.set(false);
  }

  hasFilters(): boolean {
    return Object.keys(this.filters()).length > 0;
  }

  choose(view: SavedView): void {
    this.active.set(view.id);
    this.apply.emit({ ...view.filters });
    this.close();
  }

  startSaving(): void {
    this.naming.set(true);
    this.name.set('');
    this.shared.set(false);
  }

  save(): void {
    const org = this.orgContext.selectedOrganization();
    const name = this.name().trim();
    if (!org || !name || this.saving()) return;
    this.saving.set(true);
    this.surface
      .createView(org.id, { page: this.page(), name, filters: this.filters(), shared: this.shared() })
      .subscribe({
        next: (view) => {
          this.saving.set(false);
          this.views.update((views) => [...views, view].sort((a, b) => a.name.localeCompare(b.name)));
          this.active.set(view.id);
          this.close();
          this.toasts.success(view.shared ? `Saved "${view.name}" for the whole team.` : `Saved "${view.name}".`);
        },
        error: (err) => {
          this.saving.set(false);
          this.toasts.error(apiErrorMessage(err, 'Could not save this view.'));
        },
      });
  }

  remove(view: SavedView, event: Event): void {
    event.stopPropagation();
    this.surface.deleteView(view.id).subscribe({
      next: () => {
        this.views.update((views) => views.filter((v) => v.id !== view.id));
        if (this.active() === view.id) this.active.set(null);
      },
      error: (err) => this.toasts.error(apiErrorMessage(err, 'Could not delete this view.')),
    });
  }

  private load(orgId: string): void {
    this.surface.listViews(orgId, this.page()).subscribe({
      next: (views) => this.views.set(views),
      error: () => this.views.set([]),
    });
  }
}
