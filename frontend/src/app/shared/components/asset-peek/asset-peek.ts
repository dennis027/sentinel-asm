import { Component, effect, inject, input, output, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Asset, Finding, Member } from '../../../core/models/models';
import { AssetService } from '../../../core/services/asset-service';
import { FindingService } from '../../../core/services/finding-service';
import { ToastService } from '../../../core/services/toast.service';
import { apiErrorMessage, criticalityLabel, webStatus } from '../../../core/labels';
import { Icon } from '../icon/icon';

/**
 * A side panel with the essentials of one host, opened from a list
 * without leaving it: how it answers on the web, who hosts it, who owns
 * it, what runs on it and its worst open issues.
 */
@Component({
  selector: 'app-asset-peek',
  imports: [DatePipe, FormsModule, RouterLink, Icon],
  templateUrl: './asset-peek.html',
  styleUrl: './asset-peek.scss',
  host: { '(document:keydown.escape)': 'closed.emit()' },
})
export class AssetPeek {
  private readonly findingService = inject(FindingService);
  private readonly assetService = inject(AssetService);
  private readonly toasts = inject(ToastService);

  readonly asset = input.required<Asset>();
  readonly members = input<Member[]>([]);
  readonly canEdit = input(false);
  readonly closed = output<void>();
  readonly changed = output<Asset>();

  readonly issues = signal<Finding[]>([]);
  readonly issueCount = signal(0);
  readonly loadingIssues = signal(true);
  protected readonly criticalityLabel = criticalityLabel;
  protected readonly webStatus = webStatus;

  constructor() {
    effect(() => {
      const id = this.asset().id;
      untracked(() => this.loadIssues(id));
    });
  }

  setOwner(value: string): void {
    const owner = value ? Number(value) : null;
    this.assetService.update(this.asset().id, { owner }).subscribe({
      next: (asset) => {
        this.changed.emit(asset);
        this.toasts.success(owner ? `${asset.owner_name} now owns ${asset.value}. New issues go to them.` : `${asset.value} has no owner now.`);
      },
      error: (err) => this.toasts.error(apiErrorMessage(err, 'Could not change the owner.')),
    });
  }

  private loadIssues(assetId: string): void {
    this.loadingIssues.set(true);
    this.findingService.list({ asset: assetId, kind: 'issue', is_active: true, page_size: 5 }).subscribe({
      next: (page) => {
        this.issues.set(page.results);
        this.issueCount.set(page.count);
        this.loadingIssues.set(false);
      },
      error: () => {
        this.issues.set([]);
        this.loadingIssues.set(false);
      },
    });
  }
}
