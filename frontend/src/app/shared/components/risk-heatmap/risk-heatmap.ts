import { Component, computed, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { findingTypeLabel } from '../../../core/labels';
import { Heatmap } from '../../../core/models/models';

/**
 * Open issues as a grid: kinds of issue down the side, severity across
 * the top, each cell shaded by how many there are. The darkest corner
 * is where the trouble is. Every cell links to those findings.
 */
@Component({
  selector: 'app-risk-heatmap',
  imports: [RouterLink],
  templateUrl: './risk-heatmap.html',
  styleUrl: './risk-heatmap.scss',
})
export class RiskHeatmap {
  readonly heatmap = input.required<Heatmap>();
  protected readonly typeLabel = findingTypeLabel;

  private readonly max = computed(() =>
    Math.max(1, ...this.heatmap().rows.flatMap((row) => Object.values(row.counts).map((n) => n ?? 0))),
  );

  /** 0 for an empty cell, then 1-4 by share of the busiest cell. */
  level(count: number | undefined): number {
    if (!count) return 0;
    return Math.min(4, Math.ceil((count / this.max()) * 4));
  }
}
