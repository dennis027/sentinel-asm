import { Component, input } from '@angular/core';

export type EmptyArt = 'radar' | 'servers' | 'bell' | 'shield' | 'search';

/**
 * "Nothing here" block: a small illustration, a title, and whatever
 * explanation or next step is projected into it. The drawings use the
 * theme's colour tokens, so they follow light and dark mode.
 */
@Component({
  selector: 'app-empty-state',
  templateUrl: './empty-state.html',
  styleUrl: './empty-state.scss',
})
export class EmptyState {
  readonly art = input<EmptyArt>('radar');
  readonly title = input.required<string>();
}
