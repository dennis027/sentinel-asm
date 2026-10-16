import { Component, computed, input, output } from '@angular/core';
import { PAGE_SIZE } from '../../../core/models/models';

/**
 * Previous/next controls for a paginated list. Renders nothing when
 * everything fits on one page.
 */
@Component({
  selector: 'app-pager',
  templateUrl: './pager.html',
  styleUrl: './pager.scss',
})
export class Pager {
  readonly page = input.required<number>();
  readonly count = input.required<number>();
  readonly pageSize = input(PAGE_SIZE);
  readonly pageChange = output<number>();

  readonly totalPages = computed(() => Math.max(1, Math.ceil(this.count() / this.pageSize())));
}
