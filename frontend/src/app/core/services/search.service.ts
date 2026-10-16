import { Injectable, signal } from '@angular/core';

/** Opens and closes the quick-search palette (Ctrl/Cmd+K) from anywhere. */
@Injectable({ providedIn: 'root' })
export class SearchService {
  readonly isOpen = signal(false);

  open(): void {
    this.isOpen.set(true);
  }

  close(): void {
    this.isOpen.set(false);
  }
}
