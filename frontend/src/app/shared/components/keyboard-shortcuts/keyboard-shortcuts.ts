import { Component, HostListener, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { SearchService } from '../../../core/services/search.service';

// "g" then one of these keys, within a second.
const JUMPS: { key: string; path: string; label: string }[] = [
  { key: 'd', path: '/dashboard', label: 'Dashboard' },
  { key: 'p', path: '/fix-plan', label: 'Fix plan' },
  { key: 'm', path: '/my-work', label: 'My work' },
  { key: 'f', path: '/findings', label: 'Findings' },
  { key: 'a', path: '/assets', label: 'Assets' },
  { key: 'i', path: '/inventory', label: 'Inventory' },
  { key: 'c', path: '/compliance', label: 'Compliance' },
  { key: 's', path: '/scanners', label: 'Scanners' },
  { key: 'l', path: '/logs', label: 'Logs' },
  { key: 'b', path: '/board', label: 'Board view' },
];
const PREFIX_WINDOW_MS = 1000;

/**
 * Keyboard navigation for people who live in the tool: "g" then a
 * letter jumps to a page, "/" searches, "?" shows this list. Ignored
 * while typing in a field.
 */
@Component({
  selector: 'app-keyboard-shortcuts',
  templateUrl: './keyboard-shortcuts.html',
  styleUrl: './keyboard-shortcuts.scss',
})
export class KeyboardShortcuts {
  private readonly router = inject(Router);
  private readonly search = inject(SearchService);
  private prefixAt = 0;

  protected readonly jumps = JUMPS;
  readonly isHelpOpen = signal(false);

  @HostListener('document:keydown', ['$event'])
  onKeydown(event: KeyboardEvent): void {
    if (event.ctrlKey || event.metaKey || event.altKey || this.isTyping(event) || this.search.isOpen()) return;

    if (event.key === 'Escape' && this.isHelpOpen()) {
      this.isHelpOpen.set(false);
      return;
    }
    if (event.key === '?') {
      event.preventDefault();
      this.isHelpOpen.update((open) => !open);
      return;
    }
    if (event.key === '/') {
      event.preventDefault();
      this.search.open();
      return;
    }
    if (event.key === 'g') {
      this.prefixAt = Date.now();
      return;
    }
    if (Date.now() - this.prefixAt < PREFIX_WINDOW_MS) {
      const jump = JUMPS.find((j) => j.key === event.key.toLowerCase());
      this.prefixAt = 0;
      if (jump) {
        event.preventDefault();
        this.isHelpOpen.set(false);
        this.router.navigateByUrl(jump.path);
      }
    }
  }

  private isTyping(event: KeyboardEvent): boolean {
    const target = event.target as HTMLElement | null;
    return !!target && (/^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName) || target.isContentEditable);
  }
}
