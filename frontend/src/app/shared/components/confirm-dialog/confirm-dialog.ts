import { Component, ElementRef, HostListener, computed, effect, inject, viewChild } from '@angular/core';
import { ConfirmService } from '../../../core/services/confirm.service';
import { Icon } from '../icon/icon';

/**
 * The one confirmation dialog for the whole app; shows whatever
 * ConfirmService is currently asking. Escape or a click outside
 * cancels. Focus starts on the safe choice: Cancel for destructive
 * actions, the confirm button otherwise.
 */
@Component({
  selector: 'app-confirm-dialog',
  imports: [Icon],
  templateUrl: './confirm-dialog.html',
  styleUrl: './confirm-dialog.scss',
})
export class ConfirmDialog {
  protected readonly confirm = inject(ConfirmService);

  private readonly cancelButton = viewChild<ElementRef<HTMLButtonElement>>('cancelButton');
  private readonly confirmButton = viewChild<ElementRef<HTMLButtonElement>>('confirmButton');
  // What had focus before the dialog opened, to hand it back afterwards.
  private returnFocusTo: HTMLElement | null = null;

  protected readonly paragraphs = computed(() => {
    const message = this.confirm.request()?.message ?? [];
    return Array.isArray(message) ? message : [message];
  });

  constructor() {
    effect(() => {
      const request = this.confirm.request();
      if (request) {
        this.returnFocusTo = document.activeElement instanceof HTMLElement ? document.activeElement : null;
        const first = request.danger ? this.cancelButton() : this.confirmButton();
        first?.nativeElement.focus();
      } else {
        this.returnFocusTo?.focus();
        this.returnFocusTo = null;
      }
    });
  }

  @HostListener('document:keydown.escape')
  onEscape(): void {
    if (this.confirm.request()) this.confirm.answer(false);
  }

  /** Keeps Tab inside the dialog while it is open. */
  onTab(event: Event): void {
    const buttons = [this.cancelButton()?.nativeElement, this.confirmButton()?.nativeElement];
    const [first, last] = buttons;
    if (!first || !last || !(event instanceof KeyboardEvent)) return;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }
}
