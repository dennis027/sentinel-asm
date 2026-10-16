import { Injectable, signal } from '@angular/core';
import { IconName } from '../../shared/components/icon/icon';

export interface ConfirmRequest {
  title: string;
  // One or more short paragraphs under the title.
  message: string | string[];
  // The label on the button that goes ahead, e.g. "Run scan". Say what it does, not "OK".
  confirmLabel: string;
  cancelLabel?: string;
  // Red confirm button, for things that delete or cannot be undone.
  danger?: boolean;
  icon?: IconName;
}

/**
 * "Are you sure?" in the app's own style, replacing the browser's
 * built-in confirm() box. Call ask() and await the answer; the dialog
 * itself is drawn once, by ConfirmDialog in the shell.
 *
 *   if (!(await this.confirm.ask({ title: ..., message: ..., confirmLabel: 'Delete' }))) return;
 */
@Injectable({ providedIn: 'root' })
export class ConfirmService {
  readonly request = signal<ConfirmRequest | null>(null);
  private settle: ((confirmed: boolean) => void) | null = null;

  ask(request: ConfirmRequest): Promise<boolean> {
    // A second question while one is open cancels the first.
    this.settle?.(false);
    this.request.set(request);
    return new Promise<boolean>((resolve) => (this.settle = resolve));
  }

  answer(confirmed: boolean): void {
    const settle = this.settle;
    this.settle = null;
    this.request.set(null);
    settle?.(confirmed);
  }
}
