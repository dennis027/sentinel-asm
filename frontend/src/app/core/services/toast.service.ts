import { Injectable, signal } from '@angular/core';

export interface Toast {
  id: number;
  kind: 'success' | 'error';
  message: string;
}

const VISIBLE_MS = 5000;

/**
 * Short confirmations ("Scan started") and failures that aren't tied
 * to one spot on the page. Rendered by the Toasts component in the shell.
 */
@Injectable({ providedIn: 'root' })
export class ToastService {
  private nextId = 1;
  readonly toasts = signal<Toast[]>([]);

  success(message: string): void {
    this.show('success', message);
  }

  error(message: string): void {
    this.show('error', message);
  }

  dismiss(id: number): void {
    this.toasts.update((toasts) => toasts.filter((t) => t.id !== id));
  }

  private show(kind: Toast['kind'], message: string): void {
    const id = this.nextId++;
    this.toasts.update((toasts) => [...toasts, { id, kind, message }]);
    setTimeout(() => this.dismiss(id), VISIBLE_MS);
  }
}
