import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AccountService } from '../../core/services/account.service';
import { AuthCard } from '../../shared/components/auth-card/auth-card';

/**
 * "Forgot your password?": asks for the email address and always gives
 * the same answer, so the page can't be used to find out who has an account.
 */
@Component({
  selector: 'app-forgot-password',
  imports: [FormsModule, RouterLink, AuthCard],
  template: `
    <app-auth-card heading="Reset your password">
      @if (sent()) {
        <p class="note" role="status">{{ sent() }}</p>
        <p class="muted">Didn't get it? Check spam, or ask again in a few minutes. Your organization's admin can also help.</p>
        <a class="btn block" routerLink="/login">Back to sign in</a>
      } @else {
        <p class="muted">Enter the email address of your account and we'll send you a link to choose a new password.</p>
        <form (ngSubmit)="submit()">
          <label for="email">Email address</label>
          <input id="email" name="email" type="email" autocomplete="email" required
                 [ngModel]="email()" (ngModelChange)="email.set($event)" />
          @if (error()) {
            <p class="error" role="alert">{{ error() }}</p>
          }
          <button class="btn block" type="submit" [disabled]="busy() || !email().includes('@')">
            {{ busy() ? 'Sending…' : 'Send reset link' }}
          </button>
        </form>
        <p class="alt"><a routerLink="/login">Back to sign in</a></p>
      }
    </app-auth-card>
  `,
  styles: `
    form { display: flex; flex-direction: column; gap: var(--space-2); margin-top: var(--space-3); }
    .btn.block { width: 100%; margin-top: var(--space-2); text-align: center; }
    .note { padding: var(--space-3); border-radius: var(--radius-sm); background: var(--color-success-bg); color: var(--color-success); }
    .error { color: var(--color-danger); margin: 0; }
    .alt { margin-top: var(--space-4); font-size: 13.5px; }
  `,
})
export class ForgotPassword {
  private readonly account = inject(AccountService);

  readonly email = signal('');
  readonly busy = signal(false);
  readonly sent = signal<string | null>(null);
  readonly error = signal<string | null>(null);

  submit(): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    this.account.requestPasswordReset(this.email().trim()).subscribe({
      next: (r) => {
        this.busy.set(false);
        this.sent.set(r.detail);
      },
      error: (err) => {
        this.busy.set(false);
        this.error.set(
          err.status === 429 ? 'Too many requests. Wait a while and try again.' : 'Enter a valid email address.',
        );
      },
    });
  }
}
