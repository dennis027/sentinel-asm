import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AccountService } from '../../core/services/account.service';
import { AuthCard } from '../../shared/components/auth-card/auth-card';

/** The emailed link: choose a new password. The link works once and expires in an hour. */
@Component({
  selector: 'app-reset-password',
  imports: [FormsModule, RouterLink, AuthCard],
  template: `
    <app-auth-card heading="Choose a new password">
      @if (linkProblem()) {
        <p class="error" role="alert">{{ linkProblem() }}</p>
        <a class="btn block" routerLink="/forgot-password">Ask for a new link</a>
      } @else {
        <p class="muted">At least 8 characters, not a common password, and not too close to your username or email.
          Every device signed in to your account will be signed out.</p>
        <form (ngSubmit)="submit()">
          <label for="password">New password</label>
          <input id="password" name="password" type="password" autocomplete="new-password"
                 [ngModel]="password()" (ngModelChange)="password.set($event)" />
          <label for="confirm">Type it again</label>
          <input id="confirm" name="confirm" type="password" autocomplete="new-password"
                 [ngModel]="confirm()" (ngModelChange)="confirm.set($event)" />
          @if (mismatch()) {
            <p class="error">The two passwords don't match.</p>
          }
          @for (e of errors(); track e) {
            <p class="error" role="alert">{{ e }}</p>
          }
          <button class="btn block" type="submit" [disabled]="busy() || !password() || mismatch()">
            {{ busy() ? 'Saving…' : 'Set new password' }}
          </button>
        </form>
      }
    </app-auth-card>
  `,
  styles: `
    form { display: flex; flex-direction: column; gap: var(--space-2); margin-top: var(--space-3); }
    .btn.block { width: 100%; margin-top: var(--space-2); text-align: center; }
    .error { color: var(--color-danger); margin: 0; }
  `,
})
export class ResetPassword {
  private readonly account = inject(AccountService);
  private readonly router = inject(Router);
  private readonly params = inject(ActivatedRoute).snapshot.paramMap;

  readonly password = signal('');
  readonly confirm = signal('');
  readonly busy = signal(false);
  readonly errors = signal<string[]>([]);
  readonly linkProblem = signal<string | null>(null);
  readonly mismatch = computed(() => !!this.confirm() && this.confirm() !== this.password());

  submit(): void {
    if (this.busy() || this.mismatch()) return;
    this.busy.set(true);
    this.errors.set([]);
    this.account
      .confirmPasswordReset(this.params.get('uid') ?? '', this.params.get('token') ?? '', this.password())
      .subscribe({
        next: () =>
          this.router.navigate(['/login'], {
            queryParams: { message: 'Your password was changed. Sign in with the new one.' },
          }),
        error: (err) => {
          this.busy.set(false);
          if (err.error?.token) this.linkProblem.set(err.error.token[0]);
          else if (err.status === 429) this.errors.set(['Too many attempts. Wait a while and try again.']);
          else this.errors.set(err.error?.new_password ?? ['Could not change the password.']);
        },
      });
  }
}
