import { LogoMark } from '../../shared/components/logo-mark/logo-mark';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import { Icon } from '../../shared/components/icon/icon';
import { ThemeSwitch } from '../../shared/components/theme-switch/theme-switch';

@Component({
  selector: 'app-login',
  imports: [LogoMark, FormsModule, Icon, RouterLink, ThemeSwitch],
  templateUrl: './login.html',
  styleUrl: './login.scss',
})
export class Login {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  readonly username = signal('');
  readonly password = signal('');
  readonly isSubmitting = signal(false);
  readonly errorMessage = signal<string | null>(null);
  // Second step, when the account has two-factor sign-in on.
  readonly needsCode = signal(false);
  readonly code = signal('');
  
  readonly infoMessage = signal<string | null>(
    this.route.snapshot.queryParamMap.get('message'),
  );

  /** Back to username and password, e.g. to sign in as someone else. */
  startOver(): void {
    this.needsCode.set(false);
    this.code.set('');
    this.password.set('');
    this.errorMessage.set(null);
  }

  submit(): void {
    if (!this.username() || !this.password() || this.isSubmitting()) return;
    if (this.needsCode() && !this.code().trim()) return;

    this.isSubmitting.set(true);
    this.errorMessage.set(null);

    this.auth.login(this.username(), this.password(), this.needsCode() ? this.code().trim() : undefined).subscribe({
      next: () => {
        // Redirect-memory: if the user was bounced here from a
        // protected route (or a 401), return them there instead of
        // always landing on the dashboard.
        const redirect = this.route.snapshot.queryParamMap.get('redirect') || '/dashboard';
        this.router.navigateByUrl(redirect);
      },
      error: (err) => {
        this.isSubmitting.set(false);
        if (err.status === 400 && err.error?.otp_required) {
          // Password was right; now the code from the authenticator app.
          const firstAsk = !this.needsCode();
          this.needsCode.set(true);
          this.code.set('');
          this.errorMessage.set(firstAsk ? null : (err.error.otp?.[0] ?? 'That code is not right.'));
          return;
        }
        this.errorMessage.set(
          err.status === 429
            ? 'Too many attempts. Please wait a minute and try again.'
            : 'Incorrect username or password.',
        );
      },
    });
  }
}