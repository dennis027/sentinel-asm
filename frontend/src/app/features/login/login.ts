import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-login',
  imports: [FormsModule],
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

  submit(): void {
    if (!this.username() || !this.password() || this.isSubmitting()) return;

    this.isSubmitting.set(true);
    this.errorMessage.set(null);

    this.auth.login(this.username(), this.password()).subscribe({
      next: () => {
        // Redirect-memory: if the user was bounced here from a
        // protected route (or a 401), return them there instead of
        // always landing on the dashboard.
        const redirect = this.route.snapshot.queryParamMap.get('redirect') || '/dashboard';
        this.router.navigateByUrl(redirect);
      },
      error: (err) => {
        this.isSubmitting.set(false);
        this.errorMessage.set(
          err.status === 429
            ? 'Too many attempts. Please wait a minute and try again.'
            : 'Incorrect username or password.',
        );
      },
    });
  }
}