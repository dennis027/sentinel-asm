import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-account-settings',
  imports: [FormsModule],
  templateUrl: './account-settings.html',
  styleUrl: './account-settings.scss',
})
export class AccountSettings {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  readonly currentPassword = signal('');
  readonly newPassword = signal('');
  readonly confirmPassword = signal('');
  readonly isSubmitting = signal(false);
  readonly errorMessage = signal<string | null>(null);

  submit(): void {
    if (this.isSubmitting()) return;

    if (this.newPassword() !== this.confirmPassword()) {
      this.errorMessage.set('New passwords do not match.');
      return;
    }
    if (!this.currentPassword() || !this.newPassword()) {
      this.errorMessage.set('All fields are required.');
      return;
    }

    this.isSubmitting.set(true);
    this.errorMessage.set(null);

    this.auth.changePassword(this.currentPassword(), this.newPassword()).subscribe({
      next: () => {
        // The backend blacklists EVERY session on a successful change,
        // including the one making this request -- the current access
        // token stays technically valid until its own short expiry,
        // but the refresh token behind it is already dead. Force a
        // clean re-login now rather than let the user hit a confusing
        // silent-refresh failure later.
        this.auth.clearSession();
        this.router.navigate(['/login'], {
          queryParams: { message: 'Password changed. Please sign in again.' },
        });
      },
      error: (err) => {
        this.isSubmitting.set(false);
        if (err.status === 400 && err.error?.current_password) {
          this.errorMessage.set('Incorrect current password.');
        } else if (err.status === 400 && err.error?.new_password) {
          this.errorMessage.set(err.error.new_password.join(' '));
        } else {
          this.errorMessage.set('Could not change password. Please try again.');
        }
      },
    });
  }
}