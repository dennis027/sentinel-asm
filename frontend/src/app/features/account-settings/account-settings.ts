import { Component, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { DomSanitizer } from '@angular/platform-browser';
import { Router } from '@angular/router';
import { apiErrorMessage } from '../../core/labels';
import { ApiKey, SignInEvent, TwoFactorSetup } from '../../core/models/models';
import { AccountService, TwoFactorStatus } from '../../core/services/account.service';
import { AuthService } from '../../core/services/auth.service';
import { ConfirmService } from '../../core/services/confirm.service';
import { ToastService } from '../../core/services/toast.service';
import { environment } from '../../../environments/environment';
import { Icon } from '../../shared/components/icon/icon';

/**
 * The signed-in person's own security: password, two-factor sign-in,
 * read-only API keys for integrations, and recent sign-ins (to spot one
 * that wasn't them).
 */
@Component({
  selector: 'app-account-settings',
  imports: [FormsModule, DatePipe, Icon],
  templateUrl: './account-settings.html',
  styleUrl: './account-settings.scss',
})
export class AccountSettings {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly account = inject(AccountService);
  private readonly toasts = inject(ToastService);
  private readonly confirm = inject(ConfirmService);
  private readonly sanitizer = inject(DomSanitizer);
  protected readonly apiBase = environment.apiBaseUrl;

  // --- two-factor sign-in ---
  readonly twoFactor = signal<TwoFactorStatus | null>(null);
  readonly setup = signal<TwoFactorSetup | null>(null);
  // The QR code is an SVG drawn by our own server from the setup secret.
  readonly qrCode = computed(() => {
    const svg = this.setup()?.qr_svg;
    return svg ? this.sanitizer.bypassSecurityTrustHtml(svg) : null;
  });
  readonly code = signal('');
  readonly disablePassword = signal('');
  readonly isTwoFactorBusy = signal(false);
  readonly twoFactorError = signal<string | null>(null);

  // --- API keys ---
  readonly apiKeys = signal<ApiKey[]>([]);
  readonly newKeyName = signal('');
  // Shown once, right after creation.
  readonly createdKey = signal<ApiKey | null>(null);
  readonly isCreatingKey = signal(false);

  // --- sign-ins ---
  readonly signIns = signal<SignInEvent[]>([]);

  constructor() {
    this.account.twoFactorStatus().subscribe({ next: (s) => this.twoFactor.set(s), error: () => undefined });
    this.account.apiKeys().subscribe({ next: (keys) => this.apiKeys.set(keys), error: () => undefined });
    this.account.signIns().subscribe({ next: (events) => this.signIns.set(events), error: () => undefined });
  }

  startTwoFactor(): void {
    this.isTwoFactorBusy.set(true);
    this.twoFactorError.set(null);
    this.account.startTwoFactor().subscribe({
      next: (setup) => {
        this.isTwoFactorBusy.set(false);
        this.setup.set(setup);
        this.code.set('');
      },
      error: (err) => {
        this.isTwoFactorBusy.set(false);
        this.twoFactorError.set(apiErrorMessage(err, 'Could not start the setup.'));
      },
    });
  }

  confirmTwoFactor(): void {
    if (!this.code().trim()) return;
    this.isTwoFactorBusy.set(true);
    this.twoFactorError.set(null);
    this.account.confirmTwoFactor(this.code().trim()).subscribe({
      next: (status) => {
        this.isTwoFactorBusy.set(false);
        this.twoFactor.set(status);
        this.setup.set(null);
        this.toasts.success('Two-factor sign-in is on. You will be asked for a code each time you sign in.');
        this.reloadSignIns();
      },
      error: (err) => {
        this.isTwoFactorBusy.set(false);
        this.twoFactorError.set(apiErrorMessage(err, 'That code was not accepted.'));
      },
    });
  }

  disableTwoFactor(): void {
    this.isTwoFactorBusy.set(true);
    this.twoFactorError.set(null);
    this.account.disableTwoFactor(this.disablePassword()).subscribe({
      next: (status) => {
        this.isTwoFactorBusy.set(false);
        this.twoFactor.set(status);
        this.disablePassword.set('');
        this.toasts.success('Two-factor sign-in is off.');
        this.reloadSignIns();
      },
      error: (err) => {
        this.isTwoFactorBusy.set(false);
        this.twoFactorError.set(apiErrorMessage(err, 'Could not turn it off.'));
      },
    });
  }

  createKey(): void {
    const name = this.newKeyName().trim();
    if (!name || this.isCreatingKey()) return;
    this.isCreatingKey.set(true);
    this.account.createApiKey(name).subscribe({
      next: (key) => {
        this.isCreatingKey.set(false);
        this.newKeyName.set('');
        this.createdKey.set(key);
        this.apiKeys.update((keys) => [{ ...key, key: undefined }, ...keys]);
      },
      error: (err) => {
        this.isCreatingKey.set(false);
        this.toasts.error(apiErrorMessage(err, 'Could not create the key.'));
      },
    });
  }

  copyKey(): void {
    const key = this.createdKey()?.key;
    if (!key) return;
    navigator.clipboard
      ?.writeText(key)
      .then(() => this.toasts.success('Key copied.'))
      .catch(() => this.toasts.error('Could not copy to the clipboard.'));
  }

  async revokeKey(key: ApiKey): Promise<void> {
    const confirmed = await this.confirm.ask({
      title: `Revoke "${key.name}"?`,
      message: 'Anything using this key stops working immediately. This cannot be undone.',
      confirmLabel: 'Revoke key',
      danger: true,
      icon: 'key',
    });
    if (!confirmed) return;
    this.account.revokeApiKey(key.id).subscribe({
      next: () => {
        this.apiKeys.update((keys) => keys.filter((k) => k.id !== key.id));
        if (this.createdKey()?.id === key.id) this.createdKey.set(null);
        this.toasts.success('Key revoked.');
      },
      error: () => this.toasts.error('Could not revoke the key.'),
    });
  }

  /** A short "Chrome on Windows" from a user-agent string. */
  device(userAgent: string): string {
    if (!userAgent) return 'Unknown device';
    const browser = /Edg\//.test(userAgent)
      ? 'Edge'
      : /Chrome\//.test(userAgent)
        ? 'Chrome'
        : /Firefox\//.test(userAgent)
          ? 'Firefox'
          : /Safari\//.test(userAgent)
            ? 'Safari'
            : /curl|python|okhttp|axios/i.test(userAgent)
              ? 'Script'
              : 'Browser';
    const system = /Windows/.test(userAgent)
      ? 'Windows'
      : /Mac OS X/.test(userAgent)
        ? 'macOS'
        : /Android/.test(userAgent)
          ? 'Android'
          : /iPhone|iPad/.test(userAgent)
            ? 'iOS'
            : /Linux/.test(userAgent)
              ? 'Linux'
              : '';
    return system ? `${browser} on ${system}` : browser;
  }

  private reloadSignIns(): void {
    this.account.signIns().subscribe({ next: (events) => this.signIns.set(events), error: () => undefined });
  }

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