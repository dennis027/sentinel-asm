import { Component, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { LogoMark } from '../logo-mark/logo-mark';
import { ThemeSwitch } from '../theme-switch/theme-switch';

/** The centred card the signed-out pages use: forgot password, reset password, invitations. */
@Component({
  selector: 'app-auth-card',
  imports: [LogoMark, RouterLink, ThemeSwitch],
  template: `
    <div class="auth-page">
      <app-theme-switch class="theme" />
      <main class="card">
        <a class="brand" routerLink="/" aria-label="Densight home">
          <app-logo-mark [size]="30" />
          <span>Den<span class="accent">sight</span></span>
        </a>
        <h1>{{ heading() }}</h1>
        <ng-content />
      </main>
    </div>
  `,
  styles: `
    .auth-page { min-height: 100vh; display: grid; place-items: center; padding: var(--space-5) 16px; background: var(--color-bg); position: relative; }
    .theme { position: absolute; top: var(--space-4); right: var(--space-4); }
    .card { width: 100%; max-width: 420px; }
    .brand { display: inline-flex; align-items: center; gap: var(--space-2); font-weight: 650; font-size: 15px; color: var(--color-text-primary); text-decoration: none; margin-bottom: var(--space-5); }
    .accent { color: var(--color-accent); }
    h1 { margin: 0 0 var(--space-2); font-size: 24px; }
  `,
})
export class AuthCard {
  readonly heading = input.required<string>();
}
