import { DOCUMENT } from '@angular/common';
import { Injectable, inject, signal } from '@angular/core';

export type ThemePreference = 'system' | 'light' | 'dark';

const THEME_KEY = 'sentinel_theme';

/**
 * Light / dark / follow-the-system. The choice is stored per browser
 * and applied as a data-theme attribute on <html>; styles.scss defines
 * the colour tokens for each. "system" removes the attribute so the
 * prefers-color-scheme media query decides.
 *
 * index.html applies the stored choice before the app boots, so a dark
 * page doesn't flash white while loading.
 */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly root = inject(DOCUMENT).documentElement;

  readonly preference = signal<ThemePreference>(this.stored());

  constructor() {
    this.apply(this.preference());
  }

  set(preference: ThemePreference): void {
    this.preference.set(preference);
    localStorage.setItem(THEME_KEY, preference);
    this.apply(preference);
  }

  private apply(preference: ThemePreference): void {
    if (preference === 'system') {
      this.root.removeAttribute('data-theme');
    } else {
      this.root.setAttribute('data-theme', preference);
    }
  }

  private stored(): ThemePreference {
    const value = localStorage.getItem(THEME_KEY);
    return value === 'light' || value === 'dark' ? value : 'system';
  }
}
