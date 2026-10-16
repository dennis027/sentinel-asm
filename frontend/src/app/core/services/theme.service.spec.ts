import { TestBed } from '@angular/core/testing';

import { ThemeService } from './theme.service';

describe('ThemeService', () => {
  const root = document.documentElement;

  afterEach(() => {
    localStorage.clear();
    root.removeAttribute('data-theme');
  });

  it('follows the system until told otherwise', () => {
    localStorage.clear();
    const service = TestBed.inject(ThemeService);
    expect(service.preference()).toBe('system');
    expect(root.hasAttribute('data-theme')).toBeFalse();
  });

  it('applies and remembers an explicit choice', () => {
    const service = TestBed.inject(ThemeService);
    service.set('dark');
    expect(root.getAttribute('data-theme')).toBe('dark');
    expect(localStorage.getItem('sentinel_theme')).toBe('dark');

    service.set('system');
    expect(root.hasAttribute('data-theme')).toBeFalse();
  });

  it('restores the stored choice on start', () => {
    localStorage.setItem('sentinel_theme', 'light');
    const service = TestBed.inject(ThemeService);
    expect(service.preference()).toBe('light');
    expect(root.getAttribute('data-theme')).toBe('light');
  });
});
