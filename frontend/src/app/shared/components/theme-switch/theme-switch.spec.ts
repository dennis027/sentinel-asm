import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ThemeSwitch } from './theme-switch';

describe('ThemeSwitch', () => {
  let fixture: ComponentFixture<ThemeSwitch>;
  let buttons: HTMLButtonElement[];

  beforeEach(async () => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
    await TestBed.configureTestingModule({ imports: [ThemeSwitch] }).compileComponents();
    fixture = TestBed.createComponent(ThemeSwitch);
    fixture.detectChanges();
    buttons = Array.from(fixture.nativeElement.querySelectorAll('button'));
  });

  afterEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
  });

  it('starts on "match system" and switches the page when a theme is picked', () => {
    expect(buttons.map((b) => b.getAttribute('aria-pressed'))).toEqual(['false', 'true', 'false']);

    buttons[2].click();
    fixture.detectChanges();
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(buttons[2].getAttribute('aria-pressed')).toBe('true');

    buttons[0].click();
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
  });
});
