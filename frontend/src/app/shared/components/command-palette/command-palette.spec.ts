import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { environment } from '../../../../environments/environment';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { SearchService } from '../../../core/services/search.service';
import { makeFinding, makeOrganization, page, provideAppTesting } from '../../../testing/test-helpers';

import { CommandPalette } from './command-palette';

const API = environment.apiBaseUrl;

describe('CommandPalette', () => {
  let fixture: ComponentFixture<CommandPalette>;
  let el: HTMLElement;
  let http: HttpTestingController;
  let router: Router;

  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [CommandPalette], providers: [provideAppTesting()] }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    router = TestBed.inject(Router);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));
    fixture = TestBed.createComponent(CommandPalette);
    el = fixture.nativeElement;
    fixture.detectChanges();
  });

  afterEach(() => http.verify());

  function press(key: string, ctrl = false): void {
    document.dispatchEvent(new KeyboardEvent('keydown', { key, ctrlKey: ctrl }));
    fixture.detectChanges();
  }

  function labels(): string[] {
    return Array.from(el.querySelectorAll('.result .label')).map((l) => l.textContent?.trim() ?? '');
  }

  it('opens with Ctrl+K and lists pages', () => {
    expect(el.querySelector('.palette')).toBeNull();
    press('k', true);
    expect(el.querySelector('.palette')).not.toBeNull();
    expect(labels()).toContain('Attack surface map');
  });

  it('narrows pages by keyword and opens the highlighted one with Enter', () => {
    const navigate = spyOn(router, 'navigateByUrl').and.resolveTo(true);
    TestBed.inject(SearchService).open();
    fixture.detectChanges();
    const component = fixture.componentInstance;
    component.onInput('owasp');
    fixture.detectChanges();
    expect(labels()).toEqual(['Compliance']);
    component.onKey(new KeyboardEvent('keydown', { key: 'Enter' }));
    expect(navigate).toHaveBeenCalledWith('/compliance');
    expect(TestBed.inject(SearchService).isOpen()).toBeFalse();
  });

  it('finds hosts and issues as you type', async () => {
    TestBed.inject(SearchService).open();
    fixture.detectChanges();
    fixture.componentInstance.onInput('staging');
    await new Promise((resolve) => setTimeout(resolve, 250));
    http.expectOne((r) => r.url === `${API}/assets/`).flush(page([{ id: 'a1', value: 'staging.acme.com', risk_grade: 'D' }]));
    const issues = http.expectOne((r) => r.url === `${API}/findings/`);
    expect(issues.request.params.get('search')).toBe('staging');
    issues.flush(page([makeFinding({ title: 'Open port 3389/tcp', asset_value: 'staging.acme.com' })]));
    fixture.detectChanges();
    expect(labels()).toEqual(['staging.acme.com', 'Open port 3389/tcp']);
    expect(Array.from(el.querySelectorAll('.group')).map((g) => g.textContent)).toEqual(['Assets', 'Issues']);
  });

  it('closes with Escape', () => {
    TestBed.inject(SearchService).open();
    fixture.detectChanges();
    fixture.componentInstance.onKey(new KeyboardEvent('keydown', { key: 'Escape' }));
    fixture.detectChanges();
    expect(el.querySelector('.palette')).toBeNull();
  });
});
