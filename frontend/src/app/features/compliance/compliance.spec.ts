import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { Compliance } from './compliance';

const API = environment.apiBaseUrl;

describe('Compliance', () => {
  let fixture: ComponentFixture<Compliance>;
  let el: HTMLElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [Compliance], providers: [provideAppTesting()] }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));
    fixture = TestBed.createComponent(Compliance);
    el = fixture.nativeElement;
    fixture.detectChanges();
    http.expectOne(`${API}/organizations/org-1/compliance/`).flush({
      disclaimer: 'An indicative mapping, not a compliance assessment.',
      frameworks: [
        {
          id: 'owasp',
          name: 'OWASP Top 10 (2021)',
          controls_with_issues: 1,
          controls: [
            { id: 'owasp:A02', code: 'A02', name: 'Cryptographic Failures', open_issues: 0, checks: 3, inventory_only: false },
            { id: 'owasp:A05', code: 'A05', name: 'Security Misconfiguration', open_issues: 4, checks: 5, inventory_only: false },
          ],
        },
        { id: 'cis', name: 'CIS Critical Security Controls v8', controls_with_issues: 0, controls: [
          { id: 'cis:1.1', code: '1.1', name: 'Asset inventory', open_issues: 0, checks: 1, inventory_only: true },
        ] },
      ],
    });
    fixture.detectChanges();
  });

  it('summarises each framework and lists its controls with their status', () => {
    const cards = Array.from(el.querySelectorAll('.framework-card')).map((c) => c.textContent);
    expect(cards[0]).toContain('1 / 2');
    expect(cards[0]).toContain('controls with open issues');
    expect(cards[1]).toContain('Clear');
    const rows = Array.from(el.querySelectorAll('tbody tr')).map((r) => r.textContent ?? '');
    expect(rows[0]).toContain('No open issues');
    expect(rows[1]).toContain('4 open');
    expect(el.querySelector('.disclaimer')?.textContent).toContain('not a compliance assessment');
  });

  it('links a control to the issues behind it', () => {
    const link = el.querySelector('tbody a') as HTMLAnchorElement;
    expect(link.getAttribute('href')).toContain('control=owasp:A05');
  });

  it('switches framework', () => {
    (el.querySelectorAll('.framework-card')[1] as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('tbody')?.textContent).toContain('Inventory kept');
  });
});
