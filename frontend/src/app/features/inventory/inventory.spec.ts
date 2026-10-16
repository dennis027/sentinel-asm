import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { environment } from '../../../environments/environment';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { Inventory } from './inventory';

const API = environment.apiBaseUrl;

describe('Inventory', () => {
  let fixture: ComponentFixture<Inventory>;
  let el: HTMLElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [Inventory], providers: [provideAppTesting()] }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));
    fixture = TestBed.createComponent(Inventory);
    el = fixture.nativeElement;
    fixture.detectChanges();
    const hosts = Array.from({ length: 8 }, (_, i) => ({ id: `a${i}`, value: `store${i}.acme.com` }));
    http.expectOne(`${API}/organizations/org-1/technologies/`).flush([
      { name: 'nginx', version: '1.24.0', category: 'web-server', hosts, host_count: 8 },
      { name: 'WordPress', version: '6.4', category: 'cms', hosts: hosts.slice(0, 1), host_count: 1 },
    ]);
    http.expectOne(`${API}/organizations/org-1/services/`).flush([
      { port: 3389, protocol: 'tcp', service: 'ms-wbt-server', severity: 'high', host_count: 1,
        hosts: [{ id: 'a1', value: 'staging.acme.com', product: '', finding: 'f1', status: 'open' }] },
    ]);
    http.expectOne(`${API}/organizations/org-1/certificates/`).flush([
      { asset: 'a1', asset_value: 'legacy.acme.com', finding: 'f9', not_after: '2026-01-01T00:00:00Z',
        days_remaining: -12, severity: 'critical' },
    ]);
    fixture.detectChanges();
  });

  it('lists software with the hosts it runs on, a few at a time', () => {
    const rows = el.querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);
    expect(rows[0].querySelectorAll('.hosts a').length).toBe(6);
    (rows[0].querySelector('.more') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(rows[0].querySelectorAll('.hosts a').length).toBe(8);
  });

  it('filters by what you type', () => {
    const input = el.querySelector('input[type=search]') as HTMLInputElement;
    input.value = 'wordpress';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(el.querySelectorAll('tbody tr').length).toBe(1);
  });

  it('flags certificates expiring soon and switches tabs', async () => {
    expect(el.querySelector('.n.warn')?.textContent).toContain('1 soon');
    await TestBed.inject(Router).navigate([], { queryParams: { tab: 'certificates' } });
    fixture.detectChanges();
    expect(el.querySelector('tbody')?.textContent).toContain('expired 12 days ago');
  });
});
