import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { environment } from '../../../environments/environment';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeAsset, makeFinding, makeOrganization, page } from '../../testing/test-helpers';

import { AssetDetail } from './asset-detail';

const API = environment.apiBaseUrl;

describe('AssetDetail', () => {
  let http: HttpTestingController;
  let harness: RouterTestingHarness;
  let el: HTMLElement;

  beforeEach(async () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([{ path: 'assets/:id', component: AssetDetail }])],
    });
    http = TestBed.inject(HttpTestingController);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));
    harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/assets/a1');
    el = harness.routeNativeElement!;
    http.expectOne(`${API}/assets/a1/`).flush(
      makeAsset({ id: 'a1', value: 'pay.acme.com', risk_grade: 'C', criticality: 'crown_jewel', tags: ['payments'] }),
    );
    const notAfter = new Date(Date.now() + 12.5 * 86_400_000).toISOString();
    http.expectOne((r) => r.url === `${API}/findings/`).flush(
      page([
        makeFinding({ id: 'f1', title: 'Open port 3389/tcp', severity: 'high', finding_type: 'open_port',
                      raw_data: { port: '3389', service: 'ms-wbt-server' } }),
        makeFinding({ id: 'f2', title: 'TLS certificate expires in 12 days', severity: 'medium',
                      finding_type: 'expired_ssl', raw_data: { not_after: notAfter } }),
      ]),
    );
    http.expectOne(`${API}/scanners/`).flush([]);
    http.expectOne((r) => r.url === `${API}/scan-jobs/`).flush(page([]));
    harness.detectChanges();
  });

  afterEach(() => {
    // The team, for the Owner picker.
    http.match((r) => r.url.endsWith('/members/')).forEach((r) => r.flush([]));
    http.verify();
  });

  it('shows the host with its importance, issues, ports and certificate', () => {
    expect(el.querySelector('h1')?.textContent).toBe('pay.acme.com');
    expect(el.querySelector('.badges')?.textContent).toContain('Crown jewel');
    expect(el.querySelector('.badges')?.textContent).toContain('payments');
    expect(el.querySelectorAll('.rows li').length).toBe(2);
    expect(el.querySelector('.port')?.textContent).toBe('3389');
    expect(el.textContent).toContain('12 days left');
  });

  it('saves business context', () => {
    const tags = el.querySelector('#tags') as HTMLInputElement;
    tags.value = 'payments, pci';
    tags.dispatchEvent(new Event('input'));
    harness.detectChanges();
    (el.querySelector('.context button') as HTMLButtonElement).click();
    const request = http.expectOne(`${API}/assets/a1/`);
    expect(request.request.method).toBe('PATCH');
    expect(request.request.body).toEqual({ criticality: 'crown_jewel', tags: ['payments', 'pci'], owner: null });
    request.flush(makeAsset({ id: 'a1', criticality: 'crown_jewel', tags: ['payments', 'pci'] }));
  });
});
