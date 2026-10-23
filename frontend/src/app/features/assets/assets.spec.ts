import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeAsset, makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { Assets } from './assets';

const API = environment.apiBaseUrl;

describe('Assets', () => {
  let fixture: ComponentFixture<Assets>;
  let http: HttpTestingController;

  beforeEach(async () => {
    localStorage.clear();
    await TestBed.configureTestingModule({
      imports: [Assets],
      providers: [provideAppTesting()],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);

    TestBed.inject(OrganizationContextService).loadOrganizations();
    http
      .expectOne((r) => r.url === `${API}/organizations/`)
      .flush(page([makeOrganization({ id: 'org-1' }), makeOrganization({ id: 'org-2' })]));

    fixture = TestBed.createComponent(Assets);
    fixture.detectChanges();
  });

  afterEach(() => {
    // The team (for owners) and saved views load alongside the list.
    http.match((r) => r.url.endsWith('/members/') || r.url.endsWith('/saved-views/')).forEach((r) => r.flush([]));
    http.verify();
  });

  it('lists only the selected organization\'s assets', () => {
    const request = http.expectOne((r) => r.url === `${API}/assets/`);
    expect(request.request.params.get('organization')).toBe('org-1');
    expect(request.request.params.get('page')).toBe('1');
    request.flush(page([]));
  });

  it('reloads from page 1 when the organization is switched', () => {
    http.expectOne((r) => r.url === `${API}/assets/`).flush(page([], 60));
    fixture.componentInstance.onPageChange(2);
    http.expectOne((r) => r.params.get('page') === '2').flush(page([], 60));

    TestBed.inject(OrganizationContextService).selectOrganization('org-2');
    fixture.detectChanges();

    const request = http.expectOne((r) => r.url === `${API}/assets/`);
    expect(request.request.params.get('organization')).toBe('org-2');
    expect(request.request.params.get('page')).toBe('1');
    request.flush(page([]));
  });

  it('adds a host by hand and shows the server\'s reason when it is refused', () => {
    http.expectOne((r) => r.url === `${API}/assets/`).flush(page([]));
    const component = fixture.componentInstance;
    component.startAdding();
    component.newHost.set('evil.com');
    component.addAsset();
    const refused = http.expectOne((r) => r.method === 'POST' && r.url === `${API}/assets/`);
    expect(refused.request.body).toEqual({ organization: 'org-1', value: 'evil.com' });
    refused.flush({ value: ['Assets must be acme.com or a name under it.'] }, { status: 400, statusText: 'Bad Request' });
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.add-asset .error').textContent).toContain('must be acme.com');

    component.newHost.set('vpn.acme.com');
    component.addAsset();
    http.expectOne((r) => r.method === 'POST' && r.url === `${API}/assets/`).flush({ id: 'a9', value: 'vpn.acme.com' });
    http.expectOne((r) => r.method === 'GET' && r.url === `${API}/assets/`).flush(page([]));
    expect(component.isAdding()).toBeFalse();
  });

  it('searches with the query language and opens a host in the side panel', async () => {
    http.expectOne((r) => r.url === `${API}/assets/`).flush(page([
      makeAsset({ id: 'a1', value: 'shop.acme.com', web: { status: 301, final_url: 'https://www.acme.com/' },
        hosting: { provider: 'AWS', ips: ['198.51.100.1'], checked_at: 'x' }, owner_name: 'brian' }),
    ]));
    fixture.detectChanges();
    const root: HTMLElement = fixture.nativeElement;
    const row = root.querySelector('tbody tr') as HTMLElement;
    expect(row.textContent).toContain('301 →');
    expect(row.textContent).toContain('AWS');
    expect(row.textContent).toContain('brian');

    const search = root.querySelector('.search input') as HTMLInputElement;
    search.value = 'provider:aws tech:nginx';
    search.dispatchEvent(new Event('input'));
    await new Promise((resolve) => setTimeout(resolve, 350));
    const searched = http.expectOne((r) => r.url === `${API}/assets/`);
    expect(searched.request.params.get('q')).toBe('provider:aws tech:nginx');
    searched.flush(page([makeAsset({ id: 'a1', value: 'shop.acme.com' })]));
    fixture.detectChanges();

    (root.querySelector('tbody tr td:nth-child(2)') as HTMLElement).click();
    fixture.detectChanges();
    http.expectOne((r) => r.url === `${API}/findings/` && r.params.get('asset') === 'a1').flush(page([]));
    fixture.detectChanges();
    expect(root.querySelector('app-asset-peek h2')?.textContent).toContain('shop.acme.com');
    expect(root.querySelector('app-asset-peek')?.textContent).toContain('Nothing open on this host');
  });
});
