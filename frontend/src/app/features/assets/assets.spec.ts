import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

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

  afterEach(() => http.verify());

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
});
