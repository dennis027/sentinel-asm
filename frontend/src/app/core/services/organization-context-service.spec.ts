import { HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { OrgRole, Organization } from '../models/models';
import { makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { OrganizationContextService } from './organization-context-service';

describe('OrganizationContextService', () => {
  let service: OrganizationContextService;
  let http: HttpTestingController;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({ providers: [provideAppTesting()] });
    service = TestBed.inject(OrganizationContextService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  function load(orgs: Organization[]): void {
    service.loadOrganizations();
    http.expectOne((r) => r.url === `${environment.apiBaseUrl}/organizations/`).flush(page(orgs));
  }

  it('selects the first organization when nothing is remembered', () => {
    load([makeOrganization({ id: 'a' }), makeOrganization({ id: 'b' })]);
    expect(service.selectedOrganization()?.id).toBe('a');
    expect(service.isLoaded()).toBeTrue();
  });

  it('keeps a switched selection', () => {
    load([makeOrganization({ id: 'a' }), makeOrganization({ id: 'b' })]);
    service.selectOrganization('b');
    expect(service.selectedOrganization()?.id).toBe('b');
    expect(localStorage.getItem('sentinel_selected_org_id')).toBe('b');
  });

  it('derives what the user may do from their role', () => {
    const expectations: [OrgRole | null, boolean, boolean, boolean][] = [
      // role, scan, triage, manage
      [null, false, false, false],
      ['viewer', false, false, false],
      ['analyst', true, true, false],
      ['admin', true, true, true],
      ['owner', true, true, true],
    ];
    load([makeOrganization({ id: 'a' })]);
    for (const [role, scan, triage, manage] of expectations) {
      service.updateOrganization(makeOrganization({ id: 'a', my_role: role }));
      expect(service.canTriggerScans()).withContext(`${role} scan`).toBe(scan);
      expect(service.canTriageFindings()).withContext(`${role} triage`).toBe(triage);
      expect(service.canManageSettings()).withContext(`${role} manage`).toBe(manage);
    }
  });

  it('updateOrganization replaces only the matching organization', () => {
    load([makeOrganization({ id: 'a', domain_verified: false }), makeOrganization({ id: 'b' })]);
    service.updateOrganization(makeOrganization({ id: 'a', domain_verified: true }));
    expect(service.allOrganizations().map((o) => o.domain_verified)).toEqual([true, true]);
    expect(service.allOrganizations().length).toBe(2);
  });
});
