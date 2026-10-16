import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../../environments/environment';
import { AuthService } from '../../../core/services/auth.service';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { makeOrganization, page, provideAppTesting } from '../../../testing/test-helpers';

import { ActivityBell } from './activity-bell';

const API = environment.apiBaseUrl;

function event(id: string, summary: string, at: string, actor = 'amina') {
  return { id, actor, verb: 'finding_assigned', summary, created_at: at };
}

describe('ActivityBell', () => {
  let fixture: ComponentFixture<ActivityBell>;
  let http: HttpTestingController;
  let el: HTMLElement;

  beforeEach(async () => {
    localStorage.clear();
    localStorage.setItem('sentinel_username', 'dennis');
    localStorage.setItem('sentinel_activity_seen_org-1', '2026-10-02T00:00:00Z');
    await TestBed.configureTestingModule({ imports: [ActivityBell], providers: [provideAppTesting()] }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    TestBed.inject(AuthService);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));
    fixture = TestBed.createComponent(ActivityBell);
    el = fixture.nativeElement;
    fixture.detectChanges();
    http.expectOne((r) => r.url === `${API}/organizations/org-1/activity/`).flush(
      page([
        event('e3', "Assigned 'RDP open' on staging.acme.com to dennis", '2026-10-05T00:00:00Z'),
        event('e2', 'Started Port scan on all 46 assets', '2026-10-03T00:00:00Z', 'brian'),
        event('e1', 'Added chloe as Viewer', '2026-10-01T00:00:00Z'),
      ]),
    );
    fixture.detectChanges();
  });

  afterEach(() => {
    http.verify();
    fixture.destroy();
  });

  it('counts what is new since you last looked', () => {
    expect(el.querySelector('.count')?.textContent?.trim()).toBe('2');
  });

  it('lists recent activity, marks what names you, and clears the count', () => {
    (el.querySelector('button.bell') as HTMLButtonElement).click();
    http.expectOne((r) => r.url === `${API}/organizations/org-1/activity/`).flush(
      page([event('e3', "Assigned 'RDP open' on staging.acme.com to dennis", '2026-10-05T00:00:00Z')]),
    );
    fixture.detectChanges();
    const items = el.querySelectorAll('li');
    expect(items[0].textContent).toContain('For you');
    expect(items[0].classList).toContain('new');
    expect(localStorage.getItem('sentinel_activity_seen_org-1')).toBe('2026-10-05T00:00:00Z');

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    fixture.detectChanges();
    expect(el.querySelector('.panel-pop')).toBeNull();
    expect(el.querySelector('.count')).toBeNull();
  });
});
