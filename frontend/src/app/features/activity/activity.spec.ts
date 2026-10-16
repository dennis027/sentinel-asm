import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { Activity } from './activity';

const API = environment.apiBaseUrl;

describe('Activity', () => {
  it('lists who did what, newest first', async () => {
    await TestBed.configureTestingModule({ imports: [Activity], providers: [provideAppTesting()] }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));
    const fixture: ComponentFixture<Activity> = TestBed.createComponent(Activity);
    fixture.detectChanges();
    http.expectOne((r) => r.url === `${API}/organizations/org-1/activity/`).flush(
      page([
        { id: 'e1', actor: 'amina', verb: 'finding_triaged', summary: "Marked 'Open port 21' as risk accepted", created_at: '2026-10-10T10:00:00Z' },
        { id: 'e2', actor: 'brian', verb: 'scan_started', summary: 'Started Port scan on all 46 assets', created_at: '2026-10-09T10:00:00Z' },
      ]),
    );
    fixture.detectChanges();
    const items = Array.from(fixture.nativeElement.querySelectorAll('.timeline li')).map((li) => (li as HTMLElement).textContent ?? '');
    expect(items.length).toBe(2);
    expect(items[0]).toContain("Marked 'Open port 21' as risk accepted");
    expect(items[0]).toContain('amina');
  });
});
