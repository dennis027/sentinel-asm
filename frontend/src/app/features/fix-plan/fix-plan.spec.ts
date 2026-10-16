import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { FixPlan } from '../../core/models/models';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { FixPlanPage } from './fix-plan';

const API = environment.apiBaseUrl;

const PLAN: FixPlan = {
  current_score: 69,
  current_grade: 'C',
  open_issues: 4,
  steps: [
    {
      action: 'Database dump is publicly downloadable',
      finding_type: 'exposed_file',
      severity: 'critical',
      remediation: 'Remove the file.',
      issues: 1,
      hosts: 1,
      crown_jewels: 0,
      overdue: 1,
      items: [{ finding: 'f1', asset: 'a1', asset_value: 'db.acme.com', title: 'Database dump', severity: 'critical' }],
      score_after: 84,
      grade_after: 'B',
    },
    {
      action: 'Add the Strict-Transport-Security header',
      finding_type: 'missing_header',
      severity: 'medium',
      remediation: 'Send HSTS.',
      issues: 3,
      hosts: 3,
      crown_jewels: 1,
      overdue: 0,
      items: [
        { finding: 'f2', asset: 'a2', asset_value: 'pay.acme.com', title: 'Missing HSTS', severity: 'medium' },
        { finding: 'f3', asset: 'a3', asset_value: 'www.acme.com', title: 'Missing HSTS', severity: 'medium' },
      ],
      score_after: 96,
      grade_after: 'A+',
    },
  ],
};

describe('FixPlanPage', () => {
  let fixture: ComponentFixture<FixPlanPage>;
  let http: HttpTestingController;
  let el: HTMLElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [FixPlanPage], providers: [provideAppTesting()] }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));
    fixture = TestBed.createComponent(FixPlanPage);
    el = fixture.nativeElement;
    fixture.detectChanges();
    http.expectOne(`${API}/organizations/org-1/fix-plan/`).flush(PLAN);
    http.expectOne(`${API}/organizations/org-1/members/`).flush([
      { id: 'm1', user_id: 7, username: 'brian', email: '', role: 'analyst', created_at: '' },
    ]);
    fixture.detectChanges();
  });

  afterEach(() => http.verify());

  it('shows the grade today and what each fix gets you', () => {
    expect(el.querySelector('.now .grade')?.textContent?.trim()).toBe('C');
    const milestones = Array.from(el.querySelectorAll('.milestones li')).map((li) => li.textContent?.replace(/\s+/g, ' '));
    expect(milestones[0]).toContain('Fix step 1 and the grade becomes B');
    expect(milestones[1]).toContain('Fix steps 1–2 and the grade becomes A+');
    const steps = el.querySelectorAll('.step');
    expect(steps.length).toBe(2);
    expect(steps[0].textContent).toContain('1 overdue');
    expect(steps[1].textContent).toContain('3 issues on 3 hosts');
    expect(steps[1].textContent).toContain('Crown jewel');
  });

  it('lists the hosts a step covers, linking to each issue', () => {
    (el.querySelectorAll('.step-actions .btn')[1] as HTMLButtonElement).click();
    fixture.detectChanges();
    const links = Array.from(el.querySelectorAll('.items a.issue')).map((a) => a.getAttribute('href'));
    expect(links).toEqual(['/findings/f2', '/findings/f3']);
  });

  it('assigns every issue in a step to one person', () => {
    const select = el.querySelectorAll('select.assign')[1] as HTMLSelectElement;
    select.value = '7';
    select.dispatchEvent(new Event('change'));
    const request = http.expectOne(`${API}/findings/bulk/`);
    expect(request.request.body).toEqual({ ids: ['f2', 'f3'], action: 'assign', assignee: 7 });
    request.flush({ updated: 2 });
  });
});
