import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { Board } from './board';

const API = environment.apiBaseUrl;
const ORG = `${API}/organizations/org-1`;

describe('Board', () => {
  let fixture: ComponentFixture<Board>;
  let http: HttpTestingController;
  let el: HTMLElement;

  beforeEach(async () => {
    localStorage.clear();
    await TestBed.configureTestingModule({ imports: [Board], providers: [provideAppTesting()] }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(Board);
    el = fixture.nativeElement;
    fixture.detectChanges();
    // Opened directly, so it loads the organizations itself.
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization({ name: 'Acme Retail' })]));
    fixture.detectChanges();
    http.expectOne(`${ORG}/risk-summary/`).flush({
      organization: 'Acme Retail',
      asset_count: 46,
      assets_at_risk: 21,
      average_risk_score: 69,
      average_risk_grade: 'C',
      grade_distribution: {},
      active_findings_by_severity: { critical: 3, high: 7, medium: 12, low: 5, info: 0 },
      worst_assets: [],
      remediation: { overdue: 7, unassigned_critical_high: 4, assigned: 9, fixed_last_90_days: 9, mean_days_to_fix: 28, sla_days: {} },
      narrative: ['Acme Retail has 46 internet-facing assets.', 'Overall risk is graded C.'],
    });
    http.expectOne((r) => r.url === `${ORG}/trend/`).flush({ days: 90, points: [] });
    http.expectOne(`${ORG}/fix-plan/`).flush({
      current_score: 69,
      current_grade: 'C',
      open_issues: 27,
      steps: [1, 2, 3, 4].map((n) => ({
        action: `Fix ${n}`, finding_type: 'open_port', severity: 'high', remediation: '', issues: 1, hosts: 1,
        crown_jewels: 0, overdue: 0, items: [], score_after: 70 + n, grade_after: 'B',
      })),
    });
    http.expectOne((r) => r.url === `${ORG}/changes/`).flush({
      days: 7, since: '', new_assets: { count: 0, items: [] },
      new_issues: { count: 13, by_severity: {}, items: [] }, resolved_issues: { count: 2, items: [] },
    });
    fixture.detectChanges();
  });

  afterEach(() => {
    http.verify();
    fixture.destroy();
  });

  it('shows the grade, the story and the headline numbers in big type', () => {
    expect(el.querySelector('.org')?.textContent).toContain('Acme Retail');
    expect(el.querySelector('.letter')?.textContent?.trim()).toBe('C');
    expect(el.querySelector('.narrative')?.textContent).toContain('Overall risk is graded C.');
    const tiles = Array.from(el.querySelectorAll('.tile')).map(
      (t) => `${t.querySelector('.n')?.textContent?.trim()} ${t.querySelector('.l')?.textContent?.trim()}`,
    );
    expect(tiles).toContain('10 Critical or high open');
    expect(tiles).toContain('7 Past their fix-by date');
    expect(tiles).toContain('+13 New issues this week');
  });

  it('lists only the next three fixes', () => {
    expect(Array.from(el.querySelectorAll('.fixes .what')).map((w) => w.textContent)).toEqual(['Fix 1', 'Fix 2', 'Fix 3']);
  });
});
