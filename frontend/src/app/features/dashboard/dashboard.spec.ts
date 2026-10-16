import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeFinding, makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { Dashboard } from './dashboard';

const API = environment.apiBaseUrl;
const ORG = `${API}/organizations/org-1`;

describe('Dashboard', () => {
  let fixture: ComponentFixture<Dashboard>;
  let http: HttpTestingController;
  let el: HTMLElement;

  beforeEach(async () => {
    localStorage.clear();
    await TestBed.configureTestingModule({
      imports: [Dashboard],
      providers: [provideAppTesting()],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);

    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));

    fixture = TestBed.createComponent(Dashboard);
    el = fixture.nativeElement;
    fixture.detectChanges();

    http.expectOne((r) => r.url === `${ORG}/trend/`).flush({
      days: 90,
      points: [
        { date: '2026-07-01', score: 48, grade: 'D', open_issues: 40, critical_high: 12, asset_count: 40 },
        { date: '2026-08-15', score: 70, grade: 'B', open_issues: 25, critical_high: 6, asset_count: 44 },
        { date: '2026-10-01', score: 61, grade: 'C', open_issues: 20, critical_high: 4, asset_count: 46 },
      ],
    });
    http.expectOne(`${ORG}/heatmap/`).flush({
      severities: ['critical', 'high', 'medium', 'low'],
      rows: [
        { finding_type: 'exposed_file', label: 'Exposed sensitive file', counts: { critical: 2, high: 0, medium: 1, low: 0 }, total: 3 },
        { finding_type: 'open_port', label: 'Open port', counts: { critical: 0, high: 4, medium: 0, low: 2 }, total: 6 },
      ],
    });
    http.expectOne((r) => r.url === `${ORG}/changes/`).flush({
      days: 7,
      since: '2026-10-01T00:00:00Z',
      new_assets: { count: 3, items: [{ id: 'a1', value: 'new.acme.com' }] },
      new_issues: {
        count: 2,
        by_severity: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
        items: [{ id: 'f1', title: 'RDP exposed', severity: 'critical', asset: 'a1', asset_value: 'new.acme.com' }],
      },
      resolved_issues: {
        count: 5,
        items: [{ id: 'f2', title: 'Old cert', severity: 'high', asset: 'a2', asset_value: 'www.acme.com' }],
      },
    });
    http.expectOne(`${ORG}/risk-summary/`).flush({
      organization: 'Acme',
      asset_count: 1200,
      assets_at_risk: 4,
      average_risk_score: 61,
      average_risk_grade: 'C',
      grade_distribution: {},
      active_findings_by_severity: { critical: 1, high: 3, medium: 2, low: 0, info: 0 },
      worst_assets: [{ id: 'a1', value: 'new.acme.com', risk_score: 40, risk_grade: 'D', open_findings: 3 }],
      remediation: {
        overdue: 3,
        unassigned_critical_high: 2,
        assigned: 5,
        fixed_last_90_days: 11,
        mean_days_to_fix: 12.5,
        sla_days: { critical: 7, high: 30 },
      },
      narrative: ['Acme has 1,200 internet-facing assets; 4 of them have open issues.', 'Overall risk is graded C.'],
    });
    http.expectOne((r) => r.url === `${API}/assets/`).flush(page([], 1200));
    const findings = http.expectOne((r) => r.url === `${API}/findings/`);
    expect(findings.request.params.get('kind')).toBe('issue');
    findings.flush(page([makeFinding({ title: 'RDP exposed', severity: 'critical' })]));
    fixture.detectChanges();
  });

  afterEach(() => http.verify());

  it('leads with the grade and what it means', () => {
    expect(el.querySelector('.grade')?.textContent?.trim()).toBe('C');
    expect(el.querySelector('.grade-meaning')?.textContent).toContain('Needs attention');
    expect(el.querySelector('.grade-card .hint')?.textContent).toContain('4 assets with open issues');
  });

  it('shows what changed this week', () => {
    const counts = Array.from(el.querySelectorAll('.change-count')).map((n) => n.textContent?.trim());
    expect(counts).toEqual(['3', '2', '5']);
    const text = el.querySelector('.changes')?.textContent ?? '';
    expect(text).toContain('last 7 days');
    expect(text).toContain('new.acme.com');
    expect(text).toContain('RDP exposed');
    expect(text).toContain('Old cert');
  });

  it('downloads the report for the selected organization', () => {
    const click = spyOn(HTMLAnchorElement.prototype, 'click');
    const reportButton = Array.from(el.querySelectorAll('button')).find((b) =>
      b.textContent?.includes('Download report'),
    ) as HTMLButtonElement;
    reportButton.click();

    const request = http.expectOne((r) => r.url === `${ORG}/report/`);
    expect(request.request.responseType).toBe('blob');
    request.flush(new Blob(['%PDF']));
    expect(click).toHaveBeenCalled();
  });

  it('opens with a plain-English summary', () => {
    expect(el.querySelector('.in-short-text')?.textContent).toContain(
      'Acme has 1,200 internet-facing assets; 4 of them have open issues. Overall risk is graded C.',
    );
  });

  it('shows the 90-day trend and how much it moved', () => {
    expect(el.querySelector('app-trend-chart path.line')).not.toBeNull();
    expect(el.querySelector('.delta')?.textContent).toContain('+13 points');
  });

  it('shows remediation figures that link to the work behind them', () => {
    const kpis = Array.from(el.querySelectorAll('.remediation .kpi-value')).map((k) => k.textContent?.trim());
    expect(kpis).toEqual(['3', '2', '12.5 d', '11']);
    const overdue = el.querySelector('.remediation a.kpi') as HTMLAnchorElement;
    expect(overdue.getAttribute('href')).toBe('/findings?overdue=1');
  });

  it('shows where the risk is, each square linking to those findings', () => {
    const cells = Array.from(el.querySelectorAll<HTMLAnchorElement>('app-risk-heatmap a.cell'));
    expect(cells.map((c) => c.textContent?.trim())).toEqual(['2', '1', '4', '2']);
    expect(cells[0].getAttribute('href')).toBe('/findings?type=exposed_file&severity=critical');
    // The busiest cell is the darkest.
    expect(cells[2].classList).toContain('level-4');
  });

  it('shows the grade day by day and links to the board view', () => {
    expect(el.querySelectorAll('app-grade-calendar .day').length).toBeGreaterThan(90);
    expect(el.querySelector('a[href="/board"]')).not.toBeNull();
  });
});
