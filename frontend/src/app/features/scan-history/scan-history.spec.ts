import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { ScanJob, ScanRun } from '../../core/models/models';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { ScanHistory } from './scan-history';

const API = environment.apiBaseUrl;

function run(overrides: Partial<ScanRun> = {}): ScanRun {
  return {
    run_id: 'r1', trigger: 'schedule', trigger_label: 'Daily schedule', triggered_by: null, scanner_name: null,
    scanner_label: null, host: null, scanners: 25, hosts: 46, organization_level: true, jobs: 1150, succeeded: 1140,
    failed: 10, skipped: 0, unfinished: 0, new_findings: 3, started: '2026-10-16T02:00:00Z', finished: '2026-10-16T02:14:00Z',
    ...overrides,
  };
}

const JOB = {
  id: 'j1', organization: 'org-1', organization_name: 'Acme', asset: 'a1', asset_value: 'shop.acme.com',
  scanner_name: 'nmap', status: 'success', error_message: '', created_at: '', started_at: null, finished_at: null,
  trigger: 'domain', trigger_label: 'Run scan', triggered_by: 'Amina Otieno', run_id: 'r2',
} as ScanJob;

describe('ScanHistory', () => {
  let fixture: ComponentFixture<ScanHistory>;
  let http: HttpTestingController;
  let el: HTMLElement;

  beforeEach(async () => {
    localStorage.clear();
    await TestBed.configureTestingModule({ imports: [ScanHistory], providers: [provideAppTesting()] }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization({ root_domain: 'acme.com' })]));
    fixture = TestBed.createComponent(ScanHistory);
    el = fixture.nativeElement;
    fixture.detectChanges();
    http.expectOne(`${API}/scanners/`).flush([{ name: 'nmap', label: 'Port scan' }]);
  });

  afterEach(() => http.verify());

  function flushRuns(runs: ScanRun[]): void {
    http.expectOne((r) => r.url === `${API}/scan-jobs/runs/`).flush(page(runs));
    fixture.detectChanges();
  }

  it('groups scans by where they came from', () => {
    flushRuns([
      run({ run_id: 'r3', trigger: 'recheck', trigger_label: 'Re-check of a host', triggered_by: 'Brian Mwangi',
            host: 'shop.acme.com', scanners: 18, hosts: 1, organization_level: false, jobs: 18, succeeded: 18,
            failed: 0, new_findings: 0 }),
      run({ run_id: 'r2', trigger: 'domain', trigger_label: 'Run scan', triggered_by: 'Amina Otieno',
            scanner_name: 'nmap', scanner_label: 'Port scan', scanners: 1, organization_level: false, jobs: 46,
            succeeded: 30, failed: 0, unfinished: 16, new_findings: 0, finished: null }),
      run(),
    ]);
    const titles = Array.from(el.querySelectorAll('.run-title')).map((t) => t.textContent?.trim());
    expect(titles).toEqual(['Re-check of shop.acme.com', 'Port scan on 46 hosts', 'Daily scan of everything']);
    const origins = Array.from(el.querySelectorAll('.run-origin')).map((t) => t.textContent?.trim());
    expect(origins).toEqual(['Started by Brian Mwangi', 'Run scan by Amina Otieno', 'Started automatically by the daily schedule']);
    const runs = el.querySelectorAll('.run');
    expect(runs[1].classList).toContain('busy');
    expect(runs[1].textContent).toContain('30 of 46 done');
    expect(runs[2].textContent).toContain('10 failed');
    expect(runs[2].textContent).toContain('3 new issues');
    expect(runs[2].textContent).toContain('25 scanners on 46 hosts and the domain');
    expect(runs[2].textContent).toContain('took 14 min');
  });

  it('filters by origin and opens a run to its scans', () => {
    flushRuns([run()]);
    const recheck = Array.from(el.querySelectorAll('.origin')).find((b) => b.textContent?.includes('Re-checks')) as HTMLButtonElement;
    recheck.click();
    const filtered = http.expectOne((r) => r.url === `${API}/scan-jobs/runs/`);
    expect(filtered.request.params.get('trigger')).toBe('recheck');
    filtered.flush(page([run({ run_id: 'r3', trigger: 'recheck', host: 'shop.acme.com' })]));
    fixture.detectChanges();

    (el.querySelector('.run-head') as HTMLButtonElement).click();
    const jobs = http.expectOne((r) => r.url === `${API}/scan-jobs/`);
    expect(jobs.request.params.get('run_id')).toBe('r3');
    jobs.flush(page([JOB]));
    http.expectOne((r) => r.url === `${API}/scan-jobs/reasons/` && r.params.get('run_id') === 'r3').flush([
      { status: 'skipped', reason: "the host doesn't resolve in DNS", count: 7, scanners: ['Port scan'], hosts: ['old.acme.com'] },
    ]);
    fixture.detectChanges();
    expect(el.querySelector('.run-jobs')?.textContent).toContain('Port scan');
    expect(el.querySelector('.run-jobs')?.textContent).toContain('shop.acme.com');
    const reasons = el.querySelector('.reasons')?.textContent ?? '';
    expect(reasons).toContain('7×');
    expect(reasons).toContain("the host doesn't resolve in DNS");
    expect(reasons).toContain('Skipped');
  });

  it('can still show every scan, with where each came from', () => {
    flushRuns([]);
    const every = Array.from(el.querySelectorAll('.toggle button')).find((b) => b.textContent?.includes('Every scan')) as HTMLButtonElement;
    every.click();
    http.expectOne((r) => r.url === `${API}/scan-jobs/`).flush(page([JOB]));
    fixture.detectChanges();
    expect(el.querySelector('tbody')?.textContent).toContain('Run scan · Amina Otieno');
  });
});
