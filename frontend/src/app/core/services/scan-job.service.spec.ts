import { HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { ScanJob } from '../models/models';
import { provideAppTesting } from '../../testing/test-helpers';

import { ScanJobService } from './scan-job.service';

const BASE = `${environment.apiBaseUrl}/scan-jobs`;

function makeJob(overrides: Partial<ScanJob> = {}): ScanJob {
  return {
    id: 'job-1',
    organization: 'org-1',
    organization_name: 'Acme',
    asset: 'asset-1',
    asset_value: 'acme.com',
    scanner_name: 'nmap',
    status: 'success',
    error_message: '',
    created_at: '2026-01-01T00:00:00Z',
    started_at: null,
    finished_at: null,
    trigger: 'single',
    trigger_label: 'Single scan',
    triggered_by: null,
    run_id: 'run-1',
    ...overrides,
  };
}

describe('ScanJobService', () => {
  let service: ScanJobService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideAppTesting()] });
    service = TestBed.inject(ScanJobService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('re-runs an asset scan against that asset, forcing a new job', () => {
    service.rerun(makeJob()).subscribe();
    const request = http.expectOne(`${BASE}/trigger/`);
    expect(request.request.body).toEqual({ scanner_name: 'nmap', asset_id: 'asset-1', force: true });
    request.flush(makeJob({ id: 'job-2', status: 'pending' }));
  });

  it('re-runs an organization-level scan for the organization', () => {
    service.rerun(makeJob({ asset: null, asset_value: null, scanner_name: 'subfinder' })).subscribe();
    const request = http.expectOne(`${BASE}/trigger/`);
    expect(request.request.body).toEqual({ scanner_name: 'subfinder', organization_id: 'org-1' });
    request.flush({ batch_id: 'b', scanner_name: 'subfinder', target_count: 1 });
  });

  it('reads domain-wide progress for one organization', () => {
    service.progress('org-1').subscribe();
    const request = http.expectOne((r) => r.url === `${BASE}/progress/`);
    expect(request.request.params.get('organization')).toBe('org-1');
    request.flush([]);
  });

  it('includes the page number when listing', () => {
    service.list({ organization: 'org-1', status: '', page: 3 }).subscribe();
    const request = http.expectOne((r) => r.url === `${BASE}/`);
    expect(request.request.params.keys().sort()).toEqual(['organization', 'page']);
    expect(request.request.params.get('page')).toBe('3');
    request.flush({ count: 0, next: null, previous: null, results: [] });
  });
});
