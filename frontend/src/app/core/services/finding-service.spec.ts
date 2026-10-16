import { HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { makeFinding, page, provideAppTesting } from '../../testing/test-helpers';

import { FindingService } from './finding-service';

const BASE = `${environment.apiBaseUrl}/findings`;

describe('FindingService', () => {
  let service: FindingService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideAppTesting()] });
    service = TestBed.inject(FindingService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('sends only the filters that are set, including false booleans', () => {
    service
      .list({ organization: 'org-1', is_active: true, triaged: false, severity: undefined, page: 2 })
      .subscribe();

    const request = http.expectOne((r) => r.url === `${BASE}/`);
    const params = request.request.params;
    expect(params.keys().sort()).toEqual(['is_active', 'organization', 'page', 'triaged']);
    expect(params.get('triaged')).toBe('false');
    expect(params.get('page')).toBe('2');
    request.flush(page([]));
  });

  it('posts a triage verdict', () => {
    service.triage('finding-1', 'false_positive', 'load balancer').subscribe();
    const request = http.expectOne(`${BASE}/finding-1/triage/`);
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({ status: 'false_positive', note: 'load balancer' });
    request.flush(makeFinding({ status: 'false_positive' }));
  });

  it('fetches a screenshot as a blob', () => {
    let received: Blob | undefined;
    service.screenshot('finding-1').subscribe((blob) => (received = blob));
    const request = http.expectOne(`${BASE}/finding-1/screenshot/`);
    expect(request.request.responseType).toBe('blob');
    request.flush(new Blob(['png']));
    expect(received?.size).toBe(3);
  });
});
