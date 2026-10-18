import { HttpTestingController, TestRequest } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { environment } from '../../../../environments/environment';
import { LogEventRow, LogFacets, LogSource } from '../../../core/models/models';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { makeOrganization, page, provideAppTesting } from '../../../testing/test-helpers';

import { EventSearch } from './event-search';

const API = environment.apiBaseUrl;

const SOURCES = [{ id: 's1', name: 'web-01' }, { id: 's3', name: 'payments' }] as LogSource[];

function event(overrides: Partial<LogEventRow> = {}): LogEventRow {
  return {
    id: 7, source: 's3', source_name: 'payments', occurred_at: '2026-10-16T09:00:00Z', received_at: '', host: 'pay-1',
    program: 'payments', event_id: null, level: 'error', category: 'app_error', category_label: 'App error',
    action: 'exception', user: '', src_ip: null, message: 'charge failed — GatewayTimeoutError: timed out',
    raw: { err: { stack: 'GatewayTimeoutError: timed out\n    at charge (/srv/app/gateway.js:1:1)' } },
    service: 'payments', http_status: 504, fingerprint: 'fp1', redacted: [], release: '3.8.2', ...overrides,
  };
}

const FACETS: LogFacets = {
  source: { s3: 12 }, category: { app_error: 12 }, level: { error: 10, warning: 2 },
  service: [['payments', 12]], release: [['3.8.2', 9], ['3.8.1', 3]], host: [['pay-1', 12]],
  status: { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 10 },
};

describe('EventSearch', () => {
  let fixture: ComponentFixture<EventSearch>;
  let http: HttpTestingController;
  let el: HTMLElement;

  async function setUp(url: string): Promise<TestRequest> {
    await TestBed.configureTestingModule({ imports: [EventSearch], providers: [provideAppTesting()] }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));
    await TestBed.inject(Router).navigateByUrl(url);
    fixture = TestBed.createComponent(EventSearch);
    fixture.componentRef.setInput('sources', SOURCES);
    fixture.componentRef.setInput('hasApps', true);
    el = fixture.nativeElement;
    fixture.detectChanges();
    const list = http.expectOne((r) => r.url === `${API}/log-events/`);
    http.expectOne((r) => r.url === `${API}/log-events/facets/`).flush(FACETS);
    http.expectOne((r) => r.url === `${API}/log-events/timeline/`).flush({
      start: '2026-10-16T08:00:00Z', end: '2026-10-16T09:00:00Z', bucket_seconds: 60,
      buckets: [{ t: '2026-10-16T08:59:00Z', error: 3, warning: 1, info: 5 }, { t: '2026-10-16T09:00:00Z', error: 0, warning: 0, info: 0 }],
    });
    return list;
  }

  afterEach(() => http.verify());

  it('takes its filters from the address, counts each option and shows them as removable chips', async () => {
    const list = await setUp('/?tab=search&level=problems&service=payments&release=3.8.2&since=7d');
    expect(list.request.params.get('level')).toBe('problems');
    expect(list.request.params.get('service')).toBe('payments');
    expect(list.request.params.get('release')).toBe('3.8.2');
    expect(list.request.params.get('since')).toBe('7d');
    list.flush(page([event()]));
    fixture.detectChanges();

    const chips = Array.from(el.querySelectorAll('.chip')).map((c) => c.textContent?.trim());
    expect(chips).toEqual(['Level: Warnings and errors', 'Service: payments', 'Release: 3.8.2']);
    expect(el.querySelector('select[aria-label="Level"]')?.textContent).toContain('Errors (10)');
    expect(el.querySelector('select[aria-label="Source"]')?.textContent).toContain('payments (12)');
    expect(el.querySelectorAll('.bar').length).toBe(2);

    const navigate = spyOn(TestBed.inject(Router), 'navigate').and.resolveTo(true);
    (el.querySelectorAll('.chip button')[1] as HTMLButtonElement).click();
    expect(navigate.calls.mostRecent().args[1]?.queryParams).toEqual(jasmine.objectContaining({ service: null, page: null }));
    (el.querySelector('.bar') as HTMLButtonElement).click();
    expect(navigate.calls.mostRecent().args[1]?.queryParams).toEqual(jasmine.objectContaining({
      since: 'custom', after: '2026-10-16T08:59:00.000Z', before: '2026-10-16T09:00:00.000Z',
    }));
  });

  it('turns field:value words in the search box into filters', async () => {
    (await setUp('/?tab=search')).flush(page([]));
    const navigate = spyOn(TestBed.inject(Router), 'navigate').and.resolveTo(true);
    fixture.componentInstance.text.set('level:error app:payments status:5xx release:"3.8 beta" gateway timeout');
    fixture.componentInstance.submitText();
    expect(navigate.calls.mostRecent().args[1]?.queryParams).toEqual(jasmine.objectContaining({
      level: 'error', source: 's3', status: '5xx', release: '3.8 beta', q: 'gateway timeout',
    }));
  });

  it('shows new events as they arrive, without reloading', async () => {
    jasmine.clock().install();
    try {
      (await setUp('/?tab=search')).flush(page([event()]));
      fixture.detectChanges();
      expect(el.querySelector('.live')?.textContent).toContain('Live');

      jasmine.clock().tick(3000);
      const live = http.expectOne((r) => r.url === `${API}/log-events/` && r.params.has('after_id'));
      expect(live.request.params.get('after_id')).toBe('7');
      live.flush(page([event({ id: 9, occurred_at: '2026-10-16T09:01:00Z', message: 'just arrived' })]));
      fixture.detectChanges();
      const rows = el.querySelectorAll('.event');
      expect(rows.length).toBe(2);
      expect(rows[0].textContent).toContain('just arrived');
      expect(rows[0].classList).toContain('fresh');
      expect(el.querySelector('.count')?.textContent).toContain('2 events');

      // Paused: no more requests.
      (el.querySelector('.live') as HTMLButtonElement).click();
      fixture.detectChanges();
      jasmine.clock().tick(9000);
      expect(el.querySelector('.live')?.textContent).toContain('Paused');
    } finally {
      jasmine.clock().uninstall();
    }
  });

  it('opens an event with its stack trace and links to filter by its fields', async () => {
    (await setUp('/?tab=search')).flush(page([event()]));
    fixture.detectChanges();
    (el.querySelector('.event-row') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('.event-detail .stack')?.textContent).toContain('at charge');
    const navigate = spyOn(TestBed.inject(Router), 'navigate').and.resolveTo(true);
    const release = Array.from(el.querySelectorAll('.event-detail .linkish')).find((b) => b.textContent === '3.8.2') as HTMLButtonElement;
    release.click();
    expect(navigate.calls.mostRecent().args[1]?.queryParams).toEqual(jasmine.objectContaining({ release: '3.8.2' }));
  });
});
