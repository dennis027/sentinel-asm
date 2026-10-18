import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { environment } from '../../../environments/environment';
import { ErrorGroup, LogDetection, LogOverview, LogSource, OrgRole } from '../../core/models/models';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { Logs } from './logs';

const API = environment.apiBaseUrl;

function source(overrides: Partial<LogSource> = {}): LogSource {
  return {
    id: 's1', organization: 'org-1', name: 'web-01', os: 'linux', key_prefix: 'dsl_abc', created_at: '',
    last_seen_at: '2026-10-16T10:00:00Z', last_host: 'web-01', events_received: 1200, status: 'receiving',
    open_detections: 1, is_application: false, ...overrides,
  };
}

const OVERVIEW: LogOverview = {
  events_24h: 1200,
  by_category_24h: { auth_failure: 40, auth_success: 12, privilege: 3, account_change: 1, log_tampering: 0, service: 0, app_error: 0, http_request: 0, other: 1144 },
  failed_signins_24h: 40,
  sources: { total: 1, receiving: 1, silent: 0, waiting: 0 },
  open_detections: 1,
  open_by_severity: { critical: 1 },
  top_attackers_24h: [{ ip: '203.0.113.9', failures: 38 }],
  retention_days: 30,
  applications: 0,
  errors_24h: 0,
  server_errors_24h: 0,
  unresolved_errors: 0,
  rules: [{ rule: 'brute_force', severity: 'high', title: 'Many failed sign-ins from one address', description: '…' }],
};

const ERROR: ErrorGroup = {
  id: 'g1', source: 's3', source_name: 'orders-api', fingerprint: 'abc123', exception_type: 'KeyError',
  title: "KeyError: 'sku'", culprit: 'orders/views.py in checkout', service: 'orders-api', count: 214,
  first_seen: '2026-10-15T08:00:00Z', last_seen: '2026-10-16T09:30:00Z',
  stacktrace: 'Traceback (most recent call last):\n  File "/srv/app/orders/views.py", line 41, in checkout\nKeyError: \'sku\'',
  status: 'unresolved', resolved_at: null, regressions: 1, first_release: '2.15.0', last_release: '2.15.2',
};

const DETECTION: LogDetection = {
  id: 'd1', source: 's1', source_name: 'web-01', rule: 'login_after_failures', severity: 'critical',
  title: 'admin signed in from 203.0.113.9 after 38 failures', description: 'Check it was them.', user: 'admin',
  src_ip: '203.0.113.9', event_count: 1, first_seen: '2026-10-16T09:00:00Z', last_seen: '2026-10-16T09:00:00Z',
  status: 'open', resolved_at: null, resolved_by: null,
};

describe('Logs', () => {
  let fixture: ComponentFixture<Logs>;
  let http: HttpTestingController;
  let el: HTMLElement;

  async function setUp(sources: LogSource[], role: OrgRole = 'owner', overview = OVERVIEW): Promise<void> {
    localStorage.clear();
    await TestBed.configureTestingModule({ imports: [Logs], providers: [provideAppTesting()] }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization({ my_role: role })]));
    fixture = TestBed.createComponent(Logs);
    el = fixture.nativeElement;
    fixture.detectChanges();
    http.expectOne((r) => r.url === `${API}/logs/overview/`).flush(overview);
    http.expectOne((r) => r.url === `${API}/log-sources/`).flush(sources);
    http.expectOne((r) => r.url === `${API}/log-detections/`).flush(page(sources.length ? [DETECTION] : []));
    fixture.detectChanges();
    await fixture.whenStable();
  }

  function click(text: string): void {
    const button = Array.from(el.querySelectorAll('button')).find((b) => b.textContent?.includes(text));
    if (!button) throw new Error(`No button "${text}"`);
    button.click();
    fixture.detectChanges();
  }

  afterEach(() => http.verify());

  it('explains the module and offers to connect the first server', async () => {
    await setUp([]);
    expect(el.querySelector('.intro')?.textContent).toContain('Python or Node.js app');
    click('Connect your first server');
    await fixture.whenStable();
    fixture.detectChanges();
    expect(el.querySelector('.connect-form')).not.toBeNull();
  });

  it('connects a Windows server and shows its key and setup steps', async () => {
    await setUp([source()]);
    click('Connect a server');
    await fixture.whenStable();
    fixture.detectChanges();
    // The form appears after the tab switch; its inputs join the form a tick later.
    await fixture.whenStable();
    const name = el.querySelector('#server-name') as HTMLInputElement;
    name.value = 'dc-01';
    name.dispatchEvent(new Event('input'));
    click('Windows');
    click('Continue to setup');
    const request = http.expectOne(`${API}/log-sources/`);
    expect(request.request.body).toEqual({ organization: 'org-1', name: 'dc-01', os: 'windows' });
    request.flush(source({ id: 's2', name: 'dc-01', os: 'windows', status: 'waiting', key: 'dsl_SECRET',
                           ingest_url: 'https://densight.acme.com/api/ingest/' }));
    http.expectOne((r) => r.url === `${API}/logs/overview/`).flush(OVERVIEW);
    http.expectOne((r) => r.url === `${API}/log-sources/`).flush([source()]);
    fixture.detectChanges();
    const text = el.textContent ?? '';
    expect(el.querySelector('.key-box code')?.textContent).toBe('dsl_SECRET');
    expect(text).toContain('winevtlog');
    expect(text).toContain('Authorization Bearer dsl_SECRET');
    expect(text).toContain('Host        densight.acme.com');
    expect(text).toContain('tls         On');
    expect(text).toContain('New-Service -Name densight-logs');
    expect(text).toContain('Waiting for the first logs');
  });

  it('lists detections, jumps to their events and resolves them', async () => {
    await setUp([source()]);
    expect(el.querySelector('.kpi .n')?.textContent?.trim()).toBe('1');
    expect(el.querySelector('.detection')?.textContent).toContain('after 38 failures');

    const navigate = spyOn(TestBed.inject(Router), 'navigate').and.resolveTo(true);
    click('View events');
    expect(navigate.calls.mostRecent().args[1]?.queryParams).toEqual(
      jasmine.objectContaining({ tab: 'search', source: 's1', ip: '203.0.113.9', around: '2026-10-16T09:00:00Z' }),
    );

    click('Mark as dealt with');
    http.expectOne(`${API}/log-detections/d1/resolve/`).flush({ ...DETECTION, status: 'resolved' });
    http.expectOne((r) => r.url === `${API}/log-detections/`).flush(page([]));
    http.expectOne((r) => r.url === `${API}/logs/overview/`).flush({ ...OVERVIEW, open_detections: 0 });
    http.expectOne((r) => r.url === `${API}/log-sources/`).flush([source()]);
  });

  it('filters detections by text, severity, source and rule', async () => {
    await setUp([source()]);
    fixture.componentInstance.filterDetections({ severity: 'critical', rule: 'custom' });
    const request = http.expectOne((r) => r.url === `${API}/log-detections/`);
    expect(request.request.params.get('severity')).toBe('critical');
    expect(request.request.params.get('rule')).toBe('custom');
    expect(request.request.params.get('status')).toBe('open');
    request.flush(page([]));
    fixture.detectChanges();
    expect(el.querySelector('.det-filters option[value="custom"]')?.textContent).toContain('Your own alerts');
  });

  it('refreshes by itself and highlights new detections', async () => {
    jasmine.clock().install();
    try {
      await setUp([source()]);
      jasmine.clock().tick(15_000);
      http.expectOne((r) => r.url === `${API}/logs/overview/`).flush(OVERVIEW);
      http.expectOne((r) => r.url === `${API}/log-sources/`).flush([source()]);
      http.expectOne((r) => r.url === `${API}/log-detections/`).flush(page([{ ...DETECTION, id: 'd2', title: 'New one' }, DETECTION]));
      fixture.detectChanges();
      const items = el.querySelectorAll('.detection');
      expect(items[0].classList).toContain('new');
      expect(items[1].classList).not.toContain('new');
    } finally {
      jasmine.clock().uninstall();
    }
  });

  it('viewers see servers but cannot connect or disconnect them', async () => {
    await setUp([source()], 'viewer');
    expect(el.textContent).not.toContain('Connect a server');
    TestBed.inject(Router).navigate([], { queryParams: { tab: 'servers' } });
    await fixture.whenStable();
    fixture.detectChanges();
    expect(el.querySelector('.servers')?.textContent).toContain('web-01');
    expect(el.querySelector('.servers .icon-btn')).toBeNull();
  });

  it('connects a Python app and shows the handler setup', async () => {
    await setUp([source()]);
    click('Connect a server or app');
    await fixture.whenStable();
    fixture.detectChanges();
    await fixture.whenStable();
    const name = el.querySelector('#server-name') as HTMLInputElement;
    name.value = 'orders-api';
    name.dispatchEvent(new Event('input'));
    click('Python app');
    click('Continue to setup');
    const request = http.expectOne(`${API}/log-sources/`);
    expect(request.request.body).toEqual({ organization: 'org-1', name: 'orders-api', os: 'python' });
    request.flush(source({ id: 's3', name: 'orders-api', os: 'python', is_application: true, status: 'waiting',
                           key: 'dsl_APP', ingest_url: 'https://densight.acme.com/api/ingest/' }));
    http.expectOne((r) => r.url === `${API}/logs/overview/`).flush(OVERVIEW);
    http.expectOne((r) => r.url === `${API}/log-sources/`).flush([source()]);
    fixture.detectChanges();
    const text = el.textContent ?? '';
    expect(text).toContain('curl -fsSLo densight_logging.py https://densight.acme.com/api/logs/clients/densight_logging.py');
    expect(text).toContain('"class": "densight_logging.DensightHandler"');
    expect(text).toContain('key=os.environ.get("DENSIGHT_KEY", "dsl_APP")');
    expect(text).toContain('service="orders-api"');
  });

  it('groups app errors by release and lets an analyst resolve one', async () => {
    const app = source({ id: 's3', name: 'orders-api', os: 'python', is_application: true });
    await setUp([source(), app], 'analyst', { ...OVERVIEW, applications: 1, errors_24h: 300, unresolved_errors: 1 });
    expect(el.textContent).toContain('Unresolved app errors');
    TestBed.inject(Router).navigate([], { queryParams: { tab: 'errors' } });
    await fixture.whenStable();
    fixture.detectChanges();
    http.expectOne((r) => r.url === `${API}/error-groups/` && r.params.get('status') === 'unresolved').flush(page([ERROR]));
    http.expectOne(`${API}/error-groups/releases/?organization=org-1`).flush([
      { source: 's3', source_name: 'orders-api', release: '2.15.0', first_seen: '2026-10-15T08:00:00Z',
        last_seen: '2026-10-16T09:30:00Z', events: 900, errors: 40, new_errors: 1 },
    ]);
    fixture.detectChanges();
    const row = el.querySelector('.error-row') as HTMLButtonElement;
    expect(row.textContent).toContain('KeyError');
    expect(row.textContent).toContain('214');
    expect(row.textContent).toContain('came back 1×');
    expect(row.textContent).toContain('in 2.15.0');
    expect(row.textContent).toContain('latest in 2.15.2');
    expect(el.querySelector('.release')?.textContent).toContain('1 new error');

    (el.querySelector('.release') as HTMLButtonElement).click();
    const filtered = http.expectOne((r) => r.url === `${API}/error-groups/`);
    expect(filtered.request.params.get('release')).toBe('2.15.0');
    filtered.flush(page([ERROR]));
    fixture.detectChanges();
    expect(el.querySelector('.filter-chip')?.textContent).toContain('first appeared in 2.15.0');

    row.click();
    fixture.detectChanges();
    expect(el.querySelector('.error-detail .stack')?.textContent).toContain('in checkout');
    (Array.from(el.querySelectorAll('.d-actions button')).find((b) => b.textContent?.includes('Resolve')) as HTMLButtonElement).click();
    const change = http.expectOne(`${API}/error-groups/g1/set-status/`);
    expect(change.request.body).toEqual({ status: 'resolved' });
    change.flush({ ...ERROR, status: 'resolved' });
    http.expectOne((r) => r.url === `${API}/error-groups/`).flush(page([]));
    http.expectOne((r) => r.url === `${API}/logs/overview/`).flush(OVERVIEW);
    http.expectOne((r) => r.url === `${API}/log-sources/`).flush([source(), app]);
  });

  it('jumps from an error to every occurrence of it', async () => {
    const app = source({ id: 's3', name: 'orders-api', os: 'python', is_application: true });
    await setUp([app], 'viewer', { ...OVERVIEW, applications: 1 });
    const navigate = spyOn(TestBed.inject(Router), 'navigate').and.resolveTo(true);
    fixture.componentInstance.viewOccurrences(ERROR);
    expect(navigate.calls.mostRecent().args[1]?.queryParams).toEqual(
      jasmine.objectContaining({ tab: 'search', source: 's3', fingerprint: 'abc123', since: 'all' }),
    );
  });
});
