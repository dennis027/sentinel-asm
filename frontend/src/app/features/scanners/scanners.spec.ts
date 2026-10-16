import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { Organization, ScanProgress } from '../../core/models/models';
import { ConfirmService } from '../../core/services/confirm.service';
import { ToastService } from '../../core/services/toast.service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { Scanners } from './scanners';

const API = environment.apiBaseUrl;
const UNVERIFIED = { domain_verified: false, domain_verified_at: null, scans_allowed: false };

const SUBFINDER = {
  category: 'discovery',
  name: 'subfinder',
  label: 'Subdomain discovery',
  description: 'Finds subdomains.',
  applies_to: 'organization',
  owned_finding_types: [],
};
const PORT_SCAN = {
  category: 'network',
  name: 'nmap',
  label: 'Port scan',
  description: 'Checks ports.',
  applies_to: 'asset',
  owned_finding_types: [],
};

function run(overrides: Partial<ScanProgress> = {}): ScanProgress {
  return {
    scanner_name: 'nmap',
    batch_id: 'batch-1',
    started_at: '2026-10-01T10:00:00Z',
    total: 41698,
    pending: 40000,
    running: 8,
    success: 1680,
    failed: 10,
    finished: false,
    ...overrides,
  };
}

describe('Scanners', () => {
  let fixture: ComponentFixture<Scanners>;
  let http: HttpTestingController;
  let el: HTMLElement;

  async function setUp(
    org: Organization,
    { assets = 41698, progress = [] as ScanProgress[] } = {},
  ): Promise<void> {
    localStorage.clear();
    await TestBed.configureTestingModule({
      imports: [Scanners],
      providers: [provideAppTesting()],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);

    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([org]));

    fixture = TestBed.createComponent(Scanners);
    el = fixture.nativeElement;
    fixture.detectChanges();

    http.expectOne(`${API}/scanners/`).flush([PORT_SCAN, SUBFINDER]);
    http.expectOne((r) => r.url === `${API}/scan-jobs/progress/`).flush(progress);
    http.expectOne((r) => r.url === `${API}/assets/`).flush(page([], assets));
    fixture.detectChanges();
  }

  function card(label: string): HTMLElement {
    return Array.from(el.querySelectorAll<HTMLElement>('.card')).find((c) =>
      c.textContent?.includes(label),
    ) as HTMLElement;
  }

  function button(label: string): HTMLButtonElement {
    return card(label).querySelector('button') as HTMLButtonElement;
  }

  afterEach(() => {
    // Stops the progress refresh timer before the test bed is torn down.
    fixture.destroy();
    http.verify();
  });

  it('has no asset picker: each scanner says it covers the whole domain', async () => {
    await setUp(makeOrganization({ my_role: 'analyst' }));
    expect(el.querySelector('select, input')).toBeNull();
    // Discovery is listed first.
    expect(el.querySelector('.card .name')?.textContent).toBe('Subdomain discovery');
    expect(card('Subdomain discovery').querySelector('.scope')?.textContent).toContain('acme.com');
    expect(card('Port scan').querySelector('.scope')?.textContent).toContain('all 41,698 assets');
  });

  it('starts an asset-level scanner on every asset after confirming the count', async () => {
    await setUp(makeOrganization({ my_role: 'analyst' }));
    const ask = spyOn(TestBed.inject(ConfirmService), 'ask').and.resolveTo(false);

    button('Port scan').click();
    await fixture.whenStable();
    const question = ask.calls.mostRecent().args[0];
    expect(question.title).toBe('Run Port scan on all 41,698 assets?');
    expect(question.message).toContain('That is a lot of scans and can take a long time to finish.');
    expect(question.confirmLabel).toBe('Run scan');
    http.expectNone(`${API}/scan-jobs/trigger/`);

    ask.and.resolveTo(true);
    button('Port scan').click();
    await fixture.whenStable();
    const trigger = http.expectOne(`${API}/scan-jobs/trigger/`);
    expect(trigger.request.body).toEqual({ scanner_name: 'nmap', organization_id: 'org-1' });
    trigger.flush({ batch_id: 'batch-1', scanner_name: 'nmap', target_count: 41698 });
    fixture.detectChanges();

    expect(card('Port scan').querySelector('.run-text')?.textContent).toContain('0 of 41,698 done');
    expect(button('Port scan').disabled).toBeTrue();
    expect(button('Port scan').textContent).toContain('Running');
  });

  it('starts the organization-level scanner without asking', async () => {
    await setUp(makeOrganization({ my_role: 'analyst' }));
    const ask = spyOn(TestBed.inject(ConfirmService), 'ask');

    button('Subdomain discovery').click();
    await fixture.whenStable();
    expect(ask).not.toHaveBeenCalled();
    const trigger = http.expectOne(`${API}/scan-jobs/trigger/`);
    expect(trigger.request.body).toEqual({ scanner_name: 'subfinder', organization_id: 'org-1' });
    trigger.flush({ batch_id: 'batch-2', scanner_name: 'subfinder', target_count: 1 });
    fixture.detectChanges();
    expect(card('Subdomain discovery').querySelector('.run-text')?.textContent).toContain('Running');
  });

  it('shows a run already in progress when the page is opened', async () => {
    await setUp(makeOrganization({ my_role: 'analyst' }), { progress: [run()] });
    const text = card('Port scan').querySelector('.run-text')?.textContent ?? '';
    expect(text).toContain('1,690 of 41,698 done');
    expect(text).toContain('10 failed');
    expect(button('Port scan').disabled).toBeTrue();
    // Other scanners are unaffected.
    expect(button('Subdomain discovery').disabled).toBeFalse();
  });

  it('summarises the last finished run and offers to run again', async () => {
    await setUp(makeOrganization({ my_role: 'analyst' }), {
      progress: [run({ pending: 0, running: 0, success: 41690, failed: 8, finished: true })],
    });
    const text = card('Port scan').querySelector('.run-text')?.textContent ?? '';
    expect(text).toContain('41,690 finished');
    expect(text).toContain('8 failed');
    expect(button('Port scan').disabled).toBeFalse();
    expect(button('Port scan').textContent).toContain('Run again');
  });

  it('shows the reason when the server refuses to start', async () => {
    await setUp(makeOrganization({ my_role: 'analyst' }), { assets: 1 });
    button('Port scan').click();
    await fixture.whenStable();
    http
      .expectOne(`${API}/scan-jobs/trigger/`)
      .flush({ detail: 'This scanner is still running.' }, { status: 409, statusText: 'Conflict' });
    http.expectOne((r) => r.url === `${API}/scan-jobs/progress/`).flush([]);
    fixture.detectChanges();
    expect(el.querySelector('.error')?.textContent).toContain('still running');
  });

  it('disables scanning for a viewer', async () => {
    await setUp(makeOrganization({ my_role: 'viewer' }));
    expect(button('Port scan').disabled).toBeTrue();
  });

  it('shows the DNS record to publish and unlocks scanning once it verifies', async () => {
    await setUp(makeOrganization({ my_role: 'owner', ...UNVERIFIED }));
    expect(el.querySelector('.notice')?.textContent).toContain('sentinel-asm-verification=abc123');
    expect(button('Port scan').disabled).toBeTrue();

    (el.querySelector('.notice button') as HTMLButtonElement).click();
    http
      .expectOne(`${API}/organizations/org-1/verify-domain/`)
      .flush(makeOrganization({ my_role: 'owner' }));
    fixture.detectChanges();
    // The organization changed, so its numbers are read again.
    http.expectOne((r) => r.url === `${API}/scan-jobs/progress/`).flush([]);
    http.expectOne((r) => r.url === `${API}/assets/`).flush(page([], 3));
    fixture.detectChanges();

    expect(el.querySelector('.notice')).toBeNull();
    expect(button('Port scan').disabled).toBeFalse();
  });

  it('shows why verification failed', async () => {
    await setUp(makeOrganization({ my_role: 'owner', ...UNVERIFIED }));
    (el.querySelector('.notice button') as HTMLButtonElement).click();
    http
      .expectOne(`${API}/organizations/org-1/verify-domain/`)
      .flush({ detail: 'No TXT record found.' }, { status: 400, statusText: 'Bad Request' });
    fixture.detectChanges();
    expect(el.querySelector('.notice .error')?.textContent).toContain('No TXT record found.');
  });

  it('tells a non-admin to ask an admin instead of offering the check', async () => {
    await setUp(makeOrganization({ my_role: 'analyst', ...UNVERIFIED }));
    expect(el.querySelector('.notice button')).toBeNull();
    expect(el.querySelector('.notice')?.textContent).toContain('Ask an organization admin');
  });

  it('groups scanners by what they look at, discovery first', async () => {
    await setUp(makeOrganization({ my_role: 'analyst' }));
    const headings = Array.from(el.querySelectorAll('.group h2')).map((h) => h.textContent ?? '');
    expect(headings[0]).toContain('Discovery & inventory');
    expect(headings[1]).toContain('Network');
  });

  it('runs every scanner after one confirmation', async () => {
    await setUp(makeOrganization({ my_role: 'analyst' }));
    const ask = spyOn(TestBed.inject(ConfirmService), 'ask').and.resolveTo(true);
    const runAll = fixture.componentInstance.runAll();
    await fixture.whenStable();
    expect(ask.calls.mostRecent().args[0].title).toBe('Run all 2 scanners on acme.com?');
    expect(ask.calls.mostRecent().args[0].message[0]).toContain('41,699 individual checks');

    // Discovery first, as on the page; one refusal doesn't stop the rest.
    http.expectOne((r) => r.url === `${API}/scan-jobs/trigger/` && r.body.scanner_name === 'subfinder')
      .flush({ detail: 'Already running.' }, { status: 409, statusText: 'Conflict' });
    await new Promise((resolve) => setTimeout(resolve));
    http.expectOne((r) => r.url === `${API}/scan-jobs/trigger/` && r.body.scanner_name === 'nmap')
      .flush({ batch_id: 'b1', scanner_name: 'nmap', target_count: 41698 });
    await runAll;
    http.expectOne((r) => r.url === `${API}/scan-jobs/progress/`).flush([]);
    expect(TestBed.inject(ToastService).toasts()[0].message).toContain('1 of 2 scanners started');
  });
});
