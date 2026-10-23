import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { OrgRole } from '../../core/models/models';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeFinding, makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { Findings } from './findings';

const API = environment.apiBaseUrl;
const MEMBERS = [
  { id: 'm1', user_id: 7, username: 'brian', email: '', role: 'analyst', created_at: '' },
  { id: 'm2', user_id: 9, username: 'amina', email: '', role: 'admin', created_at: '' },
];

const VIEWS = [{
  id: 'v1', organization: 'org-1', page: 'findings', name: 'Criticals only', filters: { severity: 'critical', view: 'triaged' },
  shared: true, owner_name: 'amina', is_mine: false, created_at: '',
}];

describe('Findings', () => {
  let fixture: ComponentFixture<Findings>;
  let http: HttpTestingController;

  async function setUp(role: OrgRole = 'analyst'): Promise<void> {
    localStorage.clear();
    await TestBed.configureTestingModule({
      imports: [Findings],
      providers: [provideAppTesting()],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);

    TestBed.inject(OrganizationContextService).loadOrganizations();
    http
      .expectOne((r) => r.url === `${API}/organizations/`)
      .flush(page([makeOrganization({ id: 'org-1', my_role: role })]));

    fixture = TestBed.createComponent(Findings);
    fixture.detectChanges();
    http.expectOne((r) => r.url === `${API}/saved-views/`).flush(VIEWS);
    // Analysts and above load the team, for the Owner picker.
    if (role !== 'viewer') {
      http.expectOne(`${API}/organizations/org-1/members/`).flush(MEMBERS);
    }
  }

  function expectList() {
    return http.expectOne((r) => r.url === `${API}/findings/`);
  }

  /** Opens the first finding's details and returns its triage button labels. */
  function openDetails(): string[] {
    fixture.detectChanges();
    fixture.nativeElement.querySelector('button.quick').click();
    fixture.detectChanges();
    const nodes: NodeListOf<HTMLButtonElement> =
      fixture.nativeElement.querySelectorAll('.triage button');
    return Array.from(nodes).map((b) => b.textContent?.trim() ?? '');
  }

  afterEach(() => http.verify());

  it('loads open findings for the selected organization only, exactly once', async () => {
    await setUp();
    const request = expectList();
    expect(request.request.params.get('organization')).toBe('org-1');
    expect(request.request.params.get('is_active')).toBe('true');
    expect(request.request.params.get('triaged')).toBe('false');
    // Security issues by default; inventory is one choice away.
    expect(request.request.params.get('kind')).toBe('issue');
    request.flush(page([]));

    fixture.componentInstance.onKindChange('inventory');
    expectList().flush(page([]));
    fixture.componentInstance.onKindChange('');
    const everything = expectList();
    expect(everything.request.params.has('kind')).toBeFalse();
    everything.flush(page([]));
  });

  it('switching view asks for triaged or resolved findings', async () => {
    await setUp();
    expectList().flush(page([]));

    fixture.componentInstance.onViewChange('triaged');
    let request = expectList();
    expect(request.request.params.get('triaged')).toBe('true');
    request.flush(page([]));

    fixture.componentInstance.onViewChange('resolved');
    request = expectList();
    expect(request.request.params.get('is_active')).toBe('false');
    expect(request.request.params.has('triaged')).toBeFalse();
    request.flush(page([]));
  });

  it('lets an analyst triage a finding, then reloads the list', async () => {
    await setUp('analyst');
    expectList().flush(page([makeFinding({ id: 'f1' })]));
    expect(openDetails()).toEqual(['Accept risk', 'False positive']);

    fixture.componentInstance.triageNote.set('Behind the VPN');
    fixture.nativeElement.querySelector('.triage button').click();
    const triage = http.expectOne(`${API}/findings/f1/triage/`);
    expect(triage.request.body).toEqual({ status: 'accepted', note: 'Behind the VPN' });
    triage.flush(makeFinding({ id: 'f1', status: 'accepted' }));

    expectList().flush(page([]));
  });

  it('offers Reopen for an already-triaged finding', async () => {
    await setUp('analyst');
    expectList().flush(page([]));
    fixture.componentInstance.onViewChange('triaged');
    expectList().flush(page([makeFinding({ status: 'accepted', status_changed_by: 'erin' })]));
    expect(openDetails()).toEqual(['Reopen']);
    expect(fixture.nativeElement.querySelector('.meta').textContent).toContain('Risk accepted');
  });

  it('shows no triage buttons to a viewer', async () => {
    await setUp('viewer');
    expectList().flush(page([makeFinding()]));
    expect(openDetails()).toEqual([]);
  });

  it('shows a finding\'s description and scanner details when opened', async () => {
    await setUp();
    expectList().flush(
      page([
        makeFinding({
          description: 'Port 22/tcp is open, service: ssh',
          raw_data: { port: '22', service: 'ssh', product: '', screenshot_path: 'x.png' },
        }),
      ]),
    );
    expect(fixture.nativeElement.querySelector('.more')).toBeNull();
    openDetails();

    const more: HTMLElement = fixture.nativeElement.querySelector('.more');
    expect(more.textContent).toContain('Port 22/tcp is open, service: ssh');
    const labels = Array.from(more.querySelectorAll('dt')).map((dt) => dt.textContent);
    // Empty values and the internal file path are left out.
    expect(labels).toEqual(['First seen', 'Last seen', 'port', 'service']);
  });

  it('explains why a finding matters and what to do about it', async () => {
    await setUp();
    expectList().flush(
      page([
        makeFinding({
          impact: 'Remote Desktop is reachable from the internet.',
          remediation: 'Put it behind a VPN.',
        }),
      ]),
    );
    openDetails();
    const guidance = fixture.nativeElement.querySelector('.guidance').textContent;
    expect(guidance).toContain('Why it matters. Remote Desktop is reachable');
    expect(guidance).toContain('What to do. Put it behind a VPN.');
  });

  it('uses plain-language type names and explains an empty list', async () => {
    await setUp();
    expectList().flush(page([makeFinding({ finding_type: 'expired_ssl' })]));
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.meta').textContent).toContain('TLS certificate');

    fixture.componentInstance.onViewChange('resolved');
    expectList().flush(page([]));
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.empty').textContent).toContain(
      'when a scan stops detecting it',
    );
  });

  it('searches by title after a short pause', async () => {
    await setUp();
    expectList().flush(page([]));
    fixture.componentInstance.onSearchChange('ssh');
    http.expectNone((r) => r.url === `${API}/findings/`);

    await new Promise((resolve) => setTimeout(resolve, 350));
    const request = expectList();
    expect(request.request.params.get('search')).toBe('ssh');
    request.flush(page([]));
  });

  it('loads screenshot thumbnails through the authenticated endpoint', async () => {
    await setUp();
    expectList().flush(page([makeFinding({ id: 'shot', finding_type: 'screenshot' })]));

    http.expectOne(`${API}/findings/shot/screenshot/`).flush(new Blob(['png']));
    fixture.detectChanges();

    const img: HTMLImageElement = fixture.nativeElement.querySelector('img.thumbnail');
    expect(img.src).toMatch(/^blob:/);
  });

  it('pages through results', async () => {
    await setUp();
    expectList().flush(page([makeFinding()], 60));
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.position').textContent).toContain('Page 1 of 3');

    fixture.componentInstance.onPageChange(2);
    const request = expectList();
    expect(request.request.params.get('page')).toBe('2');
    request.flush(page([makeFinding()], 60));
  });

  it('shows who owns a finding and flags it when it is past its fix-by date', async () => {
    await setUp();
    expectList().flush(
      page([makeFinding({ overdue: true, assignee: 7, assignee_username: 'brian', due_at: '2026-01-08T00:00:00Z' })]),
    );
    fixture.detectChanges();
    const meta = fixture.nativeElement.querySelector('.meta').textContent;
    expect(meta).toContain('Overdue');
    expect(meta).toContain('brian');

    openDetails();
    expect(fixture.nativeElement.querySelector('dd.late').textContent).toContain('overdue');
  });

  it('assigns a finding to a member', async () => {
    await setUp();
    expectList().flush(page([makeFinding({ id: 'f1', due_at: '2026-02-01T00:00:00Z' })]));
    openDetails();
    const options = Array.from(fixture.nativeElement.querySelectorAll('.owner option')).map(
      (o) => (o as HTMLOptionElement).textContent?.trim(),
    );
    expect(options).toEqual(['Nobody yet', 'brian', 'amina']);

    fixture.componentInstance.assign(makeFinding({ id: 'f1' }), '9');
    const request = http.expectOne(`${API}/findings/f1/assign/`);
    expect(request.request.body).toEqual({ assignee: 9 });
    request.flush(makeFinding({ id: 'f1', assignee: 9, assignee_username: 'amina' }));
    expect(fixture.componentInstance.findings()[0].assignee_username).toBe('amina');
  });

  it('filters to my work, unassigned work, or overdue work', async () => {
    await setUp();
    expectList().flush(page([]));
    for (const [value, key, expected] of [
      ['mine', 'assignee', 'me'],
      ['unassigned', 'assignee', 'none'],
      ['overdue', 'overdue', 'true'],
    ]) {
      fixture.componentInstance.onWorkflowChange(value);
      const request = expectList();
      expect(request.request.params.get(key)).toBe(expected);
      request.flush(page([]));
    }
  });

  it('copies a finding as a ready-to-paste ticket', async () => {
    await setUp();
    expectList().flush(page([]));
    const write = spyOn(navigator.clipboard, 'writeText').and.resolveTo();
    fixture.componentInstance.copyAsTicket(
      makeFinding({
        severity: 'high',
        title: 'Open port 3389/tcp',
        asset_value: 'staging.acme.com',
        impact: 'RDP is reachable.',
        remediation: 'Put it behind a VPN.',
        due_at: '2026-02-01T00:00:00Z',
        overdue: true,
        assignee_username: 'brian',
        controls: [{ id: 'owasp:A05', framework: 'owasp', code: 'A05', name: 'Security Misconfiguration' }],
      }),
    );
    const ticket = write.calls.mostRecent().args[0];
    expect(ticket).toContain('[HIGH] Open port 3389/tcp on staging.acme.com');
    expect(ticket).toContain('Fix by: 2026-02-01 (overdue)');
    expect(ticket).toContain('Owner: brian');
    expect(ticket).toContain('What to do:\nPut it behind a VPN.');
    expect(ticket).toContain('OWASP A05 (Security Misconfiguration)');
  });

  it('applies one decision to several ticked findings', async () => {
    await setUp();
    expectList().flush(
      page([makeFinding({ id: 'f1', title: 'One' }), makeFinding({ id: 'f2', title: 'Two' }), makeFinding({ id: 'f3', title: 'Three' })]),
    );
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const boxes = el.querySelectorAll<HTMLInputElement>('input.pick');
    expect(boxes.length).toBe(3);
    boxes[0].click();
    boxes[2].click();
    fixture.detectChanges();
    expect(el.querySelector('.bulk-bar')?.textContent).toContain('2 selected');

    const accept = Array.from(el.querySelectorAll<HTMLButtonElement>('.bulk-bar button')).find((b) =>
      b.textContent?.includes('Accept risk'),
    );
    accept!.click();
    const request = http.expectOne(`${API}/findings/bulk/`);
    expect(request.request.body).toEqual({ ids: ['f1', 'f3'], action: 'triage', status: 'accepted' });
    request.flush({ updated: 2 });
    // The list reloads and the selection is cleared.
    expectList().flush(page([]));
    fixture.detectChanges();
    expect(el.querySelector('.bulk-bar')).toBeNull();
  });

  it('marks issues that came back after a fix, and filters to them', async () => {
    await setUp();
    expectList().flush(page([makeFinding({ id: 'f1', reopened_count: 1 })]));
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.meta')?.textContent).toContain('Came back');
    fixture.componentInstance.onWorkflowChange('regressed');
    expect(expectList().request.params.get('regressed')).toBe('true');
  });

  it('viewers get no checkboxes', async () => {
    await setUp('viewer');
    expectList().flush(page([makeFinding({ id: 'f1' })]));
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('input.pick')).toBeNull();
  });

  it('applies a saved view and saves the current filters as a new one', async () => {
    await setUp('analyst');
    expectList().flush(page([]));
    const root: HTMLElement = fixture.nativeElement;
    (root.querySelector('app-saved-views .trigger') as HTMLButtonElement).click();
    fixture.detectChanges();
    (root.querySelector('app-saved-views .view') as HTMLButtonElement).click();
    const list = expectList();
    expect(list.request.params.get('severity')).toBe('critical');
    expect(list.request.params.get('triaged')).toBe('true');
    list.flush(page([]));
    fixture.detectChanges();

    (root.querySelector('app-saved-views .trigger') as HTMLButtonElement).click();
    fixture.detectChanges();
    (root.querySelector('app-saved-views .save') as HTMLButtonElement).click();
    fixture.detectChanges();
    await fixture.whenStable();
    const name = root.querySelector('app-saved-views .save-form input') as HTMLInputElement;
    name.value = 'Triaged criticals';
    name.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    (root.querySelector('app-saved-views .save-form button[type=submit]') as HTMLButtonElement).click();
    const create = http.expectOne(`${API}/saved-views/`);
    expect(create.request.body).toEqual({
      organization: 'org-1', page: 'findings', name: 'Triaged criticals',
      filters: { severity: 'critical', view: 'triaged' }, shared: false,
    });
    create.flush({ ...VIEWS[0], id: 'v2', name: 'Triaged criticals', is_mine: true });
  });
});
