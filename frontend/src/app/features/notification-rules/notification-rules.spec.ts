import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { NotificationRule } from '../../core/models/models';
import { ConfirmService } from '../../core/services/confirm.service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { ToastService } from '../../core/services/toast.service';
import { makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { NotificationRules } from './notification-rules';

const API = environment.apiBaseUrl;
const HOOK = 'https://hooks.slack.com/services/T0/B0/abc';

function rule(overrides: Partial<NotificationRule> = {}): NotificationRule {
  return {
    id: 'r1',
    organization: 'org-1',
    organization_name: 'Acme',
    channel: 'email',
    recipient_email: 'sec@acme.com',
    webhook_url: '',
    min_severity: 'high',
    is_active: true,
    weekly_report: false,
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('NotificationRules', () => {
  let fixture: ComponentFixture<NotificationRules>;
  let http: HttpTestingController;
  let el: HTMLElement;

  async function setUp(rules: NotificationRule[], role: 'owner' | 'viewer' = 'owner'): Promise<void> {
    localStorage.clear();
    localStorage.setItem('sentinel_username', 'dennis');
    await TestBed.configureTestingModule({
      imports: [NotificationRules],
      providers: [provideAppTesting()],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);

    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization({ my_role: role })]));

    fixture = TestBed.createComponent(NotificationRules);
    el = fixture.nativeElement;
    fixture.detectChanges();
    http.expectOne((r) => r.url === `${API}/notification-rules/`).flush(page(rules));
    http.expectOne(`${API}/organizations/org-1/alert-volume/`).flush({
      days: 30,
      new_issues: { info: 9, low: 4, medium: 6, high: 3, critical: 1 },
    });
    http.expectOne(`${API}/organizations/org-1/members/`).flush([
      { id: 'm1', user_id: 1, username: 'dennis', email: 'dennis@acme.com', role: role, created_at: '' },
    ]);
    fixture.detectChanges();
    await fixture.whenStable();
  }

  function click(text: string): void {
    const button = Array.from(el.querySelectorAll('button')).find((b) => b.textContent?.includes(text));
    if (!button) throw new Error(`No button "${text}"`);
    button.click();
    fixture.detectChanges();
  }

  async function type(selector: string, value: string): Promise<void> {
    await fixture.whenStable();
    const input = el.querySelector(selector) as HTMLInputElement;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
  }

  afterEach(() => http.verify());

  it('explains both kinds of message and writes each alert as a sentence', async () => {
    await setUp([
      rule({ weekly_report: true }),
      rule({ id: 'r2', channel: 'webhook', recipient_email: '', webhook_url: HOOK, min_severity: 'critical' }),
    ]);
    expect(el.querySelector('.explain')?.textContent).toContain('Each problem is sent once');
    expect(el.querySelectorAll('.tile-foot')[1].textContent).toContain('Going to sec@acme.com');
    const rules = Array.from(el.querySelectorAll('.rule')).map((r) => r.textContent?.replace(/\s+/g, ' ') ?? '');
    expect(rules[0]).toContain('sec@acme.com');
    expect(rules[0]).toContain('Gets an email when a scan finds new critical or high issues.');
    expect(rules[0]).toContain('Also gets the Monday report.');
    expect(rules[1]).toContain('Slack channel');
    expect(rules[1]).toContain('Gets a message when a scan finds new critical issues.');
  });

  it('offers a one-click start when there are no alerts', async () => {
    await setUp([]);
    click('Email me about serious problems');
    expect(fixture.componentInstance.destination()).toBe('dennis@acme.com');
    expect(fixture.componentInstance.newSeverity()).toBe('high');
    expect(el.querySelector('.preview')?.textContent).toContain(
      'dennis@acme.com will get an email whenever a scan finds new critical or high issues, and the one-page report every Monday.',
    );
  });

  it('guides through setting up a chat alert, showing how busy each choice would be', async () => {
    await setUp([rule()]);
    click('Add an alert');
    click('Chat channel');
    click('How do I get this link?');
    expect(el.querySelector('.help')?.textContent).toContain('Incoming Webhooks');
    await type('#destination', HOOK);
    const counts = Array.from(el.querySelectorAll('.choice.level .count')).map((c) => c.textContent?.trim());
    expect(counts).toEqual(['1 in the last 30 days', '4 in the last 30 days', '10 in the last 30 days', '14 in the last 30 days']);
    click('Emergencies only');
    expect(el.querySelector('.preview')?.textContent).toContain('The chat channel will get a message whenever a scan finds new critical issues.');
    // No Monday report for a chat channel: it is a PDF.
    expect(el.textContent).not.toContain('The Monday report too?');

    click('Save alert');
    const request = http.expectOne(`${API}/notification-rules/`);
    expect(request.request.body).toEqual({
      organization: 'org-1', channel: 'webhook', webhook_url: HOOK, min_severity: 'critical', weekly_report: false,
    });
    request.flush(rule({ id: 'r2', channel: 'webhook', webhook_url: HOOK, recipient_email: '', min_severity: 'critical' }));
    fixture.detectChanges();
    expect(el.querySelectorAll('.rule').length).toBe(2);
  });

  it("shows the server's reason when an alert is refused", async () => {
    await setUp([rule()]);
    click('Add an alert');
    await type('#destination', 'sec@acme.com');
    click('Save alert');
    http
      .expectOne(`${API}/notification-rules/`)
      .flush({ non_field_errors: ['dup'] }, { status: 400, statusText: 'Bad Request' });
    fixture.detectChanges();
    expect(el.querySelector('.error')?.textContent).toContain('already an alert for this address');
  });

  it('sends a test and says whether it got through', async () => {
    await setUp([rule()]);
    const toasts = TestBed.inject(ToastService);
    const ok = spyOn(toasts, 'success');
    const bad = spyOn(toasts, 'error');
    click('Send test');
    http.expectOne(`${API}/notification-rules/r1/test/`).flush({ delivered: true, detail: 'Test email sent.' });
    expect(ok).toHaveBeenCalledWith('Test email sent.');
    fixture.detectChanges();
    click('Send test');
    http.expectOne(`${API}/notification-rules/r1/test/`).flush({ delivered: false, detail: 'Check the link.' });
    expect(bad).toHaveBeenCalledWith('Check the link.');
  });

  it('pauses and resumes an alert', async () => {
    await setUp([rule()]);
    click('Pause');
    const patch = http.expectOne(`${API}/notification-rules/r1/`);
    expect(patch.request.body).toEqual({ is_active: false });
    patch.flush(rule({ is_active: false }));
    fixture.detectChanges();
    expect(el.querySelector('.rule')?.classList).toContain('paused');
    expect(el.querySelector('.rule .badge')?.textContent).toContain('Paused');
  });

  it('turns the Monday report on and sends it on demand', async () => {
    await setUp([rule()]);
    (el.querySelector('.switch input') as HTMLInputElement).click();
    const patch = http.expectOne(`${API}/notification-rules/r1/`);
    expect(patch.request.body).toEqual({ weekly_report: true });
    patch.flush(rule({ weekly_report: true }));
    fixture.detectChanges();
    click('Send report now');
    http.expectOne(`${API}/notification-rules/r1/send-report/`).flush({ detail: 'On its way.' });
  });

  it('asks before deleting an alert, and deletes only on yes', async () => {
    await setUp([rule()]);
    const ask = spyOn(TestBed.inject(ConfirmService), 'ask').and.resolveTo(false);
    await fixture.componentInstance.deleteRule(rule());
    expect(ask.calls.mostRecent().args[0].message).toContain('sec@acme.com will no longer be emailed');
    http.expectNone(`${API}/notification-rules/r1/`);

    ask.and.resolveTo(true);
    await fixture.componentInstance.deleteRule(rule());
    http.expectOne(`${API}/notification-rules/r1/`).flush(null);
    expect(fixture.componentInstance.rules()).toEqual([]);
  });

  it('viewers can read but not change anything', async () => {
    await setUp([rule()], 'viewer');
    expect(el.querySelector('.rule-actions')).toBeNull();
    expect(el.textContent).not.toContain('Add an alert');
  });
});
