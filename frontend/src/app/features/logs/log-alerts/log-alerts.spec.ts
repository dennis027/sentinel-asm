import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../../environments/environment';
import { LogAlertRule, LogSource } from '../../../core/models/models';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { makeOrganization, page, provideAppTesting } from '../../../testing/test-helpers';

import { LogAlerts } from './log-alerts';

const API = environment.apiBaseUrl;

const PAYMENTS = { id: 's3', name: 'payments' } as LogSource;

function rule(overrides: Partial<LogAlertRule> = {}): LogAlertRule {
  return {
    id: 'r1', organization: 'org-1', name: 'Payments failing', contains: 'payment', source: 's3',
    source_name: 'payments', category: '', level: 'error', threshold: 10, window_minutes: 5, severity: 'high',
    enabled: true, created_by: 'amina', created_at: '', last_fired_at: '2026-10-16T09:00:00Z', matches_24h: 42,
    ...overrides,
  };
}

describe('LogAlerts', () => {
  let fixture: ComponentFixture<LogAlerts>;
  let http: HttpTestingController;
  let el: HTMLElement;

  async function setUp(rules: LogAlertRule[], canEdit = true): Promise<void> {
    await TestBed.configureTestingModule({ imports: [LogAlerts], providers: [provideAppTesting()] }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));
    fixture = TestBed.createComponent(LogAlerts);
    fixture.componentRef.setInput('sources', [PAYMENTS]);
    fixture.componentRef.setInput('canEdit', canEdit);
    el = fixture.nativeElement;
    fixture.detectChanges();
    http.expectOne(`${API}/log-alert-rules/?organization=org-1`).flush(rules);
    fixture.detectChanges();
    await fixture.whenStable();
  }

  function button(text: string): HTMLButtonElement {
    const found = Array.from(el.querySelectorAll('button')).find((b) => b.textContent?.includes(text));
    if (!found) throw new Error(`No button "${text}"`);
    return found;
  }

  afterEach(() => http.verify());

  it('starts from an idea, explains it in a sentence, tests it and turns it on', async () => {
    await setUp([]);
    button('Payments failing').click();
    fixture.detectChanges();
    await fixture.whenStable();
    expect((el.querySelector('#alert-contains') as HTMLInputElement).value).toBe('payment');
    expect(el.querySelector('.sentence')?.textContent).toContain(
      'Alert (high) when “payment” at error level appears 10 times within 5 minutes on any server or app.',
    );

    fixture.componentInstance.update('source', 's3');
    fixture.detectChanges();
    expect(el.querySelector('.sentence')?.textContent).toContain('on payments.');

    button('Test on the last 24 hours').click();
    const preview = http.expectOne(`${API}/log-alert-rules/preview/`);
    expect(preview.request.body).toEqual(jasmine.objectContaining({ organization: 'org-1', contains: 'payment', source: 's3' }));
    preview.flush({ matches_24h: 3, examples: [{ id: 1, occurred_at: '2026-10-16T09:00:00Z', source_name: 'payments',
                                                 message: 'payment declined for order 7' }] });
    fixture.detectChanges();
    expect(el.querySelector('.preview')?.textContent).toContain('3 matching events');
    expect(el.querySelector('.preview code')?.textContent).toContain('payment declined for order 7');

    button('Turn on alert').click();
    const create = http.expectOne((r) => r.method === 'POST' && r.url === `${API}/log-alert-rules/`);
    expect(create.request.body).toEqual({
      organization: 'org-1', name: 'Payments failing', contains: 'payment', source: 's3', category: '',
      level: 'error', threshold: 10, window_minutes: 5, severity: 'high',
    });
    create.flush(rule());
    http.expectOne(`${API}/log-alert-rules/?organization=org-1`).flush([rule()]);
    fixture.detectChanges();
    expect(el.querySelector('.alert-form')).toBeNull();
    expect(el.querySelector('.own-list')?.textContent).toContain('42 matches in 24 h');
  });

  it('shows why a save failed', async () => {
    await setUp([]);
    fixture.componentInstance.start();
    fixture.detectChanges();
    button('Turn on alert').click();
    http.expectOne((r) => r.method === 'POST').flush(
      { contains: ['Say what to look for: some text, a kind of event, or both.'] },
      { status: 400, statusText: 'Bad Request' },
    );
    fixture.detectChanges();
    expect(el.querySelector('.error')?.textContent).toContain('Say what to look for');
  });

  it('switches an alert off and edits it', async () => {
    await setUp([rule()]);
    (el.querySelector('.switch input') as HTMLInputElement).dispatchEvent(new Event('change'));
    http.expectOne(`${API}/log-alert-rules/r1/`).flush(rule({ enabled: false }));
    fixture.detectChanges();
    expect(el.querySelector('.own-list li')?.classList).toContain('off');

    button('Edit').click();
    fixture.detectChanges();
    await fixture.whenStable();
    expect((el.querySelector('#alert-name') as HTMLInputElement).value).toBe('Payments failing');
    button('Save changes').click();
    const save = http.expectOne((r) => r.method === 'PATCH');
    expect(save.request.url).toBe(`${API}/log-alert-rules/r1/`);
    save.flush(rule());
    http.expectOne(`${API}/log-alert-rules/?organization=org-1`).flush([rule()]);
  });

  it('viewers see the alerts but cannot change them', async () => {
    await setUp([rule({ enabled: false })], false);
    expect(el.textContent).toContain('Payments failing');
    expect(el.querySelector('.switch')).toBeNull();
    expect(Array.from(el.querySelectorAll('button')).some((b) => b.textContent?.includes('New alert'))).toBeFalse();
  });
});
