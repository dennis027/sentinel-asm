import { HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { environment } from '../../../environments/environment';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeFinding, makeOrganization, page } from '../../testing/test-helpers';

import { FindingDetail } from './finding-detail';

const API = environment.apiBaseUrl;

describe('FindingDetail', () => {
  let http: HttpTestingController;
  let harness: RouterTestingHarness;
  let el: HTMLElement;

  beforeEach(async () => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([{ path: 'findings/:id', component: FindingDetail }]),
      ],
    });
    http = TestBed.inject(HttpTestingController);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));

    harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/findings/f1');
    el = harness.routeNativeElement!;
    http.expectOne(`${API}/organizations/org-1/members/`).flush([]);
    http.expectOne(`${API}/findings/f1/`).flush(
      makeFinding({
        id: 'f1',
        title: 'Open port 3389/tcp (ms-wbt-server)',
        severity: 'high',
        impact: 'Remote desktop is a top ransomware entry point.',
        remediation: 'Put it behind the VPN.',
        due_at: '2026-02-01T00:00:00Z',
        reopened_count: 1,
        asset_criticality: 'crown_jewel',
        controls: [
          { id: 'attack:T1133', framework: 'attack', code: 'T1133', name: 'External Remote Services' },
          { id: 'owasp:A05', framework: 'owasp', code: 'A05', name: 'Security Misconfiguration' },
        ],
      }),
    );
    http.expectOne(`${API}/findings/f1/timeline/`).flush([
      { kind: 'detected', at: '2026-01-01T00:00:00Z', actor: '', text: 'First detected by Port scan' },
      { kind: 'comment', at: '2026-01-02T00:00:00Z', actor: 'brian', text: 'Looking at it' },
    ]);
    harness.detectChanges();
  });

  afterEach(() => http.verify());

  it('explains the finding, its attacker technique and its history', () => {
    expect(el.querySelector('h1')?.textContent).toContain('Open port 3389');
    expect(el.textContent).toContain('Came back');
    expect(el.textContent).toContain('Crown jewel');
    const technique = el.querySelector('.techniques a') as HTMLAnchorElement;
    expect(technique.textContent?.trim()).toBe('T1133');
    expect(technique.href).toBe('https://attack.mitre.org/techniques/T1133/');
    expect(el.querySelector('.chips')?.textContent).toContain('OWASP A05');
    const entries = el.querySelectorAll('.timeline li');
    expect(entries.length).toBe(2);
    expect(entries[1].textContent).toContain('Looking at it');
  });

  it('posts a comment and refreshes the history', () => {
    const textarea = el.querySelector('textarea') as HTMLTextAreaElement;
    textarea.value = 'Closed the port';
    textarea.dispatchEvent(new Event('input'));
    harness.detectChanges();
    (el.querySelector('.comment-form button') as HTMLButtonElement).click();
    const post = http.expectOne(`${API}/findings/f1/comments/`);
    expect(post.request.body).toEqual({ body: 'Closed the port' });
    post.flush({ id: 'c1', author_name: 'owner', body: 'Closed the port', created_at: '' });
    http.expectOne(`${API}/findings/f1/timeline/`).flush([]);
  });

  it('accepts the risk until a date', () => {
    const date = el.querySelector('input[type=date]') as HTMLInputElement;
    date.value = '2027-03-01';
    date.dispatchEvent(new Event('input'));
    harness.detectChanges();
    const accept = Array.from(el.querySelectorAll('.decide button')).find((b) => b.textContent?.includes('Accept risk'));
    (accept as HTMLButtonElement).click();
    const request = http.expectOne(`${API}/findings/f1/triage/`);
    expect(request.request.body).toEqual({ status: 'accepted', note: '', accepted_until: '2027-03-01' });
    request.flush(makeFinding({ id: 'f1', status: 'accepted', accepted_until: '2027-03-01' }));
    http.expectOne(`${API}/findings/f1/timeline/`).flush([]);
  });
});
