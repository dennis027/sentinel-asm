import { HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router, convertToParamMap } from '@angular/router';
import { environment } from '../../../environments/environment';
import { InvitationDetail } from '../../core/models/models';
import { AuthService } from '../../core/services/auth.service';
import { provideAppTesting } from '../../testing/test-helpers';
import { Invite } from './invite';

const API = environment.apiBaseUrl;

function detail(overrides: Partial<InvitationDetail> = {}): InvitationDetail {
  return {
    organization: 'Acme', email: 'sam@example.com', role: 'analyst', role_label: 'Security Analyst',
    invited_by: 'Erin', expires_at: '2026-10-29T10:00:00Z', status: 'pending', detail: '', account_exists: false,
    ...overrides,
  };
}

describe('Invite', () => {
  async function setUp(invitation: InvitationDetail | null, signedInAs?: string) {
    localStorage.clear();
    if (signedInAs) localStorage.setItem('sentinel_access_token', 'a');
    await TestBed.configureTestingModule({
      imports: [Invite],
      providers: [
        provideAppTesting(),
        { provide: ActivatedRoute, useValue: { snapshot: { paramMap: convertToParamMap({ token: 'tok' }) } } },
      ],
    }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(Invite);
    fixture.detectChanges();
    const request = http.expectOne(`${API}/invitations/tok/`);
    if (invitation) request.flush(invitation);
    else request.flush({ detail: 'nope' }, { status: 404, statusText: 'Not Found' });
    if (signedInAs) http.expectOne(`${API}/auth/me/`).flush({ username: signedInAs, email: signedInAs });
    fixture.detectChanges();
    return { fixture, http, el: fixture.nativeElement as HTMLElement };
  }

  afterEach(() => TestBed.inject(HttpTestingController).verify());

  it('lets a new person create their account and join', async () => {
    const { fixture, http, el } = await setUp(detail());
    expect(el.textContent).toContain('Erin invited sam@example.com to join Acme as Security Analyst');
    const navigate = spyOn(TestBed.inject(Router), 'navigate').and.resolveTo(true);
    const page = fixture.componentInstance;
    page.firstName.set('Sam');
    page.password.set('A-new-secret-9');
    page.confirm.set('A-new-secret-9');
    page.createAccount();
    const accept = http.expectOne(`${API}/invitations/tok/accept/`);
    expect(accept.request.body).toEqual({ password: 'A-new-secret-9', first_name: 'Sam', last_name: '' });
    accept.flush({ organization: 'org-1', role: 'analyst', username: 'sam@example.com', created_account: true,
                   access: 'a', refresh: 'r' });
    http.expectOne((r) => r.url === `${API}/organizations/`).flush({ count: 0, next: null, previous: null, results: [] });
    expect(TestBed.inject(AuthService).currentUsername()).toBe('sam@example.com');
    expect(navigate).toHaveBeenCalledWith(['/dashboard']);
  });

  it('asks an existing account to sign in, and comes back here after', async () => {
    const { el } = await setUp(detail({ account_exists: true }));
    const link = el.querySelector('a.btn') as HTMLAnchorElement;
    expect(link.textContent).toContain('Sign in to accept');
    expect(decodeURIComponent(link.href)).toContain('redirect=/invite/tok');
  });

  it('joins with one click when signed in as the invited address', async () => {
    const { fixture, http, el } = await setUp(detail({ account_exists: true }), 'sam@example.com');
    spyOn(TestBed.inject(Router), 'navigate').and.resolveTo(true);
    expect(el.querySelector('button.btn')?.textContent).toContain('Join Acme');
    fixture.componentInstance.join();
    const accept = http.expectOne(`${API}/invitations/tok/accept/`);
    expect(accept.request.body).toEqual({});
    accept.flush({ organization: 'org-1', role: 'analyst', username: 'sam', created_account: false });
    http.expectOne((r) => r.url === `${API}/organizations/`).flush({ count: 0, next: null, previous: null, results: [] });
  });

  it('warns when signed in as someone else', async () => {
    const { el } = await setUp(detail(), 'erin@acme.com');
    expect(el.querySelector('.warn')?.textContent).toContain('erin@acme.com');
  });

  it('explains spent and invalid links', async () => {
    const spent = await setUp(detail({ status: 'expired', detail: 'This invitation has expired.' }));
    expect(spent.el.querySelector('.error')?.textContent).toContain('expired');
    TestBed.resetTestingModule();
    const invalid = await setUp(null);
    expect(invalid.el.querySelector('.error')?.textContent).toContain("isn't valid");
  });
});
