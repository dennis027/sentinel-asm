import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { Invitation, Member, Organization } from '../../core/models/models';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { ConfirmService } from '../../core/services/confirm.service';
import { ToastService } from '../../core/services/toast.service';
import { makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { OrganizationPage } from './organization';

const ORGS = `${environment.apiBaseUrl}/organizations`;

function invitation(overrides: Partial<Invitation> = {}): Invitation {
  return {
    id: 'inv-1', email: 'sam@example.com', role: 'analyst', role_label: 'Security Analyst', status: 'pending',
    invited_by: 'erin', created_at: '2026-10-22T10:00:00Z', expires_at: '2026-10-29T10:00:00Z', ...overrides,
  };
}

function member(username: string, role: Member['role']): Member {
  return { id: `m-${username}`, user_id: username.length, username, email: '', role, created_at: '2026-01-01T00:00:00Z' };
}

describe('OrganizationPage', () => {
  let fixture: ComponentFixture<OrganizationPage>;
  let http: HttpTestingController;
  let el: HTMLElement;
  let context: OrganizationContextService;

  async function setUp(orgs: Organization[], members: Member[] = [], invitations: Invitation[] = []): Promise<void> {
    localStorage.clear();
    localStorage.setItem('sentinel_username', 'erin');
    await TestBed.configureTestingModule({
      imports: [OrganizationPage],
      providers: [provideAppTesting()],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    context = TestBed.inject(OrganizationContextService);

    context.loadOrganizations();
    http.expectOne((r) => r.url === `${ORGS}/`).flush(page(orgs));

    fixture = TestBed.createComponent(OrganizationPage);
    el = fixture.nativeElement;
    fixture.detectChanges();
    if (orgs.length > 0) {
      http.expectOne(`${ORGS}/${orgs[0].id}/members/`).flush(members);
      // Admins and owners also see who is still invited.
      if (orgs[0].my_role === 'owner' || orgs[0].my_role === 'admin') {
        http.expectOne(`${ORGS}/${orgs[0].id}/invitations/`).flush(invitations);
      }
      fixture.detectChanges();
    }
  }

  function messages(): string[] {
    return TestBed.inject(ToastService)
      .toasts()
      .map((t) => t.message);
  }

  afterEach(() => http.verify());

  it('welcomes a user with no organization and creates their first one', async () => {
    await setUp([]);
    expect(el.querySelector('h1')?.textContent).toContain('Welcome');

    const page_ = fixture.componentInstance;
    page_.newName.set('Acme');
    page_.newDomain.set('acme.com');
    page_.submitCreate();

    const request = http.expectOne(`${ORGS}/`);
    expect(request.request.body).toEqual({ name: 'Acme', root_domain: 'acme.com' });
    request.flush(makeOrganization({ id: 'new', domain_verified: false, scans_allowed: false }));
    fixture.detectChanges();
    http.expectOne(`${ORGS}/new/members/`).flush([member('erin', 'owner')]);
    http.expectOne(`${ORGS}/new/invitations/`).flush([]);
    fixture.detectChanges();

    expect(context.selectedOrganization()?.id).toBe('new');
    expect(el.querySelector('h1')?.textContent).toContain('Organization');
    // Straight on to the next thing they have to do.
    expect(el.textContent).toContain('sentinel-asm-verification=abc123');
  });

  it('shows the server\'s reason when a domain is rejected', async () => {
    await setUp([]);
    fixture.componentInstance.newName.set('Acme');
    fixture.componentInstance.newDomain.set('localhost');
    fixture.componentInstance.submitCreate();
    http
      .expectOne(`${ORGS}/`)
      .flush({ root_domain: ['Enter a public domain name.'] }, { status: 400, statusText: 'Bad' });
    fixture.detectChanges();
    expect(el.querySelector('form .error')?.textContent).toContain('Enter a public domain name.');
  });

  it('asks for both fields before sending anything', async () => {
    await setUp([]);
    fixture.componentInstance.submitCreate();
    fixture.detectChanges();
    expect(el.querySelector('form .error')?.textContent).toContain('Enter a name');
  });

  it('marks a verified domain and hides the DNS instructions', async () => {
    await setUp([makeOrganization()], [member('erin', 'owner')]);
    expect(el.querySelector('.badge.ok')?.textContent).toContain('Verified');
    expect(el.querySelector('.steps')).toBeNull();
  });

  it('invites by email, shows the link once, and lists the invitation', async () => {
    await setUp([makeOrganization({ my_role: 'admin' })], [member('erin', 'admin')]);
    fixture.componentInstance.inviteEmail.set('sam@example.com');
    fixture.componentInstance.inviteRole.set('analyst');
    fixture.componentInstance.invite();

    const request = http.expectOne(`${ORGS}/org-1/invitations/`);
    expect(request.request.body).toEqual({ email: 'sam@example.com', role: 'analyst' });
    request.flush(invitation({ invite_link: 'https://app/invite/tok123', email_sent: false }));
    fixture.detectChanges();

    expect(el.querySelector('.invites')?.textContent).toContain('sam@example.com');
    expect(el.querySelector('.invite-link code')?.textContent).toBe('https://app/invite/tok123');
    expect(el.querySelector('.invite-link')?.textContent).toContain("Email isn't set up");
    expect(messages()[0]).toContain('copy the link');
  });

  it('resends an invitation with a new link and cancels one after asking', async () => {
    await setUp([makeOrganization({ my_role: 'owner' })], [member('erin', 'owner')], [invitation()]);
    const page_ = fixture.componentInstance;
    page_.resendInvitation(page_.invitations()[0]);
    http.expectOne(`${ORGS}/org-1/invitations/inv-1/resend/`)
      .flush(invitation({ invite_link: 'https://app/invite/new', email_sent: true }));
    fixture.detectChanges();
    expect(el.querySelector('.invite-link')?.textContent).toContain('Emailed to');
    expect(messages()[0]).toContain('old link no longer works');

    const confirm = spyOn(TestBed.inject(ConfirmService), 'ask').and.resolveTo(true);
    await page_.cancelInvitation(page_.invitations()[0]);
    expect(confirm).toHaveBeenCalled();
    http.expectOne(`${ORGS}/org-1/invitations/inv-1/`).flush(null);
    fixture.detectChanges();
    expect(page_.invitations()).toEqual([]);
    expect(el.querySelector('.invite-link')).toBeNull();
  });

  it('does not show invitations to analysts', async () => {
    await setUp([makeOrganization({ my_role: 'analyst' })], [member('erin', 'analyst')]);
    expect(el.querySelector('form.add-member')).toBeNull();
  });

  it('does not offer the owner role to an admin, or let them edit an owner', async () => {
    await setUp(
      [makeOrganization({ my_role: 'admin' })],
      [member('erin', 'admin'), member('olga', 'owner'), member('vic', 'viewer')],
    );
    const page_ = fixture.componentInstance;
    expect(page_.assignableRoles().map((r) => r.value)).toEqual(['viewer', 'analyst', 'admin']);
    expect(page_.canEdit(member('olga', 'owner'))).toBeFalse();
    expect(page_.canEdit(member('vic', 'viewer'))).toBeTrue();
  });

  it('shows members read-only to a viewer', async () => {
    await setUp([makeOrganization({ my_role: 'viewer' })], [member('erin', 'viewer')]);
    expect(el.querySelector('.add-member')).toBeNull();
    expect(el.querySelector('tbody select')).toBeNull();
    // They can still leave.
    expect(el.querySelector('tbody button')?.textContent).toContain('Leave');
  });

  it('puts the old role back when the server refuses a change', async () => {
    await setUp([makeOrganization()], [member('erin', 'owner'), member('vic', 'viewer')]);
    fixture.componentInstance.changeRole(member('vic', 'viewer'), 'admin');
    expect(fixture.componentInstance.members()[1].role).toBe('admin');

    http
      .expectOne(`${ORGS}/org-1/members/m-vic/`)
      .flush({ detail: 'Not allowed.' }, { status: 403, statusText: 'Forbidden' });
    fixture.detectChanges();

    expect(fixture.componentInstance.members()[1].role).toBe('viewer');
    expect(el.querySelector('.error')?.textContent).toContain('Not allowed.');
  });

  it('asks before removing a member', async () => {
    await setUp([makeOrganization()], [member('erin', 'owner'), member('vic', 'viewer')]);
    const ask = spyOn(TestBed.inject(ConfirmService), 'ask').and.resolveTo(false);

    await fixture.componentInstance.removeMember(member('vic', 'viewer'));
    const question = ask.calls.mostRecent().args[0];
    expect(question.title).toBe('Remove vic from Acme?');
    expect(question.danger).toBeTrue();
    http.expectNone(`${ORGS}/org-1/members/m-vic/`);

    ask.and.resolveTo(true);
    await fixture.componentInstance.removeMember(member('vic', 'viewer'));
    http.expectOne(`${ORGS}/org-1/members/m-vic/`).flush(null);
    expect(fixture.componentInstance.members().map((m) => m.username)).toEqual(['erin']);
  });

  it('lets only the owner delete, and only after typing the domain', async () => {
    await setUp([makeOrganization(), makeOrganization({ id: 'org-2', name: 'Beta' })], [member('erin', 'owner')]);
    const button = () =>
      Array.from(el.querySelectorAll('button')).find((b) =>
        b.textContent?.includes('Delete organization'),
      ) as HTMLButtonElement;
    expect(button().disabled).toBeTrue();

    fixture.componentInstance.deleteConfirmation.set('wrong.com');
    fixture.detectChanges();
    expect(button().disabled).toBeTrue();
    fixture.componentInstance.deleteOrganization();
    http.expectNone(`${ORGS}/org-1/`);

    fixture.componentInstance.deleteConfirmation.set(' ACME.com ');
    fixture.detectChanges();
    expect(button().disabled).toBeFalse();
    button().click();

    const request = http.expectOne(`${ORGS}/org-1/`);
    expect(request.request.method).toBe('DELETE');
    request.flush(null);
    fixture.detectChanges();

    // On to the next organization, with the confirmation box cleared.
    http.expectOne(`${ORGS}/org-2/members/`).flush([]);
    http.expectOne(`${ORGS}/org-2/invitations/`).flush([]);
    expect(context.allOrganizations().map((o) => o.id)).toEqual(['org-2']);
    expect(context.selectedOrganization()?.id).toBe('org-2');
    expect(fixture.componentInstance.deleteConfirmation()).toBe('');
    expect(messages()).toEqual(['Acme and all of its data were deleted.']);
  });

  it('hides the delete section from everyone but the owner', async () => {
    await setUp([makeOrganization({ my_role: 'admin' })], [member('erin', 'admin')]);
    expect(el.querySelector('.panel.danger')).toBeNull();
  });

  it('keeps the organization and shows the reason when deletion is refused', async () => {
    await setUp([makeOrganization()], [member('erin', 'owner')]);
    fixture.componentInstance.deleteConfirmation.set('acme.com');
    fixture.componentInstance.deleteOrganization();
    http
      .expectOne(`${ORGS}/org-1/`)
      .flush({ detail: 'This action requires the Owner role.' }, { status: 403, statusText: 'Forbidden' });
    fixture.detectChanges();
    expect(el.querySelector('.panel.danger .error')?.textContent).toContain('requires the Owner role');
    expect(context.allOrganizations().length).toBe(1);
  });
});
