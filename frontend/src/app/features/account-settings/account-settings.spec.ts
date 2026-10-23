import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { Router } from '@angular/router';
import { ConfirmService } from '../../core/services/confirm.service';
import { provideAppTesting } from '../../testing/test-helpers';

import { AccountSettings } from './account-settings';

const API = environment.apiBaseUrl;

const PROFILE = {
  id: 1, username: 'erin', email: 'erin@acme.com', first_name: 'Erin', last_name: 'Otieno',
  date_joined: '2026-01-01T00:00:00Z', last_login: null, two_factor_enabled: false,
};

describe('AccountSettings', () => {
  let fixture: ComponentFixture<AccountSettings>;
  let http: HttpTestingController;
  let el: HTMLElement;

  beforeEach(async () => {
    localStorage.clear();
    await TestBed.configureTestingModule({
      imports: [AccountSettings],
      providers: [provideAppTesting()],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(AccountSettings);
    el = fixture.nativeElement;
    fixture.detectChanges();
    http.expectOne(`${API}/auth/2fa/`).flush({ enabled: false, enabled_at: null });
    http.expectOne(`${API}/auth/api-keys/`).flush([
      { id: 'k1', name: 'Splunk', prefix: 'sasm_abc1234', created_at: '2026-01-01T00:00:00Z', last_used_at: null },
    ]);
    http.expectOne(`${API}/auth/sign-ins/`).flush([
      { id: 'e1', event_type: 'login_failed', label: 'Login failed', ip_address: '203.0.113.9',
        user_agent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/120.0', created_at: '2026-01-01T00:00:00Z' },
    ]);
    http.expectOne(`${API}/auth/me/`).flush(PROFILE);
    fixture.detectChanges();
  });

  afterEach(() => http.verify());

  it('lists API keys without the keys themselves, and recent sign-ins', () => {
    expect(el.textContent).toContain('sasm_abc1234…');
    expect(el.textContent).toContain('Chrome on Windows');
    expect(el.textContent).toContain('203.0.113.9');
  });

  it('shows a new key once, right after creating it', () => {
    const name = el.querySelector('input[name=key-name]') as HTMLInputElement;
    name.value = 'CI pipeline';
    name.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    const create = Array.from(el.querySelectorAll('button')).find((b) => b.textContent?.includes('Create key'));
    create!.click();
    const request = http.expectOne(`${API}/auth/api-keys/`);
    expect(request.request.body).toEqual({ name: 'CI pipeline' });
    request.flush({ id: 'k2', name: 'CI pipeline', prefix: 'sasm_xyz', created_at: '', last_used_at: null, key: 'sasm_xyz_full' });
    fixture.detectChanges();
    expect(el.querySelector('.new-key')?.textContent).toContain('sasm_xyz_full');
    expect(el.querySelectorAll('tbody tr').length).toBeGreaterThanOrEqual(2);
  });

  it('sets up two-factor sign-in with a QR code and a confirming code', async () => {
    const start = Array.from(el.querySelectorAll('button')).find((b) => b.textContent?.includes('Set up two-factor'));
    start!.click();
    http.expectOne(`${API}/auth/2fa/setup/`).flush({
      secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/x', qr_svg: '<svg data-test="qr"></svg>',
    });
    fixture.detectChanges();
    expect(el.querySelector('.qr svg')).not.toBeNull();
    expect(el.querySelector('.secret')?.textContent).toBe('JBSWY3DPEHPK3PXP');
    // A newly shown input joins the form a tick later.
    await fixture.whenStable();

    const code = el.querySelector('input[name=code]') as HTMLInputElement;
    code.value = '123456';
    code.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    const turnOn = Array.from(el.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Turn on');
    turnOn!.click();
    http.expectOne(`${API}/auth/2fa/confirm/`).flush({ enabled: true, enabled_at: '2026-01-05T00:00:00Z' });
    http.expectOne(`${API}/auth/sign-ins/`).flush([]);
    fixture.detectChanges();
    expect(el.querySelector('.panel-header .badge')?.textContent).toContain('On');
  });

  it('shows the profile and saves a changed name', () => {
    expect(el.querySelector('.facts-inline')?.textContent).toContain('erin@acme.com');
    fixture.componentInstance.firstName.set('Erinn');
    fixture.componentInstance.saveProfile();
    const request = http.expectOne(`${API}/auth/me/`);
    expect(request.request.method).toBe('PATCH');
    expect(request.request.body).toEqual({ first_name: 'Erinn', last_name: 'Otieno' });
    request.flush({ ...PROFILE, first_name: 'Erinn' });
    expect(fixture.componentInstance.profile()?.first_name).toBe('Erinn');
  });

  it('changes the email address with the current password, and shows why it was refused', () => {
    const page = fixture.componentInstance;
    page.newEmail.set('erin@new.com');
    page.emailPassword.set('wrong');
    page.changeEmail();
    const refused = http.expectOne(`${API}/auth/me/email/`);
    expect(refused.request.body).toEqual({ email: 'erin@new.com', current_password: 'wrong' });
    refused.flush({ current_password: ['Incorrect password.'] }, { status: 400, statusText: 'Bad Request' });
    fixture.detectChanges();
    expect(el.textContent).toContain('Incorrect password.');

    page.emailPassword.set('right');
    page.changeEmail();
    http.expectOne(`${API}/auth/me/email/`).flush({ ...PROFILE, email: 'erin@new.com' });
    expect(page.profile()?.email).toBe('erin@new.com');
    expect(page.emailPassword()).toBe('');
  });

  it('signs out every device after asking, then goes to sign-in', async () => {
    spyOn(TestBed.inject(ConfirmService), 'ask').and.resolveTo(true);
    const navigate = spyOn(TestBed.inject(Router), 'navigate').and.resolveTo(true);
    await fixture.componentInstance.signOutEverywhere();
    http.expectOne(`${API}/auth/sessions/revoke/`).flush({ signed_out: 3, detail: 'ok' });
    expect(navigate).toHaveBeenCalledWith(['/login'], { queryParams: { message: 'Signed out on every device.' } });
  });
});
