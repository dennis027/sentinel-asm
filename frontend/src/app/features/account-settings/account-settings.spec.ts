import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { provideAppTesting } from '../../testing/test-helpers';

import { AccountSettings } from './account-settings';

const API = environment.apiBaseUrl;

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
});
