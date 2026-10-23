import { HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router, convertToParamMap } from '@angular/router';
import { environment } from '../../../environments/environment';
import { provideAppTesting } from '../../testing/test-helpers';
import { ResetPassword } from './reset-password';

const URL = `${environment.apiBaseUrl}/auth/password-reset/confirm/`;

describe('ResetPassword', () => {
  async function setUp() {
    await TestBed.configureTestingModule({
      imports: [ResetPassword],
      providers: [
        provideAppTesting(),
        { provide: ActivatedRoute, useValue: { snapshot: { paramMap: convertToParamMap({ uid: 'MQ', token: 'tok' }) } } },
      ],
    }).compileComponents();
    const fixture = TestBed.createComponent(ResetPassword);
    fixture.detectChanges();
    return { fixture, http: TestBed.inject(HttpTestingController), el: fixture.nativeElement as HTMLElement };
  }

  it('sets the new password and sends the person to sign in', async () => {
    const { fixture, http } = await setUp();
    const navigate = spyOn(TestBed.inject(Router), 'navigate').and.resolveTo(true);
    fixture.componentInstance.password.set('A-new-secret-9');
    fixture.componentInstance.confirm.set('A-new-secret-9');
    fixture.componentInstance.submit();
    const request = http.expectOne(URL);
    expect(request.request.body).toEqual({ uid: 'MQ', token: 'tok', new_password: 'A-new-secret-9' });
    request.flush({ detail: 'ok', username: 'erin' });
    expect(navigate.calls.mostRecent().args[0]).toEqual(['/login']);
  });

  it('refuses mismatched passwords and explains a spent link', async () => {
    const { fixture, http, el } = await setUp();
    fixture.componentInstance.password.set('A-new-secret-9');
    fixture.componentInstance.confirm.set('different');
    fixture.detectChanges();
    expect(el.textContent).toContain("don't match");
    fixture.componentInstance.submit();
    http.expectNone(URL);

    fixture.componentInstance.confirm.set('A-new-secret-9');
    fixture.componentInstance.submit();
    http.expectOne(URL).flush({ token: ['This link is invalid or has expired. Ask for a new one.'] },
                              { status: 400, statusText: 'Bad Request' });
    fixture.detectChanges();
    expect(el.querySelector('.error')?.textContent).toContain('invalid or has expired');
    expect(el.querySelector('a[href="/forgot-password"]')).not.toBeNull();
  });
});
