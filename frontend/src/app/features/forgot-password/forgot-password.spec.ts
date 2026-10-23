import { HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { provideAppTesting } from '../../testing/test-helpers';
import { ForgotPassword } from './forgot-password';

describe('ForgotPassword', () => {
  it('sends the address and shows the same answer whatever it is', async () => {
    await TestBed.configureTestingModule({ imports: [ForgotPassword], providers: [provideAppTesting()] }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(ForgotPassword);
    fixture.detectChanges();
    fixture.componentInstance.email.set('erin@acme.com');
    fixture.componentInstance.submit();
    const request = http.expectOne(`${environment.apiBaseUrl}/auth/password-reset/`);
    expect(request.request.body).toEqual({ email: 'erin@acme.com' });
    request.flush({ detail: "If an account uses that address, we've sent it a link." });
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.note').textContent).toContain('If an account uses that address');
    http.verify();
  });
});
