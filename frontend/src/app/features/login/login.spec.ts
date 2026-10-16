import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { environment } from '../../../environments/environment';
import { provideAppTesting } from '../../testing/test-helpers';

import { Login } from './login';

const API = environment.apiBaseUrl;

describe('Login', () => {
  let fixture: ComponentFixture<Login>;
  let http: HttpTestingController;
  let el: HTMLElement;

  beforeEach(async () => {
    localStorage.clear();
    await TestBed.configureTestingModule({
      imports: [Login],
      providers: [provideAppTesting()],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(Login);
    el = fixture.nativeElement;
    fixture.detectChanges();
  });

  afterEach(() => http.verify());

  function type(selector: string, value: string): void {
    const input = el.querySelector(selector) as HTMLInputElement;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
  }

  function submit(): void {
    (el.querySelector('button[type=submit]') as HTMLButtonElement).click();
    fixture.detectChanges();
  }

  it('says when the username or password is wrong', () => {
    type('#username', 'dennis');
    type('#password', 'nope');
    submit();
    http.expectOne(`${API}/auth/login/`).flush({ detail: 'x' }, { status: 401, statusText: 'Unauthorized' });
    fixture.detectChanges();
    expect(el.querySelector('.error')?.textContent).toContain('Incorrect username or password');
  });

  it('asks for the authenticator code when two-factor sign-in is on', async () => {
    const navigate = spyOn(TestBed.inject(Router), 'navigateByUrl');
    type('#username', 'dennis');
    type('#password', 'secret');
    submit();
    const first = http.expectOne(`${API}/auth/login/`);
    expect(first.request.body).toEqual({ username: 'dennis', password: 'secret' });
    first.flush({ otp_required: true, detail: 'Enter the code' }, { status: 400, statusText: 'Bad Request' });
    fixture.detectChanges();

    expect(el.querySelector('.two-factor')?.textContent).toContain('dennis');
    expect(el.querySelector('.error')).toBeNull();
    // A newly shown input joins the form a tick later.
    await fixture.whenStable();
    type('#code', '111111');
    submit();
    http
      .expectOne(`${API}/auth/login/`)
      .flush({ otp_required: true, otp: ["That code isn't right."] }, { status: 400, statusText: 'Bad Request' });
    fixture.detectChanges();
    expect(el.querySelector('.error')?.textContent).toContain("That code isn't right");

    type('#code', '287082');
    submit();
    const last = http.expectOne(`${API}/auth/login/`);
    expect(last.request.body).toEqual({ username: 'dennis', password: 'secret', otp: '287082' });
    last.flush({ access: 'a', refresh: 'r' });
    expect(navigate).toHaveBeenCalledWith('/dashboard');
  });
});
