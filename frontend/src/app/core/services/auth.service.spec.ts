import { HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { provideAppTesting } from '../../testing/test-helpers';

import { AuthService } from './auth.service';

describe('AuthService', () => {
  let service: AuthService;
  let http: HttpTestingController;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({ providers: [provideAppTesting()] });
    service = TestBed.inject(AuthService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  function logIn(asTyped = 'erin'): void {
    service.login(asTyped, 'pw').subscribe();
    http
      .expectOne(`${environment.apiBaseUrl}/auth/login/`)
      .flush({ access: 'access-1', refresh: 'refresh-1' });
    // Then: who is this account, really (signing in with an email gives the email).
    http.expectOne(`${environment.apiBaseUrl}/auth/me/`).flush({ username: 'erin' });
  }

  it('remembers the real username after signing in with an email address', () => {
    logIn('erin@acme.com');
    expect(service.currentUsername()).toBe('erin');
    expect(localStorage.getItem('sentinel_username')).toBe('erin');
  });

  it('starts a session from an invitation that created the account', () => {
    service.startSession('a', 'r', 'new@acme.com');
    expect(service.isAuthenticated()).toBeTrue();
    expect(service.currentUsername()).toBe('new@acme.com');
  });

  it('stores the session on login', () => {
    expect(service.isAuthenticated()).toBeFalse();
    logIn();
    expect(service.isAuthenticated()).toBeTrue();
    expect(service.getAccessToken()).toBe('access-1');
    expect(service.currentUsername()).toBe('erin');
    expect(localStorage.getItem('sentinel_refresh_token')).toBe('refresh-1');
  });

  it('clearSession forgets everything, including the selected organization', () => {
    logIn();
    localStorage.setItem('sentinel_selected_org_id', 'org-1');
    service.clearSession();
    expect(service.isAuthenticated()).toBeFalse();
    expect(service.hasRefreshToken()).toBeFalse();
    expect(localStorage.length).toBe(0);
  });

  it('shares one refresh request between simultaneous callers', () => {
    logIn();
    const results: string[] = [];
    service.refreshAccessToken().subscribe((t) => results.push(t.access));
    service.refreshAccessToken().subscribe((t) => results.push(t.access));
    service.refreshAccessToken().subscribe((t) => results.push(t.access));

    // expectOne fails if the three callers produced more than one request.
    const request = http.expectOne(`${environment.apiBaseUrl}/token/refresh/`);
    expect(request.request.body).toEqual({ refresh: 'refresh-1' });
    request.flush({ access: 'access-2', refresh: 'refresh-2' });

    expect(results).toEqual(['access-2', 'access-2', 'access-2']);
    expect(service.getAccessToken()).toBe('access-2');
    expect(service.getRefreshToken()).toBe('refresh-2');
  });

  it('starts a new refresh once the previous one has finished', () => {
    logIn();
    service.refreshAccessToken().subscribe();
    http
      .expectOne(`${environment.apiBaseUrl}/token/refresh/`)
      .flush({ access: 'access-2', refresh: 'refresh-2' });

    service.refreshAccessToken().subscribe();
    const second = http.expectOne(`${environment.apiBaseUrl}/token/refresh/`);
    expect(second.request.body).toEqual({ refresh: 'refresh-2' });
    second.flush({ access: 'access-3', refresh: 'refresh-3' });
  });

  it('can retry after a failed refresh', () => {
    logIn();
    let failed = false;
    service.refreshAccessToken().subscribe({ error: () => (failed = true) });
    http
      .expectOne(`${environment.apiBaseUrl}/token/refresh/`)
      .flush({}, { status: 401, statusText: 'Unauthorized' });
    expect(failed).toBeTrue();

    service.refreshAccessToken().subscribe();
    http
      .expectOne(`${environment.apiBaseUrl}/token/refresh/`)
      .flush({ access: 'access-2', refresh: 'refresh-2' });
    expect(service.getAccessToken()).toBe('access-2');
  });
});
