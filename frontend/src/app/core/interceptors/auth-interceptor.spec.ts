import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { environment } from '../../../environments/environment';
import { AuthService } from '../services/auth.service';

import { authInterceptor } from './auth-interceptor';

const API = environment.apiBaseUrl;
const UNAUTHORIZED = { status: 401, statusText: 'Unauthorized' };

describe('authInterceptor', () => {
  let client: HttpClient;
  let http: HttpTestingController;
  let auth: AuthService;
  let router: Router;

  beforeEach(() => {
    localStorage.clear();
    localStorage.setItem('sentinel_access_token', 'expired-access');
    localStorage.setItem('sentinel_refresh_token', 'refresh-1');

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    });
    client = TestBed.inject(HttpClient);
    http = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);
    router = TestBed.inject(Router);
    spyOn(router, 'navigate').and.resolveTo(true);
  });

  afterEach(() => http.verify());

  it('attaches the access token to API requests', () => {
    client.get(`${API}/assets/`).subscribe();
    const request = http.expectOne(`${API}/assets/`);
    expect(request.request.headers.get('Authorization')).toBe('Bearer expired-access');
    request.flush({});
  });

  it('does not attach it to the login request', () => {
    client.post(`${API}/auth/login/`, {}).subscribe();
    const request = http.expectOne(`${API}/auth/login/`);
    expect(request.request.headers.has('Authorization')).toBeFalse();
    request.flush({});
  });

  it('refreshes once and retries every request when several get a 401 together', () => {
    const responses: unknown[] = [];
    client.get(`${API}/assets/`).subscribe((r) => responses.push(r));
    client.get(`${API}/findings/`).subscribe((r) => responses.push(r));
    client.get(`${API}/organizations/org-1/risk-summary/`).subscribe((r) => responses.push(r));

    http.expectOne(`${API}/assets/`).flush({}, UNAUTHORIZED);
    http.expectOne(`${API}/findings/`).flush({}, UNAUTHORIZED);
    http.expectOne(`${API}/organizations/org-1/risk-summary/`).flush({}, UNAUTHORIZED);

    // The whole point: three 401s, exactly one refresh. Refresh tokens
    // are single-use, so a second one here would have logged the user out.
    http.expectOne(`${API}/token/refresh/`).flush({ access: 'fresh-access', refresh: 'refresh-2' });

    for (const url of ['/assets/', '/findings/', '/organizations/org-1/risk-summary/']) {
      const retried = http.expectOne(`${API}${url}`);
      expect(retried.request.headers.get('Authorization')).toBe('Bearer fresh-access');
      retried.flush({ url });
    }

    expect(responses.length).toBe(3);
    expect(auth.isAuthenticated()).toBeTrue();
    expect(router.navigate).not.toHaveBeenCalled();
  });

  it('ends the session and goes to login when the refresh itself fails', () => {
    let failed = false;
    client.get(`${API}/assets/`).subscribe({ error: () => (failed = true) });

    http.expectOne(`${API}/assets/`).flush({}, UNAUTHORIZED);
    http.expectOne(`${API}/token/refresh/`).flush({}, UNAUTHORIZED);

    expect(failed).toBeTrue();
    expect(auth.isAuthenticated()).toBeFalse();
    expect(router.navigate).toHaveBeenCalledWith(['/login'], jasmine.anything());
  });

  it('passes non-401 errors straight through', () => {
    let status = 0;
    client.get(`${API}/assets/`).subscribe({ error: (e) => (status = e.status) });
    http.expectOne(`${API}/assets/`).flush({}, { status: 403, statusText: 'Forbidden' });
    expect(status).toBe(403);
    http.expectNone(`${API}/token/refresh/`);
  });
});
