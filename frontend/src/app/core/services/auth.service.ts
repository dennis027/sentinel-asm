import { HttpClient } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, tap } from 'rxjs';
import { environment } from '../../../environments/environment';

interface TokenPair {
  access: string;
  refresh: string;
}

const ACCESS_TOKEN_KEY = 'sentinel_access_token';
const REFRESH_TOKEN_KEY = 'sentinel_refresh_token';
const USERNAME_KEY = 'sentinel_username';

/**
 * Tokens persist in localStorage so a page reload doesn't force a
 * re-login -- a deliberate trade-off, not an oversight. This is
 * LESS XSS-resistant than the memory-only approach (any injected
 * script can read localStorage), but is the standard, accepted choice
 * for most apps that aren't handling especially high-value sessions.
 * If this app's threat model changes later, the fix is httpOnly
 * cookies issued by the backend instead -- that requires backend
 * changes (Set-Cookie on login/refresh), not just a frontend swap.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly router = inject(Router);

  private readonly accessToken = signal<string | null>(localStorage.getItem(ACCESS_TOKEN_KEY));
  private readonly refreshToken = signal<string | null>(localStorage.getItem(REFRESH_TOKEN_KEY));
  private readonly username = signal<string | null>(localStorage.getItem(USERNAME_KEY));

  readonly isAuthenticated = computed(() => this.accessToken() !== null);
  readonly currentUsername = computed(() => this.username());

  getAccessToken(): string | null {
    return this.accessToken();
  }

  login(username: string, password: string): Observable<TokenPair> {
    return this.http
      .post<TokenPair>(`${environment.apiBaseUrl}/auth/login/`, { username, password })
      .pipe(
        tap((tokens) => {
          this.setSession(tokens.access, tokens.refresh, username);
        }),
      );
  }

  logout(): void {
    const refresh = this.refreshToken();
    // Fire-and-forget: clear local state regardless of whether the
    // blacklist call succeeds (e.g. network drop) -- the user should
    // never be stuck "logged in" locally just because this one request
    // failed.
    if (refresh) {
      this.http
        .post(`${environment.apiBaseUrl}/auth/logout/`, { refresh })
        .subscribe({ error: () => undefined });
    }
    this.clearSession();
    this.router.navigate(['/login']);
  }

  /** Called by the auth interceptor on a 401 to attempt a silent refresh. */
  refreshAccessToken(): Observable<TokenPair> {
    return this.http
      .post<TokenPair>(`${environment.apiBaseUrl}/token/refresh/`, {
        refresh: this.refreshToken(),
      })
      .pipe(
        tap((tokens) => {
          this.accessToken.set(tokens.access);
          localStorage.setItem(ACCESS_TOKEN_KEY, tokens.access);
          // ROTATE_REFRESH_TOKENS is on server-side -- a new refresh
          // token comes back on every refresh, replace it.
          if (tokens.refresh) {
            this.refreshToken.set(tokens.refresh);
            localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh);
          }
        }),
      );
  }

  hasRefreshToken(): boolean {
    return this.refreshToken() !== null;
  }

  getRefreshToken(): string | null {
    return this.refreshToken();
  }

  clearSession(): void {
    this.accessToken.set(null);
    this.refreshToken.set(null);
    this.username.set(null);
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(USERNAME_KEY);
  }

  private setSession(access: string, refresh: string, username: string): void {
    this.accessToken.set(access);
    this.refreshToken.set(refresh);
    this.username.set(username);
    localStorage.setItem(ACCESS_TOKEN_KEY, access);
    localStorage.setItem(REFRESH_TOKEN_KEY, refresh);
    localStorage.setItem(USERNAME_KEY, username);
  }
}