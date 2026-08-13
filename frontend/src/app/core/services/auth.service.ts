import { HttpClient } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, tap } from 'rxjs';
import { environment } from '../../../environments/environment';

interface TokenPair {
  access: string;
  refresh: string;
}

/**
 * Both tokens live only in memory (a signal), never localStorage or
 * sessionStorage -- deliberate XSS mitigation, matching the backend's
 * own access-token-in-memory design. Trade-off: a hard page refresh
 * loses the session and requires re-login, since the backend issues
 * tokens in the JSON body rather than an httpOnly cookie. Acceptable
 * for this app; revisit if that friction becomes a real UX problem.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly router = inject(Router);

  private readonly accessToken = signal<string | null>(null);
  private readonly refreshToken = signal<string | null>(null);
  private readonly username = signal<string | null>(null);

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
          this.accessToken.set(tokens.access);
          this.refreshToken.set(tokens.refresh);
          this.username.set(username);
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
          // ROTATE_REFRESH_TOKENS is on server-side -- a new refresh
          // token comes back on every refresh, replace it.
          if (tokens.refresh) {
            this.refreshToken.set(tokens.refresh);
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
  }
}