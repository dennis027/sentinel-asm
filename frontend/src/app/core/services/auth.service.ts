import { HttpClient } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, finalize, shareReplay, tap } from 'rxjs';
import { environment } from '../../../environments/environment';

interface TokenPair {
  access: string;
  refresh: string;
}

const ACCESS_TOKEN_KEY = 'sentinel_access_token';
const REFRESH_TOKEN_KEY = 'sentinel_refresh_token';
const USERNAME_KEY = 'sentinel_username';
// Owned by OrganizationContextService, cleared here too on logout so a
// different account logging in on the same browser doesn't briefly
// inherit a stale org selection before its own load completes.
const SELECTED_ORG_KEY = 'sentinel_selected_org_id';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly router = inject(Router);

  private readonly accessToken = signal<string | null>(localStorage.getItem(ACCESS_TOKEN_KEY));
  private readonly refreshToken = signal<string | null>(localStorage.getItem(REFRESH_TOKEN_KEY));
  private readonly username = signal<string | null>(localStorage.getItem(USERNAME_KEY));

  private refreshInFlight: Observable<TokenPair> | null = null;

  readonly isAuthenticated = computed(() => this.accessToken() !== null);
  readonly currentUsername = computed(() => this.username());

  getAccessToken(): string | null {
    return this.accessToken();
  }

  /**
   * With two-factor sign-in on, the first attempt (no `otp`) fails with
   * 400 and `otp_required: true`; send the same request again with the code.
   */
  login(username: string, password: string, otp?: string): Observable<TokenPair> {
    return this.http
      .post<TokenPair>(`${environment.apiBaseUrl}/auth/login/`, { username, password, ...(otp ? { otp } : {}) })
      .pipe(
        tap((tokens) => {
          this.setSession(tokens.access, tokens.refresh, username);
        }),
      );
  }

  logout(): void {
    const refresh = this.refreshToken();
    if (refresh) {
      this.http
        .post(`${environment.apiBaseUrl}/auth/logout/`, { refresh })
        .subscribe({ error: () => undefined });
    }
    this.clearSession();
    this.router.navigate(['/login']);
  }

  /**
   * Every caller that asks while a refresh is already in flight gets
   * that same request's result. This matters because refresh tokens
   * are single-use (the backend rotates and blacklists them): a page
   * that fires several requests at once gets several 401s when the
   * access token expires, and if each one refreshed on its own, the
   * first would succeed and the rest would present an already-spent
   * token, fail, and log the user out.
   */
  refreshAccessToken(): Observable<TokenPair> {
    if (!this.refreshInFlight) {
      this.refreshInFlight = this.http
        .post<TokenPair>(`${environment.apiBaseUrl}/token/refresh/`, {
          refresh: this.refreshToken(),
        })
        .pipe(
          tap((tokens) => {
            this.accessToken.set(tokens.access);
            localStorage.setItem(ACCESS_TOKEN_KEY, tokens.access);
            if (tokens.refresh) {
              this.refreshToken.set(tokens.refresh);
              localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh);
            }
          }),
          finalize(() => (this.refreshInFlight = null)),
          shareReplay({ bufferSize: 1, refCount: false }),
        );
    }
    return this.refreshInFlight;
  }

  changePassword(currentPassword: string, newPassword: string): Observable<{ detail: string }> {
    return this.http.post<{ detail: string }>(
      `${environment.apiBaseUrl}/auth/change-password/`,
      { current_password: currentPassword, new_password: newPassword },
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
    localStorage.removeItem(SELECTED_ORG_KEY);
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