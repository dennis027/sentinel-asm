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
    if (refresh) {
      this.http
        .post(`${environment.apiBaseUrl}/auth/logout/`, { refresh })
        .subscribe({ error: () => undefined });
    }
    this.clearSession();
    this.router.navigate(['/login']);
  }

  refreshAccessToken(): Observable<TokenPair> {
    return this.http
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