import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { ApiKey, SignInEvent, TwoFactorSetup } from '../models/models';

export interface TwoFactorStatus {
  enabled: boolean;
  enabled_at: string | null;
}

/** The signed-in person's own security settings: two-factor sign-in, API keys, sign-in history. */
@Injectable({ providedIn: 'root' })
export class AccountService {
  private readonly http = inject(HttpClient);
  private readonly base = `${environment.apiBaseUrl}/auth`;

  twoFactorStatus(): Observable<TwoFactorStatus> {
    return this.http.get<TwoFactorStatus>(`${this.base}/2fa/`);
  }

  /** A fresh secret and its QR code; nothing changes at sign-in until confirmed. */
  startTwoFactor(): Observable<TwoFactorSetup> {
    return this.http.post<TwoFactorSetup>(`${this.base}/2fa/setup/`, {});
  }

  confirmTwoFactor(code: string): Observable<TwoFactorStatus> {
    return this.http.post<TwoFactorStatus>(`${this.base}/2fa/confirm/`, { code });
  }

  disableTwoFactor(password: string): Observable<TwoFactorStatus> {
    return this.http.post<TwoFactorStatus>(`${this.base}/2fa/disable/`, { password });
  }

  apiKeys(): Observable<ApiKey[]> {
    return this.http.get<ApiKey[]>(`${this.base}/api-keys/`);
  }

  /** The reply's `key` is the only time the key itself is ever shown. */
  createApiKey(name: string): Observable<ApiKey> {
    return this.http.post<ApiKey>(`${this.base}/api-keys/`, { name });
  }

  revokeApiKey(id: string): Observable<void> {
    return this.http.delete<void>(`${this.base}/api-keys/${id}/`);
  }

  signIns(): Observable<SignInEvent[]> {
    return this.http.get<SignInEvent[]>(`${this.base}/sign-ins/`);
  }
}
