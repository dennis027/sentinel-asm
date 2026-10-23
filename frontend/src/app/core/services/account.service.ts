import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { ApiKey, InvitationDetail, OrgRole, Profile, SignInEvent, TwoFactorSetup } from '../models/models';

export interface TwoFactorStatus {
  enabled: boolean;
  enabled_at: string | null;
}

export interface AcceptedInvitation {
  organization: string;
  role: OrgRole;
  username: string;
  created_account: boolean;
  // Only when the invitation created the account: signed in straight away.
  access?: string;
  refresh?: string;
}

/**
 * The signed-in person's own account (profile, email, sessions,
 * two-factor sign-in, API keys, sign-in history), and the flows for
 * people who aren't signed in: forgotten passwords and invitation links.
 */
@Injectable({ providedIn: 'root' })
export class AccountService {
  private readonly http = inject(HttpClient);
  private readonly api = environment.apiBaseUrl;
  private readonly base = `${environment.apiBaseUrl}/auth`;

  // ---------------- profile and sessions ----------------

  me(): Observable<Profile> {
    return this.http.get<Profile>(`${this.base}/me/`);
  }

  updateProfile(changes: Pick<Profile, 'first_name' | 'last_name'>): Observable<Profile> {
    return this.http.patch<Profile>(`${this.base}/me/`, changes);
  }

  changeEmail(email: string, currentPassword: string): Observable<Profile> {
    return this.http.post<Profile>(`${this.base}/me/email/`, { email, current_password: currentPassword });
  }

  signOutEverywhere(): Observable<{ signed_out: number; detail: string }> {
    return this.http.post<{ signed_out: number; detail: string }>(`${this.base}/sessions/revoke/`, {});
  }

  // ---------------- two-factor sign-in ----------------

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

  // ---------------- API keys and sign-ins ----------------

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

  // ---------------- signed out: forgotten password, invitations ----------------

  requestPasswordReset(email: string): Observable<{ detail: string }> {
    return this.http.post<{ detail: string }>(`${this.base}/password-reset/`, { email });
  }

  confirmPasswordReset(uid: string, token: string, newPassword: string): Observable<{ detail: string; username: string }> {
    return this.http.post<{ detail: string; username: string }>(`${this.base}/password-reset/confirm/`, {
      uid,
      token,
      new_password: newPassword,
    });
  }

  invitation(token: string): Observable<InvitationDetail> {
    return this.http.get<InvitationDetail>(`${this.api}/invitations/${encodeURIComponent(token)}/`);
  }

  acceptInvitation(
    token: string,
    newAccount?: { password: string; first_name: string; last_name: string },
  ): Observable<AcceptedInvitation> {
    return this.http.post<AcceptedInvitation>(
      `${this.api}/invitations/${encodeURIComponent(token)}/accept/`,
      newAccount ?? {},
    );
  }
}
