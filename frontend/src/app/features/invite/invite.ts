import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { InvitationDetail } from '../../core/models/models';
import { AccountService } from '../../core/services/account.service';
import { AuthService } from '../../core/services/auth.service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { AuthCard } from '../../shared/components/auth-card/auth-card';

type Mode = 'loading' | 'invalid' | 'gone' | 'join' | 'wrong-account' | 'sign-in' | 'create';

/**
 * An invitation link. Depending on who opens it:
 * - signed in as the invited address: join with one click;
 * - signed in as someone else: told so, with a way to switch;
 * - not signed in, and the address has an account: sign in first, then back here;
 * - not signed in, no account yet: create one (the address is the username) and join.
 */
@Component({
  selector: 'app-invite',
  imports: [DatePipe, FormsModule, RouterLink, AuthCard],
  templateUrl: './invite.html',
  styleUrl: './invite.scss',
})
export class Invite implements OnInit {
  private readonly account = inject(AccountService);
  private readonly auth = inject(AuthService);
  private readonly orgContext = inject(OrganizationContextService);
  private readonly router = inject(Router);
  private readonly token = inject(ActivatedRoute).snapshot.paramMap.get('token') ?? '';

  readonly invitation = signal<InvitationDetail | null>(null);
  readonly problem = signal('');
  readonly busy = signal(false);
  readonly errors = signal<string[]>([]);
  readonly firstName = signal('');
  readonly lastName = signal('');
  readonly password = signal('');
  readonly confirm = signal('');
  readonly signedInAs = signal<string | null>(null);
  readonly mismatch = computed(() => !!this.confirm() && this.confirm() !== this.password());

  readonly mode = computed<Mode>(() => {
    const invitation = this.invitation();
    if (this.problem()) return 'invalid';
    if (!invitation) return 'loading';
    if (invitation.status !== 'pending') return 'gone';
    if (this.auth.isAuthenticated()) {
      const me = this.signedInAs();
      if (me === null) return 'loading';
      return me.toLowerCase() === invitation.email.toLowerCase() ? 'join' : 'wrong-account';
    }
    return invitation.account_exists ? 'sign-in' : 'create';
  });

  readonly signInLink = computed(() => ({
    redirect: `/invite/${this.token}`,
    message: `Sign in as ${this.invitation()?.email} to accept the invitation.`,
  }));

  ngOnInit(): void {
    this.account.invitation(this.token).subscribe({
      next: (invitation) => this.invitation.set(invitation),
      error: (err) =>
        this.problem.set(
          err.status === 429 ? 'Too many attempts. Wait a while and try again.' : "This invitation link isn't valid.",
        ),
    });
    if (this.auth.isAuthenticated()) {
      this.account.me().subscribe({
        next: (me) => this.signedInAs.set(me.email || me.username),
        error: () => this.signedInAs.set(''),
      });
    }
  }

  join(): void {
    this.accept();
  }

  createAccount(): void {
    if (this.mismatch() || !this.password()) return;
    this.accept({ password: this.password(), first_name: this.firstName().trim(), last_name: this.lastName().trim() });
  }

  /** Signed in as someone else: sign out and stay on this page. */
  switchAccount(): void {
    this.auth.clearSession();
    this.orgContext.clear();
    this.signedInAs.set(null);
  }

  private accept(newAccount?: { password: string; first_name: string; last_name: string }): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.errors.set([]);
    this.account.acceptInvitation(this.token, newAccount).subscribe({
      next: (joined) => {
        if (joined.access && joined.refresh) this.auth.startSession(joined.access, joined.refresh, joined.username);
        this.orgContext.selectOrganization(joined.organization);
        this.orgContext.loadOrganizations();
        this.router.navigate(['/dashboard']);
      },
      error: (err) => {
        this.busy.set(false);
        if (err.status === 410 || err.status === 404) {
          this.invitation.update((i) => (i ? { ...i, status: err.error?.status ?? 'expired', detail: err.error?.detail } : i));
        } else if (err.error?.code === 'sign_in_required') {
          this.invitation.update((i) => (i ? { ...i, account_exists: true } : i));
        } else if (err.status === 429) {
          this.errors.set(['Too many attempts. Wait a while and try again.']);
        } else {
          this.errors.set(err.error?.password ?? (err.error?.detail ? [err.error.detail] : ['Could not accept the invitation.']));
        }
      },
    });
  }
}
