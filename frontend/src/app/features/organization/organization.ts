import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ROLES, apiErrorMessage, roleLabel } from '../../core/labels';
import { Member, OrgRole, Organization } from '../../core/models/models';
import { AuthService } from '../../core/services/auth.service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { ToastService } from '../../core/services/toast.service';
import { ConfirmService } from '../../core/services/confirm.service';
import { Icon } from '../../shared/components/icon/icon';

/**
 * Everything about the selected organization that isn't scan data:
 * creating one, proving the domain is yours, and who is on the team.
 * Also where a brand-new user lands, since nothing else works until
 * an organization exists.
 */
@Component({
  selector: 'app-organization',
  imports: [FormsModule, DatePipe, Icon],
  templateUrl: './organization.html',
  styleUrl: './organization.scss',
})
export class OrganizationPage {
  private readonly orgService = inject(OrganizationService);
  private readonly auth = inject(AuthService);
  private readonly toasts = inject(ToastService);
  private readonly confirm = inject(ConfirmService);
  protected readonly orgContext = inject(OrganizationContextService);

  protected readonly roles = ROLES;
  protected readonly roleLabel = roleLabel;

  readonly org = this.orgContext.selectedOrganization;
  readonly hasNoOrganizations = computed(
    () => this.orgContext.isLoaded() && this.orgContext.allOrganizations().length === 0,
  );

  // --- create ---
  readonly isCreating = signal(false);
  readonly newName = signal('');
  readonly newDomain = signal('');
  readonly createError = signal<string | null>(null);
  readonly isSubmittingCreate = signal(false);

  // --- verification ---
  readonly isVerifying = signal(false);
  readonly verifyError = signal<string | null>(null);
  readonly copied = signal<'name' | 'value' | null>(null);

  // --- members ---
  readonly members = signal<Member[]>([]);
  readonly membersError = signal<string | null>(null);
  readonly newMemberIdentifier = signal('');
  readonly newMemberRole = signal<OrgRole>('viewer');
  readonly isAddingMember = signal(false);

  // --- policy: days to fix, and hosts never to scan ---
  protected readonly slaSeverities = ['critical', 'high', 'medium', 'low'] as const;
  readonly slaDraft = signal<Record<string, number>>({});
  readonly scopeDraft = signal('');
  readonly isSavingPolicy = signal<'sla' | 'scope' | null>(null);
  readonly policyError = signal<{ section: 'sla' | 'scope'; message: string } | null>(null);

  // --- delete ---
  // What the owner has typed to confirm; must match the root domain.
  readonly deleteConfirmation = signal('');
  readonly isDeleting = signal(false);
  readonly deleteError = signal<string | null>(null);
  readonly canDelete = computed(
    () => !!this.org() && this.deleteConfirmation().trim().toLowerCase() === this.org()?.root_domain,
  );

  readonly isOwner = computed(() => this.org()?.my_role === 'owner');
  // Only an owner may hand out the owner role.
  readonly assignableRoles = computed(() =>
    this.isOwner() ? ROLES : ROLES.filter((r) => r.value !== 'owner'),
  );

  constructor() {
    effect(() => {
      const org = this.org();
      untracked(() => {
        this.verifyError.set(null);
        this.membersError.set(null);
        this.deleteConfirmation.set('');
        this.deleteError.set(null);
        this.members.set([]);
        this.policyError.set(null);
        this.slaDraft.set({ ...(org?.sla_days ?? {}) });
        this.scopeDraft.set((org?.scope_exclusions ?? []).join('\n'));
        if (org) this.loadMembers(org.id);
      });
    });
  }

  // ---------------- policy ----------------

  setSla(severity: string, value: number | string): void {
    this.slaDraft.update((draft) => ({ ...draft, [severity]: Number(value) }));
  }

  saveSla(): void {
    this.savePolicy(
      'sla',
      { sla_days: this.slaDraft() as Organization['sla_days'] },
      'Fix-by deadlines saved. Every open issue is re-dated.',
    );
  }

  saveScope(): void {
    const patterns = this.scopeDraft()
      .split(/[\s,]+/)
      .map((p) => p.trim())
      .filter(Boolean);
    this.savePolicy(
      'scope',
      { scope_exclusions: patterns },
      patterns.length ? `${patterns.length} host pattern(s) will never be scanned.` : 'Every host may be scanned again.',
    );
  }

  private savePolicy(
    section: 'sla' | 'scope',
    change: Partial<Pick<Organization, 'sla_days' | 'scope_exclusions'>>,
    message: string,
  ): void {
    const org = this.org();
    if (!org) return;
    this.isSavingPolicy.set(section);
    this.policyError.set(null);
    this.orgService.update(org.id, change).subscribe({
      next: (updated) => {
        this.isSavingPolicy.set(null);
        this.orgContext.updateOrganization(updated);
        this.toasts.success(message);
      },
      error: (err) => {
        this.isSavingPolicy.set(null);
        this.policyError.set({ section, message: apiErrorMessage(err, 'Could not save.') });
      },
    });
  }

  // ---------------- create ----------------

  startCreating(): void {
    this.isCreating.set(true);
    this.createError.set(null);
  }

  cancelCreating(): void {
    this.isCreating.set(false);
    this.newName.set('');
    this.newDomain.set('');
    this.createError.set(null);
  }

  submitCreate(): void {
    const name = this.newName().trim();
    const domain = this.newDomain().trim();
    if (!name || !domain) {
      this.createError.set('Enter a name and the domain you want to monitor.');
      return;
    }

    this.isSubmittingCreate.set(true);
    this.createError.set(null);
    this.orgService.create(name, domain).subscribe({
      next: (created) => {
        this.isSubmittingCreate.set(false);
        this.cancelCreating();
        this.orgContext.addOrganization(created);
        this.toasts.success(`${created.name} created.`);
      },
      error: (err) => {
        this.isSubmittingCreate.set(false);
        this.createError.set(apiErrorMessage(err, 'Could not create the organization.'));
      },
    });
  }

  // ---------------- verification ----------------

  verifyDomain(): void {
    const org = this.org();
    if (!org) return;

    this.isVerifying.set(true);
    this.verifyError.set(null);
    this.orgService.verifyDomain(org.id).subscribe({
      next: (updated) => {
        this.isVerifying.set(false);
        this.orgContext.updateOrganization(updated);
        this.toasts.success(`${updated.root_domain} is verified. You can start scanning.`);
      },
      error: (err) => {
        this.isVerifying.set(false);
        this.verifyError.set(apiErrorMessage(err, 'Could not check the DNS record.'));
      },
    });
  }

  copy(which: 'name' | 'value', text: string): void {
    navigator.clipboard?.writeText(text).then(() => {
      this.copied.set(which);
      setTimeout(() => this.copied.set(null), 2000);
    });
  }

  // ---------------- members ----------------

  isSelf(member: Member): boolean {
    return member.username === this.auth.currentUsername();
  }

  /** Admins manage everyone except owners; owners manage everyone. */
  canEdit(member: Member): boolean {
    if (!this.orgContext.canManageSettings()) return false;
    return member.role !== 'owner' || this.isOwner();
  }

  addMember(): void {
    const org = this.org();
    const identifier = this.newMemberIdentifier().trim();
    if (!org || !identifier) return;

    this.isAddingMember.set(true);
    this.membersError.set(null);
    this.orgService.addMember(org.id, identifier, this.newMemberRole()).subscribe({
      next: (member) => {
        this.isAddingMember.set(false);
        this.newMemberIdentifier.set('');
        this.newMemberRole.set('viewer');
        this.members.update((members) =>
          [...members, member].sort((a, b) => a.username.localeCompare(b.username)),
        );
        this.toasts.success(`${member.username} added as ${roleLabel(member.role)}.`);
      },
      error: (err) => {
        this.isAddingMember.set(false);
        this.membersError.set(apiErrorMessage(err, 'Could not add that person.'));
      },
    });
  }

  changeRole(member: Member, role: OrgRole): void {
    const org = this.org();
    if (!org || role === member.role) return;

    const setRole = (value: OrgRole) =>
      this.members.update((members) =>
        members.map((m) => (m.id === member.id ? { ...m, role: value } : m)),
      );

    this.membersError.set(null);
    // Show the new role straight away, and put the old one back if the
    // server refuses -- otherwise the dropdown would keep showing a
    // role the person doesn't have.
    setRole(role);
    this.orgService.updateMemberRole(org.id, member.id, role).subscribe({
      next: (updated) => {
        this.toasts.success(`${updated.username} is now ${roleLabel(updated.role)}.`);
        // Changing your own role changes what this page lets you do.
        if (this.isSelf(updated)) this.orgContext.loadOrganizations();
      },
      error: (err) => {
        setRole(member.role);
        this.membersError.set(apiErrorMessage(err, 'Could not change that role.'));
      },
    });
  }

  async removeMember(member: Member): Promise<void> {
    const org = this.org();
    if (!org) return;

    const self = this.isSelf(member);
    const confirmed = await this.confirm.ask(
      self
        ? {
            title: `Leave ${org.name}?`,
            message: 'You will lose access to it. An admin would have to add you again.',
            confirmLabel: 'Leave organization',
            danger: true,
            icon: 'logout',
          }
        : {
            title: `Remove ${member.username} from ${org.name}?`,
            message: `${member.username} will lose access to this organization straight away.`,
            confirmLabel: 'Remove member',
            danger: true,
            icon: 'users',
          },
    );
    if (!confirmed) return;

    this.membersError.set(null);
    this.orgService.removeMember(org.id, member.id).subscribe({
      next: () => {
        if (self) {
          this.orgContext.removeOrganization(org.id);
          this.toasts.success(`You left ${org.name}.`);
          return;
        }
        this.members.update((members) => members.filter((m) => m.id !== member.id));
        this.toasts.success(`${member.username} removed.`);
      },
      error: (err) => this.membersError.set(apiErrorMessage(err, 'Could not remove that member.')),
    });
  }

  // ---------------- delete ----------------

  deleteOrganization(): void {
    const org = this.org();
    if (!org || !this.canDelete() || this.isDeleting()) return;

    this.isDeleting.set(true);
    this.deleteError.set(null);
    this.orgService.delete(org.id).subscribe({
      next: () => {
        this.isDeleting.set(false);
        // Selection moves to another organization, or to the welcome
        // screen if this was the last one.
        this.orgContext.removeOrganization(org.id);
        this.toasts.success(`${org.name} and all of its data were deleted.`);
      },
      error: (err) => {
        this.isDeleting.set(false);
        this.deleteError.set(apiErrorMessage(err, 'Could not delete the organization.'));
      },
    });
  }

  private loadMembers(orgId: string): void {
    this.orgService.members(orgId).subscribe({
      next: (members) => this.members.set(members),
      error: () => this.membersError.set('Could not load members.'),
    });
  }
}
