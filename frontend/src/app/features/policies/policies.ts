import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { PolicyKind, Severity, SurfacePolicy } from '../../core/models/models';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { PolicyInput, SurfaceService } from '../../core/services/surface.service';
import { ToastService } from '../../core/services/toast.service';
import { ConfirmService } from '../../core/services/confirm.service';
import { apiErrorMessage } from '../../core/labels';
import { EmptyState } from '../../shared/components/empty-state/empty-state';
import { Icon, IconName } from '../../shared/components/icon/icon';

export const POLICY_KINDS: { value: PolicyKind; label: string; placeholder: string; hint: string; icon: IconName }[] = [
  { value: 'port', label: 'Port must not be open', placeholder: '3389', hint: 'A port number, e.g. 3389 for Remote Desktop or 22 for SSH.', icon: 'plug' },
  { value: 'technology', label: 'Software must not be used', placeholder: 'WordPress', hint: 'Matches any software whose name contains this.', icon: 'package' },
  { value: 'hostname', label: 'Host names must not match', placeholder: '*dev*', hint: 'A name pattern; * matches anything, e.g. *dev* or staging.*', icon: 'globe' },
  { value: 'provider', label: 'Must not be hosted on', placeholder: 'Heroku', hint: 'A hosting provider as shown on Inventory → Hosting.', icon: 'cloud' },
];

// Ready-made rules most teams want; one click fills the form.
export const POLICY_EXAMPLES: (PolicyInput & { why: string })[] = [
  { name: 'No Remote Desktop on the internet', kind: 'port', value: '3389', severity: 'high', enabled: true, why: 'RDP is one of the most attacked services there is.', guidance: 'Put Remote Desktop behind a VPN or a gateway with multi-factor sign-in, then close port 3389 to the internet.' },
  { name: 'No databases on the internet', kind: 'port', value: '5432', severity: 'critical', enabled: true, why: 'Databases should only be reachable from your own servers.', guidance: 'Restrict the database to private networks with a firewall rule.' },
  { name: 'No development hosts in public', kind: 'hostname', value: '*dev*', severity: 'medium', enabled: true, why: 'Dev and test systems are rarely patched or monitored.', guidance: 'Put development hosts behind single sign-on or remove their public DNS records.' },
  { name: 'No Telnet', kind: 'port', value: '23', severity: 'high', enabled: true, why: 'Telnet sends passwords in clear text.', guidance: 'Turn Telnet off and use SSH instead.' },
];

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Rules for what the attack surface may look like; hosts that break one get a finding. */
@Component({
  selector: 'app-policies',
  imports: [FormsModule, RouterLink, EmptyState, Icon],
  templateUrl: './policies.html',
  styleUrl: './policies.scss',
})
export class Policies {
  private readonly surface = inject(SurfaceService);
  private readonly toasts = inject(ToastService);
  private readonly confirm = inject(ConfirmService);
  protected readonly orgContext = inject(OrganizationContextService);

  readonly policies = signal<SurfacePolicy[]>([]);
  readonly isLoading = signal(true);
  readonly editing = signal(false);
  readonly saving = signal(false);
  readonly formError = signal<string | null>(null);
  readonly draft = signal<PolicyInput>(this.blank());
  protected readonly kinds = POLICY_KINDS;
  protected readonly examples = POLICY_EXAMPLES;
  protected readonly severities = SEVERITIES;

  readonly kindInfo = computed(() => POLICY_KINDS.find((k) => k.value === this.draft().kind)!);
  readonly breakingTotal = computed(() => this.policies().reduce((sum, p) => sum + (p.enabled ? p.breaking : 0), 0));
  // Examples not already added.
  readonly suggestions = computed(() =>
    POLICY_EXAMPLES.filter((e) => !this.policies().some((p) => p.kind === e.kind && p.value === e.value)),
  );

  constructor() {
    effect(() => {
      this.orgContext.selectedOrganization();
      untracked(() => this.load());
    });
  }

  iconFor(kind: PolicyKind): IconName {
    return POLICY_KINDS.find((k) => k.value === kind)?.icon ?? 'shield';
  }

  start(example?: PolicyInput): void {
    this.draft.set(example ? { ...example } : this.blank());
    this.formError.set(null);
    this.editing.set(true);
  }

  patch(change: Partial<PolicyInput>): void {
    this.draft.update((draft) => ({ ...draft, ...change }));
  }

  save(): void {
    const org = this.orgContext.selectedOrganization();
    const draft = this.draft();
    if (!org || !draft.name.trim() || !draft.value.trim() || this.saving()) return;
    this.saving.set(true);
    this.formError.set(null);
    this.surface.createPolicy(org.id, draft).subscribe({
      next: () => {
        this.saving.set(false);
        this.editing.set(false);
        this.toasts.success(`"${draft.name}" is on. Every host was checked against it.`);
        this.load();
      },
      error: (err) => {
        this.saving.set(false);
        this.formError.set(apiErrorMessage(err, 'Could not add this policy.'));
      },
    });
  }

  toggle(policy: SurfacePolicy): void {
    this.surface.updatePolicy(policy.id, { enabled: !policy.enabled }).subscribe({
      next: () => this.load(),
      error: (err) => this.toasts.error(apiErrorMessage(err, 'Could not change this policy.')),
    });
  }

  async remove(policy: SurfacePolicy): Promise<void> {
    const confirmed = await this.confirm.ask({
      title: `Delete "${policy.name}"?`,
      message: policy.breaking
        ? [`The ${policy.breaking} finding(s) it raised will be marked resolved.`]
        : ['Hosts will no longer be checked against it.'],
      confirmLabel: 'Delete policy',
      danger: true,
    });
    if (!confirmed) return;
    this.surface.deletePolicy(policy.id).subscribe({
      next: () => {
        this.toasts.success(`Deleted "${policy.name}".`);
        this.load();
      },
      error: (err) => this.toasts.error(apiErrorMessage(err, 'Could not delete this policy.')),
    });
  }

  private blank(): PolicyInput {
    return { name: '', kind: 'port', value: '', severity: 'medium', guidance: '', enabled: true };
  }

  private load(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) {
      this.isLoading.set(!this.orgContext.isLoaded());
      return;
    }
    this.surface.listPolicies(org.id).subscribe({
      next: (policies) => {
        this.policies.set(policies);
        this.isLoading.set(false);
      },
      error: () => {
        this.policies.set([]);
        this.isLoading.set(false);
      },
    });
  }
}
