import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { RouterLink } from '@angular/router';
import { FRAMEWORK_SHORT_NAMES } from '../../core/labels';
import { ComplianceFramework } from '../../core/models/models';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { Icon } from '../../shared/components/icon/icon';

/**
 * Open issues seen through the frameworks auditors and boards ask
 * about: OWASP Top 10, CIS Controls, ISO 27001, PCI DSS -- plus MITRE
 * ATT&CK, the techniques an attacker would use them for. Each control
 * shows how many open issues bear on it and links to them.
 */
@Component({
  selector: 'app-compliance',
  imports: [RouterLink, Icon],
  templateUrl: './compliance.html',
  styleUrl: './compliance.scss',
})
export class Compliance {
  private readonly orgService = inject(OrganizationService);
  protected readonly orgContext = inject(OrganizationContextService);
  protected readonly shortNames = FRAMEWORK_SHORT_NAMES;

  readonly frameworks = signal<ComplianceFramework[]>([]);
  readonly disclaimer = signal('');
  readonly selected = signal('owasp');
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly framework = computed(() => this.frameworks().find((f) => f.id === this.selected()) ?? null);

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      untracked(() => {
        if (!org) return;
        this.isLoading.set(true);
        this.orgService.compliance(org.id).subscribe({
          next: (body) => {
            this.frameworks.set(body.frameworks);
            this.disclaimer.set(body.disclaimer);
            this.isLoading.set(false);
          },
          error: () => {
            this.errorMessage.set('Could not load the compliance view.');
            this.isLoading.set(false);
          },
        });
      });
    });
  }

}
