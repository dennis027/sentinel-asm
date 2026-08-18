import { Component, effect, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { NotificationRule, Severity } from '../../core/models/models';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { NotificationRuleService } from '../../core/services/notification-rule-service';

@Component({
  selector: 'app-notification-rules',
  imports: [FormsModule],
  templateUrl: './notification-rules.html',
  styleUrl: './notification-rules.scss',
})
export class NotificationRules {
  private readonly ruleService = inject(NotificationRuleService);
  protected readonly orgContext = inject(OrganizationContextService);

  readonly rules = signal<NotificationRule[]>([]);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly isAdding = signal(false);
  readonly newEmail = signal('');
  readonly newSeverity = signal<Severity>('medium');

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      if (org) {
        this.fetchRules(org.id);
      }
    });
  }

  showAddForm(): void {
    this.isAdding.set(true);
  }

  cancelAdd(): void {
    this.isAdding.set(false);
    this.newEmail.set('');
    this.newSeverity.set('medium');
  }

  submitNewRule(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org || !this.newEmail()) return;

    this.ruleService
      .create({
        organization: org.id,
        recipient_email: this.newEmail(),
        min_severity: this.newSeverity(),
      })
      .subscribe({
        next: () => {
          this.cancelAdd();
          this.fetchRules(org.id);
        },
        error: (err) => {
          this.errorMessage.set(
            err.status === 400
              ? 'A rule for this email already exists on this organization.'
              : 'Could not create rule.',
          );
        },
      });
  }

  deleteRule(rule: NotificationRule): void {
    this.ruleService.delete(rule.id).subscribe({
      next: () => this.rules.update((rules) => rules.filter((r) => r.id !== rule.id)),
      error: () => this.errorMessage.set('Could not delete rule.'),
    });
  }

  private fetchRules(orgId: string): void {
    this.isLoading.set(true);
    this.ruleService.list(orgId).subscribe({
      next: (page) => {
        this.rules.set(page.results);
        this.isLoading.set(false);
      },
      error: () => {
        this.errorMessage.set('Could not load notification rules.');
        this.isLoading.set(false);
      },
    });
  }
}