import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { NotificationRule, Organization, Severity } from '../../core/models/models';
import { OrganizationService } from '../../core/services/organization-service';
import { NotificationRuleService } from '../../core/services/notification-rule-service';
@Component({
  selector: 'app-notification-rules',
  imports: [FormsModule],
  templateUrl: './notification-rules.html',
  styleUrl: './notification-rules.scss',
})
export class NotificationRules implements OnInit {
  private readonly ruleService = inject(NotificationRuleService);
  private readonly orgService = inject(OrganizationService);

  readonly rules = signal<NotificationRule[]>([]);
  readonly organization = signal<Organization | null>(null);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly isAdding = signal(false);
  readonly newEmail = signal('');
  readonly newSeverity = signal<Severity>('medium');

  ngOnInit(): void {
    this.orgService.list().subscribe({
      next: (page) => {
        const org = page.results[0] ?? null;
        this.organization.set(org);
        if (org) {
          this.fetchRules(org.id);
        } else {
          this.isLoading.set(false);
        }
      },
      error: () => {
        this.errorMessage.set('Could not load organization.');
        this.isLoading.set(false);
      },
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
    const org = this.organization();
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