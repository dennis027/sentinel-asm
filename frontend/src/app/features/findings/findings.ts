import { Component, effect, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Finding, Severity } from '../../core/models/models';
import { FindingService } from '../../core/services/finding-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';

@Component({
  selector: 'app-findings',
  imports: [FormsModule],
  templateUrl: './findings.html',
  styleUrl: './findings.scss',
})
export class Findings {
  private readonly findingService = inject(FindingService);
  private readonly orgService = inject(OrganizationService);
  protected readonly orgContext = inject(OrganizationContextService);

  readonly findings = signal<Finding[]>([]);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly severityFilter = signal<Severity | ''>('');
  readonly statusFilter = signal<'active' | 'resolved'>('active');

  constructor() {
    effect(() => {
      // Re-reading selectedOrganization() here just to establish the
      // dependency -- fetchFindings() below isn't org-filtered directly
      // (findings are asset-scoped, not directly org-filterable via this
      // endpoint), but re-running on org change keeps this page
      // consistent with the rest of the app when the org switches.
      this.orgContext.selectedOrganization();
      this.fetchFindings();
    });
  }

  onSeverityChange(value: string): void {
    this.severityFilter.set(value as Severity | '');
    this.fetchFindings();
  }

  onStatusChange(status: 'active' | 'resolved'): void {
    this.statusFilter.set(status);
    this.fetchFindings();
  }

  downloadExport(format: 'csv' | 'json' | 'pdf'): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) return;

    this.orgService.export(org.id, format).subscribe({
      next: (blob) => {
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${org.root_domain}-findings.${format}`;
        link.click();
        URL.revokeObjectURL(url);
      },
      error: () => this.errorMessage.set('Export failed.'),
    });
  }

  private fetchFindings(): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);

    this.findingService
      .list({
        severity: this.severityFilter() || undefined,
        is_active: this.statusFilter() === 'active',
      })
      .subscribe({
        next: (page) => {
          this.findings.set(page.results);
          this.isLoading.set(false);
        },
        error: () => {
          this.errorMessage.set('Could not load findings.');
          this.isLoading.set(false);
        },
      });
  }
}