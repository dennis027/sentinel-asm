import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Finding, Organization, Severity } from '../../core/models/models';
import { FindingService } from '../../core/services/finding-service';
import { OrganizationService } from '../../core/services/organization-service';

@Component({
  selector: 'app-findings',
  imports: [FormsModule],
  templateUrl: './findings.html',
  styleUrl: './findings.scss',
})
export class Findings implements OnInit {
  private readonly findingService = inject(FindingService);
  private readonly orgService = inject(OrganizationService);

  readonly findings = signal<Finding[]>([]);
  readonly organization = signal<Organization | null>(null);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);

  readonly severityFilter = signal<Severity | ''>('');
  readonly statusFilter = signal<'active' | 'resolved'>('active');

  ngOnInit(): void {
    this.orgService.list().subscribe({
      next: (page) => this.organization.set(page.results[0] ?? null),
    });
    this.fetchFindings();
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
    const org = this.organization();
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