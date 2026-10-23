import { Component, computed, effect, inject, input, output, signal, untracked } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { Preflight } from '../../../core/models/models';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { OrganizationService } from '../../../core/services/organization-service';
import { Icon } from '../icon/icon';

/**
 * The check before a scan starts: what it covers, which hosts no longer
 * exist (and will be skipped), what can't run on the worker, and about
 * how long it takes. Emits true to go ahead, false to cancel.
 */
@Component({
  selector: 'app-preflight-dialog',
  imports: [DecimalPipe, Icon],
  templateUrl: './preflight-dialog.html',
  styleUrl: './preflight-dialog.scss',
  host: { '(document:keydown.escape)': 'decided.emit(false)' },
})
export class PreflightDialog {
  private readonly orgService = inject(OrganizationService);
  private readonly orgContext = inject(OrganizationContextService);

  // Scanner names; empty means every scanner.
  readonly scanners = input<string[]>([]);
  readonly decided = output<boolean>();

  readonly check = signal<Preflight | null>(null);
  readonly failed = signal(false);
  readonly runnable = computed(() => (this.check()?.scanners ?? []).filter((s) => !s.missing_tools.length && !s.running));
  readonly hostsOk = computed(() => {
    const hosts = this.check()?.hosts;
    return hosts ? hosts.missing + hosts.private === 0 : true;
  });

  constructor() {
    effect(() => {
      const names = this.scanners();
      const org = this.orgContext.selectedOrganization();
      if (!org) return;
      untracked(() =>
        this.orgService.preflight(org.id, names).subscribe({
          next: (check) => this.check.set(check),
          error: () => this.failed.set(true),
        }),
      );
    });
  }

  duration(seconds: number): string {
    if (seconds < 90) return 'under 2 minutes';
    const minutes = Math.round(seconds / 60);
    if (minutes < 90) return `about ${minutes} minutes`;
    const hours = Math.round(minutes / 6) / 10;
    return `about ${hours} hours`;
  }
}
