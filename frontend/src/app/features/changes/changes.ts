import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe, DecimalPipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { SurfaceChangeEvent, SurfaceChangeKind, SurfaceChanges } from '../../core/models/models';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { EmptyState } from '../../shared/components/empty-state/empty-state';
import { Icon, IconName } from '../../shared/components/icon/icon';

const KIND_ICONS: Record<SurfaceChangeKind, IconName> = {
  host_added: 'plus',
  host_gone: 'unlink',
  port_opened: 'plug',
  port_closed: 'lock',
  software_seen: 'package',
  certificate: 'shield-check',
  dns_changed: 'network',
};

// Changes that widen what an attacker can reach, as opposed to narrowing it.
const EXPOSING: SurfaceChangeKind[] = ['host_added', 'port_opened', 'software_seen'];

export const PERIODS = [7, 30, 90];

/**
 * What changed on the attack surface, day by day: new and vanished
 * hosts, ports that opened or closed, new software and certificates,
 * DNS records that moved. The "since last week" view.
 */
@Component({
  selector: 'app-changes',
  imports: [DatePipe, DecimalPipe, RouterLink, EmptyState, Icon],
  templateUrl: './changes.html',
  styleUrl: './changes.scss',
})
export class Changes {
  private readonly orgService = inject(OrganizationService);
  protected readonly orgContext = inject(OrganizationContextService);

  readonly days = signal(30);
  readonly kind = signal<SurfaceChangeKind | ''>('');
  readonly data = signal<SurfaceChanges | null>(null);
  readonly isLoading = signal(true);
  readonly failed = signal(false);
  protected readonly periods = PERIODS;

  readonly kinds = computed(() => {
    const data = this.data();
    if (!data) return [];
    return (Object.keys(data.kinds) as SurfaceChangeKind[]).map((kind) => ({
      kind,
      label: data.kinds[kind],
      count: data.counts[kind],
      icon: KIND_ICONS[kind],
      exposing: EXPOSING.includes(kind),
    }));
  });

  // Events grouped by day, newest first.
  readonly dayGroups = computed(() => {
    const groups: { day: string; events: SurfaceChangeEvent[] }[] = [];
    for (const event of this.data()?.events ?? []) {
      const day = event.at.slice(0, 10);
      const last = groups[groups.length - 1];
      if (last?.day === day) last.events.push(event);
      else groups.push({ day, events: [event] });
    }
    return groups;
  });

  constructor() {
    effect(() => {
      this.orgContext.selectedOrganization();
      untracked(() => this.fetch());
    });
  }

  iconFor(kind: SurfaceChangeKind): IconName {
    return KIND_ICONS[kind];
  }

  isExposing(kind: SurfaceChangeKind): boolean {
    return EXPOSING.includes(kind);
  }

  setDays(days: number): void {
    this.days.set(days);
    this.fetch();
  }

  setKind(kind: SurfaceChangeKind | ''): void {
    this.kind.set(this.kind() === kind ? '' : kind);
    this.fetch();
  }

  private fetch(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) {
      this.isLoading.set(!this.orgContext.isLoaded());
      return;
    }
    this.isLoading.set(true);
    this.failed.set(false);
    this.orgService.surfaceChanges(org.id, this.days(), this.kind()).subscribe({
      next: (data) => {
        this.data.set(data);
        this.isLoading.set(false);
      },
      error: () => {
        this.failed.set(true);
        this.isLoading.set(false);
      },
    });
  }
}
