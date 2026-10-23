import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { CertificateRow, Hosting, ServiceRow, TechnologyRow } from '../../core/models/models';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { EmptyState } from '../../shared/components/empty-state/empty-state';
import { Icon } from '../../shared/components/icon/icon';

type Tab = 'software' | 'services' | 'certificates' | 'hosting';
const HOSTS_SHOWN = 6;

/**
 * What the organization runs on the internet, three ways: software and
 * versions (where is that vulnerable version?), open services (where is
 * RDP open?), and TLS certificates (what expires next?). The answers
 * people need the morning a new vulnerability is announced.
 */
@Component({
  selector: 'app-inventory',
  imports: [DatePipe, FormsModule, RouterLink, Icon, EmptyState],
  templateUrl: './inventory.html',
  styleUrl: './inventory.scss',
})
export class Inventory {
  private readonly orgService = inject(OrganizationService);
  private readonly router = inject(Router);
  private readonly queryParams = toSignal(inject(ActivatedRoute).queryParamMap);
  protected readonly orgContext = inject(OrganizationContextService);
  protected readonly hostsShown = HOSTS_SHOWN;

  readonly tab = computed<Tab>(() => {
    const tab = this.queryParams()?.get('tab');
    return tab === 'services' || tab === 'certificates' || tab === 'hosting' ? tab : 'software';
  });
  readonly technologies = signal<TechnologyRow[]>([]);
  readonly services = signal<ServiceRow[]>([]);
  readonly certificates = signal<CertificateRow[]>([]);
  readonly hosting = signal<Hosting | null>(null);
  readonly providerCount = computed(() => this.hosting()?.providers.length ?? 0);
  readonly shownProviders = computed(() => {
    const q = this.filter().trim().toLowerCase();
    const largest = Math.max(1, ...(this.hosting()?.providers ?? []).map((p) => p.count));
    return (this.hosting()?.providers ?? [])
      .filter((p) => !q || p.provider.toLowerCase().includes(q) || p.hosts.some((h) => h.includes(q)))
      .map((p) => ({ ...p, share: (p.count / largest) * 100 }));
  });
  readonly filter = signal('');
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);
  // rows whose full host list is showing
  readonly expanded = signal<ReadonlySet<string>>(new Set());

  readonly shownTechnologies = computed(() => {
    const q = this.filter().trim().toLowerCase();
    return this.technologies().filter((t) => !q || `${t.name} ${t.version} ${t.category}`.toLowerCase().includes(q));
  });
  readonly shownServices = computed(() => {
    const q = this.filter().trim().toLowerCase();
    return this.services().filter((s) => !q || `${s.port} ${s.service}`.toLowerCase().includes(q));
  });
  readonly shownCertificates = computed(() => {
    const q = this.filter().trim().toLowerCase();
    return this.certificates().filter((c) => !q || c.asset_value.includes(q));
  });
  readonly expiringSoon = computed(() => this.certificates().filter((c) => c.days_remaining <= 30).length);

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      untracked(() => {
        if (org) this.load(org.id);
      });
    });
  }

  select(tab: Tab): void {
    this.filter.set('');
    this.router.navigate([], { queryParams: { tab }, replaceUrl: true });
  }

  toggle(key: string): void {
    const next = new Set(this.expanded());
    if (next.has(key)) next.delete(key);
    else next.add(key);
    this.expanded.set(next);
  }

  private load(orgId: string): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);
    let pending = 4;
    const done = () => {
      pending -= 1;
      if (pending === 0) this.isLoading.set(false);
    };
    const fail = () => {
      this.errorMessage.set('Could not load the inventory.');
      done();
    };
    this.orgService.technologies(orgId).subscribe({
      next: (rows) => {
        this.technologies.set(rows);
        done();
      },
      error: fail,
    });
    this.orgService.services(orgId).subscribe({
      next: (rows) => {
        this.services.set(rows);
        done();
      },
      error: fail,
    });
    this.orgService.hosting(orgId).subscribe({
      next: (hosting) => {
        this.hosting.set(hosting);
        done();
      },
      error: fail,
    });
    this.orgService.certificates(orgId).subscribe({
      next: (rows) => {
        this.certificates.set(rows);
        done();
      },
      error: fail,
    });
  }
}
