import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { DatePipe, DecimalPipe } from '@angular/common';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { apiErrorMessage } from '../../core/labels';
import { ErrorGroup, LogDetection, LogOverview, LogSource, LogSourceKind } from '../../core/models/models';
import { ConfirmService } from '../../core/services/confirm.service';
import { DetectionFilters, LogService } from '../../core/services/log.service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { ToastService } from '../../core/services/toast.service';
import { EmptyState } from '../../shared/components/empty-state/empty-state';
import { Icon } from '../../shared/components/icon/icon';
import { Pager } from '../../shared/components/pager/pager';
import { every } from '../../shared/live';
import { PluralPipe } from '../../shared/pipes/plural';
import { ConnectServer } from './connect-server/connect-server';
import { ErrorGroups } from './error-groups/error-groups';
import { EventSearch } from './event-search/event-search';
import { LogAlerts } from './log-alerts/log-alerts';

type Tab = 'detections' | 'errors' | 'search' | 'servers' | 'rules';

const RETENTION = [7, 14, 30, 60, 90, 180, 365];

export const SOURCE_KINDS: { value: LogSourceKind; label: string; hint: string; icon: 'server' | 'monitor' | 'package' }[] = [
  { value: 'linux', label: 'Ubuntu / Linux', hint: 'Debian, RHEL, Rocky, Amazon Linux…', icon: 'server' },
  { value: 'windows', label: 'Windows', hint: 'Windows Server 2016 and later', icon: 'monitor' },
  { value: 'python', label: 'Python app', hint: 'Django, Flask, FastAPI, scripts', icon: 'package' },
  { value: 'node', label: 'Node.js app', hint: 'Express, Nest, Next.js; pino or winston', icon: 'package' },
  { value: 'php', label: 'PHP app', hint: 'Laravel, Symfony, anything with Monolog', icon: 'package' },
  { value: 'ruby', label: 'Ruby app', hint: 'Rails, Sinatra, Sidekiq', icon: 'package' },
  { value: 'go', label: 'Go app', hint: 'log/slog, zap, logrus', icon: 'package' },
  { value: 'java', label: 'Java / Kotlin app', hint: 'Spring Boot, Logback, Log4j2', icon: 'package' },
  { value: 'dotnet', label: '.NET app', hint: 'ASP.NET Core, Serilog', icon: 'package' },
  { value: 'other', label: 'Other app', hint: 'Anything that can send JSON', icon: 'package' },
];
// Counts, detections and sources refresh this often, so the page never needs reloading.
const REFRESH_MS = 15_000;

/**
 * Logs: the client's own servers (Ubuntu/Linux, Windows) and apps (Python,
 * Node.js, PHP, Ruby, Go, Java, .NET, anything that posts JSON) send their
 * logs here. Everything on the page refreshes by itself. Detections come
 * first, then grouped app errors, searching the events, then the sources
 * themselves and how to connect another.
 */
@Component({
  selector: 'app-logs',
  imports: [DatePipe, DecimalPipe, FormsModule, RouterLink, Icon, EmptyState, Pager, PluralPipe, ConnectServer, ErrorGroups, EventSearch, LogAlerts],
  templateUrl: './logs.html',
  styleUrl: './logs.scss',
})
export class Logs {
  private readonly logService = inject(LogService);
  private readonly orgService = inject(OrganizationService);
  private readonly toasts = inject(ToastService);
  private readonly confirm = inject(ConfirmService);
  private readonly router = inject(Router);
  private readonly queryParams = toSignal(inject(ActivatedRoute).queryParamMap);
  protected readonly orgContext = inject(OrganizationContextService);

  protected readonly kinds = SOURCE_KINDS;
  protected readonly retention = RETENTION;
  protected readonly rules = computed(() => this.overview()?.rules ?? []);

  readonly tab = computed<Tab>(() => {
    const tab = this.queryParams()?.get('tab');
    return tab === 'search' || tab === 'servers' || tab === 'rules' || tab === 'errors' ? tab : 'detections';
  });

  readonly overview = signal<LogOverview | null>(null);
  readonly sources = signal<LogSource[]>([]);
  readonly isLoading = signal(true);

  // Detections
  readonly detections = signal<LogDetection[]>([]);
  readonly detectionCount = signal(0);
  readonly detectionStatus = signal<'open' | 'resolved'>('open');
  readonly detectionPage = signal(1);

  readonly detectionFilters = signal<DetectionFilters>({});
  readonly detectionText = signal('');
  // Detections that appeared since the page loaded, highlighted.
  readonly newDetections = signal<ReadonlySet<string>>(new Set());
  private knownDetections = new Set<string>();

  // Connecting a server
  readonly isConnecting = signal(false);
  readonly newName = signal('');
  readonly newOs = signal<LogSourceKind>('linux');
  readonly connectError = signal<string | null>(null);
  readonly setupFor = signal<LogSource | null>(null);

  readonly hasServers = computed(() => this.sources().length > 0);
  readonly hasApps = computed(() => this.sources().some((s) => s.is_application));
  readonly appSources = computed(() => this.sources().filter((s) => s.is_application));

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      untracked(() => {
        if (!org) return;
        this.setupFor.set(null);
        this.knownDetections = new Set();
        this.loadOverview(org.id);
        this.loadDetections();
      });
    });
    every(REFRESH_MS, () => {
      const org = this.orgContext.selectedOrganization();
      if (!org) return;
      this.loadOverview(org.id);
      if (this.tab() === 'detections' && this.detectionPage() === 1) this.loadDetections();
    });
  }

  showFailedSignins(): void {
    this.router.navigate([], { queryParams: { tab: 'search', category: 'auth_failure' } });
  }

  select(tab: Tab): void {
    this.router.navigate([], { queryParams: { tab }, queryParamsHandling: 'merge', replaceUrl: true });
  }

  // ---------------- detections ----------------

  showDetections(status: 'open' | 'resolved'): void {
    this.detectionStatus.set(status);
    this.detectionPage.set(1);
    this.loadDetections();
  }

  filterDetections(changes: DetectionFilters): void {
    this.detectionFilters.update((filters) => ({ ...filters, ...changes }));
    this.detectionPage.set(1);
    this.loadDetections();
  }

  onDetectionPage(page: number): void {
    this.detectionPage.set(page);
    this.loadDetections();
  }

  resolve(detection: LogDetection, reopen = false): void {
    this.logService.resolve(detection.id, reopen).subscribe({
      next: () => {
        this.toasts.success(reopen ? 'Reopened.' : 'Marked as dealt with.');
        this.loadDetections();
        this.refreshOverview();
      },
      error: () => this.toasts.error('Could not change it.'),
    });
  }

  /** The events behind a detection: same source and address or user, around when it happened. */
  viewEvents(detection: LogDetection): void {
    this.router.navigate([], {
      queryParams: {
        tab: 'search',
        source: detection.source,
        ip: detection.src_ip || null,
        user: detection.src_ip ? null : detection.user || null,
        around: detection.first_seen,
      },
    });
  }

  // ---------------- errors ----------------

  /** Every occurrence of an error group, in the search. */
  viewOccurrences(group: ErrorGroup): void {
    this.router.navigate([], {
      queryParams: { tab: 'search', source: group.source, fingerprint: group.fingerprint, since: 'all' },
    });
  }

  kindLabel(source: LogSource): string {
    return this.kinds.find((k) => k.value === source.os)?.label ?? source.os;
  }

  // ---------------- servers ----------------

  startConnecting(): void {
    this.isConnecting.set(true);
    this.newName.set('');
    this.connectError.set(null);
    this.select('servers');
  }

  connect(): void {
    const org = this.orgContext.selectedOrganization();
    const name = this.newName().trim();
    if (!org || !name) return;
    this.logService.connect(org.id, name, this.newOs()).subscribe({
      next: (source) => {
        this.isConnecting.set(false);
        this.setupFor.set(source);
        this.refreshOverview();
      },
      error: (err) => this.connectError.set(apiErrorMessage(err, 'Could not connect the server.')),
    });
  }

  async replaceKey(source: LogSource): Promise<void> {
    const ok = await this.confirm.ask({
      title: `Show setup steps for ${source.name}?`,
      message:
        'Keys are only shown once, so this makes a new key. The server stops sending until its configuration ' +
        'is updated with the new one.',
      confirmLabel: 'Make a new key',
      icon: 'key',
    });
    if (!ok) return;
    this.logService.replaceKey(source.id).subscribe({
      next: (updated) => this.setupFor.set(updated),
      error: () => this.toasts.error('Could not make a new key.'),
    });
  }

  async disconnect(source: LogSource): Promise<void> {
    const ok = await this.confirm.ask({
      title: `Disconnect ${source.name}?`,
      message: `Its key stops working, and all ${source.events_received.toLocaleString()} of its stored events, its detections and its errors are deleted.`,
      confirmLabel: 'Disconnect and delete',
      danger: true,
      icon: 'server',
    });
    if (!ok) return;
    this.logService.disconnect(source.id).subscribe({
      next: () => {
        this.toasts.success(`${source.name} disconnected.`);
        this.refreshOverview();
        this.loadDetections();
      },
      error: () => this.toasts.error('Could not disconnect it.'),
    });
  }

  finishSetup(): void {
    this.setupFor.set(null);
    this.refreshOverview();
  }

  setRetention(days: string): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) return;
    this.orgService.update(org.id, { log_retention_days: Number(days) }).subscribe({
      next: (updated) => {
        this.orgContext.updateOrganization(updated);
        this.toasts.success(`Logs are now kept for ${days} days.`);
      },
      error: (err) => this.toasts.error(apiErrorMessage(err, 'Could not change how long logs are kept.')),
    });
  }

  severityCount(severity: string): number {
    return (this.overview()?.open_by_severity as Record<string, number> | undefined)?.[severity] ?? 0;
  }

  // ---------------- loading ----------------

  refreshOverview(): void {
    const org = this.orgContext.selectedOrganization();
    if (org) this.loadOverview(org.id);
  }

  private loadOverview(orgId: string): void {
    this.logService.overview(orgId).subscribe({
      next: (overview) => {
        this.overview.set(overview);
        this.isLoading.set(false);
      },
      error: () => this.isLoading.set(false),
    });
    this.logService.sources(orgId).subscribe({ next: (s) => this.sources.set(s), error: () => undefined });
  }

  private loadDetections(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) return;
    this.logService.detections(org.id, this.detectionStatus(), this.detectionPage(), this.detectionFilters()).subscribe({
      next: (page) => {
        // On a refresh, anything not seen before is new: highlighted until the next one.
        const first = this.knownDetections.size === 0;
        this.newDetections.set(new Set(first ? [] : page.results.filter((d) => !this.knownDetections.has(d.id)).map((d) => d.id)));
        page.results.forEach((d) => this.knownDetections.add(d.id));
        this.detections.set(page.results);
        this.detectionCount.set(page.count);
      },
      error: () => undefined,
    });
  }
}
