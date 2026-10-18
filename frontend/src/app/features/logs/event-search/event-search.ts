import { Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { DatePipe, DecimalPipe } from '@angular/common';
import { toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { LogEventRow, LogFacets, LogSource, LogTimeline } from '../../../core/models/models';
import { LogSearch, LogService } from '../../../core/services/log.service';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { ToastService } from '../../../core/services/toast.service';
import { EmptyState } from '../../../shared/components/empty-state/empty-state';
import { Icon } from '../../../shared/components/icon/icon';
import { Pager } from '../../../shared/components/pager/pager';
import { every } from '../../../shared/live';
import { PluralPipe } from '../../../shared/pipes/plural';
import { LOG_CATEGORIES } from '../log-categories';

/** Every filter the search understands; each one lives in the page address, so a view can be shared. */
export const FILTER_KEYS = [
  'q', 'source', 'category', 'level', 'service', 'release', 'host', 'user', 'ip', 'status', 'fingerprint',
  'since', 'after', 'before', 'around',
] as const;
export type FilterKey = (typeof FILTER_KEYS)[number];
export type Filters = Record<FilterKey, string>;

const PAGE = 50;
const LIVE_MS = 3000;
// The timeline and option counts refresh every this many live ticks.
const SLOW_EVERY = 5;
const LIVE_KEEP = 300;

export const LEVELS = [
  { value: 'problems', label: 'Warnings and errors' },
  { value: 'error', label: 'Errors' },
  { value: 'warning', label: 'Warnings' },
  { value: 'info', label: 'Info' },
];
const SINCE = [
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: 'all', label: 'Everything kept' },
  { value: 'custom', label: 'Custom range…' },
];
// "field:value" words typed in the search box become filters.
const SYNTAX: Record<string, FilterKey> = {
  level: 'level', service: 'service', svc: 'service', release: 'release', version: 'release', host: 'host',
  user: 'user', ip: 'ip', from: 'ip', status: 'status', source: 'source', server: 'source', app: 'source',
  kind: 'category', category: 'category',
};
const TOKEN = /(\w+):("[^"]*"|\S+)/g;

/**
 * The log search: every event from every server and app, filtered by
 * anything (source, kind, level, service, release, host, user, address,
 * status, time) with a count beside each option, a timeline of matching
 * events, and new events appearing as they arrive.
 */
@Component({
  selector: 'app-event-search',
  imports: [DatePipe, DecimalPipe, FormsModule, Icon, EmptyState, Pager, PluralPipe],
  templateUrl: './event-search.html',
  styleUrl: './event-search.scss',
})
export class EventSearch {
  private readonly logService = inject(LogService);
  private readonly orgContext = inject(OrganizationContextService);
  private readonly toasts = inject(ToastService);
  private readonly router = inject(Router);
  private readonly queryParams = toSignal(inject(ActivatedRoute).queryParamMap);

  readonly sources = input<LogSource[]>([]);
  readonly hasApps = input(false);

  protected readonly categories = LOG_CATEGORIES;
  protected readonly levels = LEVELS;
  protected readonly sinceOptions = SINCE;
  protected readonly pageSize = PAGE;

  readonly filters = computed<Filters>(() => {
    const params = this.queryParams();
    return Object.fromEntries(FILTER_KEYS.map((key) => [key, params?.get(key) ?? ''])) as Filters;
  });
  readonly page = computed(() => Number(this.queryParams()?.get('page') ?? 1) || 1);
  readonly since = computed(() => this.filters().since || '24h');

  readonly events = signal<LogEventRow[]>([]);
  readonly eventCount = signal(0);
  readonly isSearching = signal(false);
  readonly expandedEvent = signal<number | null>(null);
  readonly facets = signal<LogFacets | null>(null);
  readonly timeline = signal<LogTimeline | null>(null);
  readonly showMore = signal(false);
  // What is typed in the search box (applied on Enter).
  readonly text = signal('');

  readonly live = signal(true);
  // Live only makes sense on the first page of an open-ended time range.
  readonly isLive = computed(
    () => this.live() && this.page() === 1 && !this.filters().before && !this.filters().around,
  );
  // Ids that just arrived, shown highlighted for a moment.
  readonly fresh = signal<ReadonlySet<number>>(new Set());
  private liveTicks = 0;

  /** The active filters as removable chips. */
  readonly chips = computed(() => {
    const f = this.filters();
    const chips: { key: FilterKey | 'range'; label: string }[] = [];
    const add = (key: FilterKey, label: string) => f[key] && chips.push({ key, label });
    add('source', `Source: ${this.sources().find((s) => s.id === f.source)?.name ?? 'one source'}`);
    add('category', `Kind: ${this.categories.find((c) => c.value === f.category)?.label ?? f.category}`);
    add('level', `Level: ${this.levels.find((l) => l.value === f.level)?.label ?? f.level}`);
    add('service', `Service: ${f.service}`);
    add('release', `Release: ${f.release}`);
    add('host', `Host: ${f.host}`);
    add('user', `User: ${f.user}`);
    add('ip', `Address: ${f.ip}`);
    add('status', `Status: ${f.status}`);
    add('fingerprint', 'One error, every occurrence');
    add('q', `Text: “${f.q}”`);
    if (f.around) chips.push({ key: 'around', label: `Around ${new Date(f.around).toLocaleString()}` });
    if (f.since === 'custom' && (f.after || f.before)) {
      const when = (v: string) => (v ? new Date(v).toLocaleString() : '…');
      chips.push({ key: 'range', label: `${when(f.after)} → ${when(f.before)}` });
    }
    return chips;
  });

  readonly maxBar = computed(() =>
    Math.max(1, ...(this.timeline()?.buckets ?? []).map((b) => b.error + b.warning + b.info)),
  );

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      const filters = this.filters();
      const page = this.page();
      untracked(() => {
        if (!org) return;
        this.text.set(filters.q);
        this.load(page);
      });
    });
    every(LIVE_MS, () => this.liveTick());
  }

  // ---------------- filters ----------------

  set(changes: Partial<Record<FilterKey, string | null>>): void {
    const queryParams: Record<string, string | null> = { tab: 'search', page: null };
    for (const [key, value] of Object.entries(changes)) queryParams[key] = value || null;
    this.router.navigate([], { queryParams, queryParamsHandling: 'merge', replaceUrl: true });
  }

  setSince(value: string): void {
    if (value === 'custom') {
      // Start the custom range from what was showing.
      const hours = { '1h': 1, '24h': 24, '7d': 168, '30d': 720 }[this.since()] ?? 24;
      this.set({ since: 'custom', after: new Date(Date.now() - hours * 3_600_000).toISOString(), before: null, around: null });
    } else {
      this.set({ since: value === '24h' ? null : value, after: null, before: null, around: null });
    }
  }

  /** The search box: free text, plus any "field:value" words as filters. */
  submitText(): void {
    const changes: Partial<Record<FilterKey, string | null>> = {};
    const rest = this.text().replace(TOKEN, (whole, field: string, raw: string) => {
      const key = SYNTAX[field.toLowerCase()];
      if (!key) return whole;
      const value = raw.replace(/^"|"$/g, '');
      changes[key] = this.resolve(key, value);
      return '';
    });
    changes.q = rest.replace(/\s+/g, ' ').trim() || null;
    this.set(changes);
  }

  remove(key: FilterKey | 'range'): void {
    if (key === 'range') this.set({ since: null, after: null, before: null });
    else this.set({ [key]: null });
  }

  clearAll(): void {
    this.set(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])));
  }

  /** From an event's detail: show only events with this value. */
  filterBy(key: FilterKey, value: string | null | undefined): void {
    if (value) this.set({ [key]: value });
  }

  /** Click a bar of the timeline: zoom in to that stretch of time. */
  zoom(bucket: { t: string }): void {
    const size = (this.timeline()?.bucket_seconds ?? 60) * 1000;
    const start = new Date(bucket.t).getTime();
    this.set({ since: 'custom', after: new Date(start).toISOString(), before: new Date(start + size).toISOString(), around: null });
  }

  setRange(edge: 'after' | 'before', local: string): void {
    this.set({ since: 'custom', [edge]: local ? new Date(local).toISOString() : null });
  }

  /** An ISO time as a datetime-local input value (local time, minutes). */
  localInput(iso: string): string {
    if (!iso) return '';
    const d = new Date(iso);
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  onPage(page: number): void {
    this.router.navigate([], { queryParams: { page: page > 1 ? page : null }, queryParamsHandling: 'merge' });
  }

  toggleLive(): void {
    this.live.set(!this.live());
  }

  // ---------------- counts beside options ----------------

  sourceCount(id: string): number {
    return this.facets()?.source[id] ?? 0;
  }

  categoryCount(value: string): number {
    return (this.facets()?.category as Record<string, number> | undefined)?.[value] ?? 0;
  }

  levelCount(value: string): number {
    const levels = (this.facets()?.level ?? {}) as Record<string, number>;
    return value === 'problems' ? (levels['warning'] ?? 0) + (levels['error'] ?? 0) : (levels[value] ?? 0);
  }

  statusCount(value: '2xx' | '3xx' | '4xx' | '5xx'): number {
    return this.facets()?.status[value] ?? 0;
  }

  /** A list facet (service, release, host), keeping the chosen value even when it has no matches. */
  options(key: 'service' | 'release' | 'host'): [string, number][] {
    const list = this.facets()?.[key] ?? [];
    const chosen = this.filters()[key];
    return chosen && !list.some(([value]) => value === chosen) ? [[chosen, 0], ...list] : list;
  }

  barTitle(b: { t: string; error: number; warning: number; info: number }): string {
    const when = new Date(b.t).toLocaleString();
    return `${when}: ${b.error + b.warning + b.info} events (${b.error} errors, ${b.warning} warnings). Click to zoom in.`;
  }

  // ---------------- events ----------------

  toggleEvent(id: number): void {
    this.expandedEvent.set(this.expandedEvent() === id ? null : id);
  }

  rawText(event: LogEventRow): string {
    return JSON.stringify(event.raw, null, 2);
  }

  /** The stack trace in an event, whichever shape the app sent it in. */
  stackOf(event: LogEventRow): string {
    const raw = event.raw as Record<string, unknown>;
    for (const key of ['exception', 'err', 'error']) {
      const nested = raw[key];
      if (nested && typeof nested === 'object') {
        const value = (nested as Record<string, unknown>)['stacktrace'] ?? (nested as Record<string, unknown>)['stack'];
        if (typeof value === 'string') return value;
      }
    }
    for (const key of ['stack_trace', 'stacktrace', 'stack', 'exc_text', '@x', 'Exception', 'exception', 'error.stack_trace']) {
      const value = raw[key];
      if (typeof value === 'string' && value.includes('\n')) return value;
    }
    return '';
  }

  exportCsv(): void {
    const query = this.query();
    if (!query) return;
    this.logService.exportCsv(query).subscribe({
      next: (blob) => {
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `densight-logs-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-')}.csv`;
        link.click();
        URL.revokeObjectURL(url);
      },
      error: () => this.toasts.error('The export failed. Try again.'),
    });
  }

  // ---------------- loading ----------------

  private resolve(key: FilterKey, value: string): string {
    if (key === 'source') {
      return this.sources().find((s) => s.name.toLowerCase() === value.toLowerCase() || s.id === value)?.id ?? value;
    }
    if (key === 'category') {
      const lower = value.toLowerCase();
      return this.categories.find((c) => c.value === lower || c.label.toLowerCase().startsWith(lower))?.value ?? value;
    }
    if (key === 'level') {
      const lower = value.toLowerCase();
      return lower.startsWith('warn') ? 'warning' : lower.startsWith('err') ? 'error' : lower;
    }
    return value;
  }

  /** The filters as an API query. */
  query(): LogSearch | null {
    const org = this.orgContext.selectedOrganization();
    if (!org) return null;
    const f = this.filters();
    const query: LogSearch = { organization: org.id, since: this.since() };
    for (const key of FILTER_KEYS) {
      if (key !== 'since' && key !== 'around' && f[key]) (query as unknown as Record<string, string>)[key] = f[key];
    }
    if (f.around) {
      // An hour before a detection to a day after, whatever the time range says.
      const t = new Date(f.around).getTime();
      query.since = 'custom';
      query.after = new Date(t - 3_600_000).toISOString();
      query.before = new Date(t + 24 * 3_600_000).toISOString();
    }
    return query;
  }

  private load(page: number): void {
    const query = this.query();
    if (!query) return;
    this.isSearching.set(true);
    this.liveTicks = 0;
    this.logService.events({ ...query, page }).subscribe({
      next: (result) => {
        this.events.set(result.results);
        this.eventCount.set(result.count);
        this.isSearching.set(false);
      },
      error: () => this.isSearching.set(false),
    });
    this.loadOverviews(query);
  }

  private loadOverviews(query: LogSearch): void {
    this.logService.facets(query).subscribe({ next: (facets) => this.facets.set(facets), error: () => undefined });
    this.logService.timeline(query).subscribe({ next: (timeline) => this.timeline.set(timeline), error: () => undefined });
  }

  /** New events since the newest one shown, added to the top. */
  private liveTick(): void {
    const query = this.query();
    if (!query || !this.isLive() || this.isSearching()) return;
    const newest = this.events().reduce((max, e) => Math.max(max, e.id), 0);
    this.logService.events({ ...query, after_id: newest, page_size: 200 }).subscribe({
      next: (result) => {
        if (result.results.length) {
          const arrived = [...result.results].sort((a, b) => b.occurred_at.localeCompare(a.occurred_at));
          this.events.update((events) => [...arrived, ...events].slice(0, LIVE_KEEP));
          this.eventCount.update((count) => count + result.count);
          this.fresh.set(new Set(arrived.map((e) => e.id)));
        } else if (this.fresh().size) {
          this.fresh.set(new Set());
        }
      },
      error: () => undefined,
    });
    if (++this.liveTicks % SLOW_EVERY === 0) this.loadOverviews(query);
  }
}
