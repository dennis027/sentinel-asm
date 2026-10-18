import { Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { DatePipe, DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { apiErrorMessage } from '../../../core/labels';
import { LogAlertRule, LogEventRow, LogSource } from '../../../core/models/models';
import { ConfirmService } from '../../../core/services/confirm.service';
import { LogAlertRuleInput, LogService } from '../../../core/services/log.service';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { ToastService } from '../../../core/services/toast.service';
import { Icon } from '../../../shared/components/icon/icon';
import { LOG_CATEGORIES } from '../log-categories';

type Draft = Omit<LogAlertRuleInput, 'organization'>;

const BLANK: Draft = {
  name: '',
  contains: '',
  source: null,
  category: '',
  level: '',
  threshold: 1,
  window_minutes: 5,
  severity: 'medium',
};

// One click to start from a common case.
export const ALERT_IDEAS: { label: string; draft: Partial<Draft> }[] = [
  { label: 'Payments failing', draft: { name: 'Payments failing', contains: 'payment', level: 'error', threshold: 10, window_minutes: 5, severity: 'high' } },
  { label: 'Database connection lost', draft: { name: 'Database connection lost', contains: 'connection refused', threshold: 3, window_minutes: 5, severity: 'high' } },
  { label: 'Any error in one app', draft: { name: 'Errors in an app', category: 'app_error', threshold: 1, window_minutes: 5, severity: 'medium' } },
  { label: 'Out of disk space', draft: { name: 'Disk full', contains: 'No space left on device', threshold: 1, window_minutes: 60, severity: 'critical' } },
];

/**
 * The organization's own log alerts: "tell me when <text> appears <n>
 * times within <m> minutes". Shown under "What we watch for", above
 * the built-in detections. Analysts and above can change them.
 */
@Component({
  selector: 'app-log-alerts',
  imports: [DatePipe, DecimalPipe, FormsModule, Icon],
  templateUrl: './log-alerts.html',
  styleUrl: './log-alerts.scss',
})
export class LogAlerts implements OnInit {
  private readonly logService = inject(LogService);
  private readonly orgContext = inject(OrganizationContextService);
  private readonly toasts = inject(ToastService);
  private readonly confirm = inject(ConfirmService);

  readonly sources = input<LogSource[]>([]);
  readonly canEdit = input(false);

  protected readonly categories = LOG_CATEGORIES;
  protected readonly ideas = ALERT_IDEAS;

  readonly rules = signal<LogAlertRule[]>([]);
  readonly loaded = signal(false);
  // null: no form; '': a new alert; otherwise the id being edited.
  readonly editing = signal<string | null>(null);
  readonly draft = signal<Draft>({ ...BLANK });
  readonly error = signal<string | null>(null);
  readonly isSaving = signal(false);
  readonly preview = signal<{ matches_24h: number; examples: LogEventRow[] } | null>(null);

  /** The draft in one plain sentence, so people can check what they built. */
  readonly sentence = computed(() => this.describe(this.draft()));

  ngOnInit(): void {
    this.load();
  }

  describe(rule: Draft | LogAlertRule): string {
    const what = rule.contains ? `“${rule.contains}”` : 'an event';
    const kind = rule.category ? ` (${this.categories.find((c) => c.value === rule.category)?.label.toLowerCase()})` : '';
    const level = rule.level === 'error' ? ' at error level' : rule.level === 'warning' ? ' at warning level or worse' : '';
    const where = rule.source ? ` on ${this.sources().find((s) => s.id === rule.source)?.name ?? 'one source'}` : ' on any server or app';
    const times = rule.threshold === 1 ? '' : ` ${rule.threshold} times within ${rule.window_minutes} minutes`;
    return `Alert (${rule.severity}) when ${what}${kind}${level} appears${times}${where}.`;
  }

  start(idea?: Partial<Draft>): void {
    this.draft.set({ ...BLANK, ...idea });
    this.editing.set('');
    this.error.set(null);
    this.preview.set(null);
  }

  edit(rule: LogAlertRule): void {
    const { name, contains, source, category, level, threshold, window_minutes, severity } = rule;
    this.draft.set({ name, contains, source, category, level, threshold, window_minutes, severity });
    this.editing.set(rule.id);
    this.error.set(null);
    this.preview.set(null);
  }

  cancel(): void {
    this.editing.set(null);
  }

  update<K extends keyof Draft>(field: K, value: Draft[K]): void {
    this.draft.update((draft) => ({ ...draft, [field]: value }));
    this.preview.set(null);
  }

  test(): void {
    const body = this.body();
    if (!body) return;
    this.logService.previewAlertRule(body).subscribe({
      next: (result) => {
        this.error.set(null);
        this.preview.set(result);
      },
      error: (err) => this.error.set(apiErrorMessage(err, 'Could not test this alert.')),
    });
  }

  save(): void {
    const body = this.body();
    if (!body) return;
    const id = this.editing();
    this.isSaving.set(true);
    const request = id ? this.logService.updateAlertRule(id, body) : this.logService.createAlertRule(body);
    request.subscribe({
      next: (rule) => {
        this.isSaving.set(false);
        this.editing.set(null);
        this.toasts.success(id ? 'Alert updated.' : `Alert “${rule.name}” is on. It goes to your alerts like the built-in ones.`);
        this.load();
      },
      error: (err) => {
        this.isSaving.set(false);
        this.error.set(apiErrorMessage(err, 'Could not save this alert.'));
      },
    });
  }

  toggle(rule: LogAlertRule): void {
    this.logService.updateAlertRule(rule.id, { enabled: !rule.enabled }).subscribe({
      next: (updated) => this.rules.update((rules) => rules.map((r) => (r.id === updated.id ? updated : r))),
      error: () => this.toasts.error('Could not change it.'),
    });
  }

  async remove(rule: LogAlertRule): Promise<void> {
    const ok = await this.confirm.ask({
      title: `Delete “${rule.name}”?`,
      message: 'Detections it already raised are kept.',
      confirmLabel: 'Delete alert',
      danger: true,
      icon: 'bell',
    });
    if (!ok) return;
    this.logService.deleteAlertRule(rule.id).subscribe({
      next: () => {
        this.toasts.success('Alert deleted.');
        this.load();
      },
      error: () => this.toasts.error('Could not delete it.'),
    });
  }

  private body(): LogAlertRuleInput | null {
    const org = this.orgContext.selectedOrganization();
    if (!org) return null;
    const draft = this.draft();
    return { ...draft, organization: org.id, threshold: Number(draft.threshold), window_minutes: Number(draft.window_minutes) };
  }

  private load(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) return;
    this.logService.alertRules(org.id).subscribe({
      next: (rules) => {
        this.rules.set(rules);
        this.loaded.set(true);
      },
      error: () => this.loaded.set(true),
    });
  }
}
