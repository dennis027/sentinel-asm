import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { NotificationChannel, NotificationRule, Severity } from '../../core/models/models';
import { AuthService } from '../../core/services/auth.service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { NotificationRuleService } from '../../core/services/notification-rule-service';
import { ToastService } from '../../core/services/toast.service';
import { ConfirmService } from '../../core/services/confirm.service';
import { apiErrorMessage } from '../../core/labels';
import { Icon, IconName } from '../../shared/components/icon/icon';

const ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

// The choices offered when setting up an alert, in plain words.
const LEVELS: { value: Severity; title: string; text: string; recommended?: boolean }[] = [
  {
    value: 'critical',
    title: 'Emergencies only',
    text: 'Critical issues, such as an exposed database or an expired certificate. Rare and always urgent.',
  },
  {
    value: 'high',
    title: 'Serious problems',
    text: 'Critical and high issues: worth acting on within days. Right for most teams.',
    recommended: true,
  },
  { value: 'medium', title: 'Most problems', text: 'Adds medium issues. Suits the security team itself.' },
  { value: 'low', title: 'Everything', text: 'Every new issue, including minor ones. Can be busy.' },
];

// What a rule covers, as the end of a sentence: "...finds new critical or high issues".
const COVERS: Record<Severity, string> = {
  critical: 'critical issues',
  high: 'critical or high issues',
  medium: 'medium, high or critical issues',
  low: 'issues of any severity',
  info: 'findings of any kind',
};

/**
 * Alerts & reports: who hears about new problems (by email or in a chat
 * channel), and who gets the Monday PDF. Setting one up is three plain
 * questions -- where, which problems, the weekly report too? -- with a
 * sentence that says exactly what will happen, and a test send to prove
 * it arrives.
 */
@Component({
  selector: 'app-notification-rules',
  imports: [FormsModule, Icon],
  templateUrl: './notification-rules.html',
  styleUrl: './notification-rules.scss',
})
export class NotificationRules {
  private readonly ruleService = inject(NotificationRuleService);
  private readonly orgService = inject(OrganizationService);
  private readonly auth = inject(AuthService);
  private readonly toasts = inject(ToastService);
  private readonly confirm = inject(ConfirmService);
  protected readonly orgContext = inject(OrganizationContextService);

  protected readonly levels = LEVELS;

  readonly rules = signal<NotificationRule[]>([]);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);
  // New issues of the last 30 days by severity, for "about N a month".
  readonly volume = signal<Record<Severity, number> | null>(null);
  // The signed-in person's email, for the one-click "email me" start.
  readonly myEmail = signal<string | null>(null);

  readonly isAdding = signal(false);
  readonly newChannel = signal<NotificationChannel>('email');
  // The email address or the webhook link, depending on the channel.
  readonly destination = signal('');
  readonly newSeverity = signal<Severity>('high');
  readonly newWeeklyReport = signal(true);
  readonly isSaving = signal(false);
  readonly showWebhookHelp = signal(false);

  // rule id -> what is in progress on it
  readonly busy = signal<Record<string, 'test' | 'report' | 'pause' | undefined>>({});

  readonly emailRules = computed(() => this.rules().filter((r) => r.channel === 'email'));
  readonly reportRecipients = computed(() => this.emailRules().filter((r) => r.weekly_report && r.is_active));

  /** The rule being set up, as one sentence, before it is saved. */
  readonly preview = computed(() => {
    const covers = COVERS[this.newSeverity()];
    if (this.newChannel() === 'webhook') {
      return `The chat channel will get a message whenever a scan finds new ${covers}.`;
    }
    const who = this.destination().trim() || 'This address';
    const report = this.newWeeklyReport() ? ', and the one-page report every Monday' : '';
    return `${who} will get an email whenever a scan finds new ${covers}${report}.`;
  });

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      untracked(() => {
        if (!org) return;
        this.fetchRules(org.id);
        this.volume.set(null);
        this.orgService.alertVolume(org.id).subscribe({
          next: (body) => this.volume.set(body.new_issues),
          error: () => undefined,
        });
        this.orgService.members(org.id).subscribe({
          next: (members) =>
            this.myEmail.set(members.find((m) => m.username === this.auth.currentUsername())?.email || null),
          error: () => undefined,
        });
      });
    });
  }

  /** How many new issues this threshold would have covered in the last 30 days. */
  countFor(level: Severity): number | null {
    const volume = this.volume();
    if (!volume) return null;
    return ORDER.slice(ORDER.indexOf(level)).reduce((sum, severity) => sum + (volume[severity] ?? 0), 0);
  }

  covers(rule: NotificationRule): string {
    return COVERS[rule.min_severity];
  }

  /** "Slack channel", "Microsoft Teams channel"... from the webhook's address. */
  chatName(url: string): string {
    const host = (() => {
      try {
        return new URL(url).hostname;
      } catch {
        return '';
      }
    })();
    if (host.endsWith('slack.com')) return 'Slack channel';
    if (host.includes('office.com') || host.includes('logic.azure.com')) return 'Microsoft Teams channel';
    if (host.includes('discord')) return 'Discord channel';
    if (host.includes('mattermost')) return 'Mattermost channel';
    return 'Chat channel';
  }

  channelIcon(rule: NotificationRule): IconName {
    return rule.channel === 'webhook' ? 'message' : 'mail';
  }

  startAdding(channel: NotificationChannel = 'email', destination = ''): void {
    this.isAdding.set(true);
    this.newChannel.set(channel);
    this.destination.set(destination);
    this.newSeverity.set('high');
    this.newWeeklyReport.set(channel === 'email');
    this.errorMessage.set(null);
    this.showWebhookHelp.set(false);
  }

  cancelAdd(): void {
    this.isAdding.set(false);
    this.destination.set('');
    this.errorMessage.set(null);
  }

  chooseChannel(channel: NotificationChannel): void {
    if (channel === this.newChannel()) return;
    this.newChannel.set(channel);
    this.destination.set('');
    this.newWeeklyReport.set(channel === 'email');
  }

  submitNewRule(): void {
    const org = this.orgContext.selectedOrganization();
    const destination = this.destination().trim();
    if (!org || !destination || this.isSaving()) return;
    const viaWebhook = this.newChannel() === 'webhook';

    this.isSaving.set(true);
    this.ruleService
      .create({
        organization: org.id,
        channel: this.newChannel(),
        ...(viaWebhook ? { webhook_url: destination } : { recipient_email: destination }),
        min_severity: this.newSeverity(),
        weekly_report: !viaWebhook && this.newWeeklyReport(),
      })
      .subscribe({
        next: (rule) => {
          this.isSaving.set(false);
          this.cancelAdd();
          this.rules.update((rules) => [...rules, rule]);
          this.toasts.success('Alert saved. Use "Send test" to check it arrives.');
        },
        error: (err) => {
          this.isSaving.set(false);
          // The server says what is wrong: a malformed address, or one
          // that already has an alert.
          this.errorMessage.set(
            err.error?.non_field_errors
              ? 'There is already an alert for this address. Change that one instead.'
              : apiErrorMessage(err, 'Could not save the alert.'),
          );
        },
      });
  }

  sendTest(rule: NotificationRule): void {
    this.setBusy(rule.id, 'test');
    this.ruleService.test(rule.id).subscribe({
      next: (body) => {
        this.setBusy(rule.id, undefined);
        if (body.delivered) this.toasts.success(body.detail);
        else this.toasts.error(body.detail);
      },
      error: () => {
        this.setBusy(rule.id, undefined);
        this.toasts.error('Could not send the test.');
      },
    });
  }

  togglePaused(rule: NotificationRule): void {
    const active = !rule.is_active;
    this.setBusy(rule.id, 'pause');
    this.ruleService.update(rule.id, { is_active: active }).subscribe({
      next: (updated) => {
        this.setBusy(rule.id, undefined);
        this.replace(updated);
        this.toasts.success(active ? 'Alert resumed.' : 'Alert paused. Nothing is sent until you resume it.');
      },
      error: () => {
        this.setBusy(rule.id, undefined);
        this.toasts.error('Could not change the alert.');
      },
    });
  }

  toggleWeeklyReport(rule: NotificationRule): void {
    const weekly = !rule.weekly_report;
    this.ruleService.update(rule.id, { weekly_report: weekly }).subscribe({
      next: (updated) => {
        this.replace(updated);
        this.toasts.success(
          weekly
            ? `${updated.recipient_email} will get the report every Monday.`
            : `${updated.recipient_email} will no longer get the weekly report.`,
        );
      },
      error: () => this.toasts.error('Could not change the weekly report setting.'),
    });
  }

  sendReportNow(rule: NotificationRule): void {
    this.setBusy(rule.id, 'report');
    this.ruleService.sendReport(rule.id).subscribe({
      next: (body) => {
        this.setBusy(rule.id, undefined);
        this.toasts.success(body.detail);
      },
      error: () => {
        this.setBusy(rule.id, undefined);
        this.toasts.error('Could not send the report.');
      },
    });
  }

  async deleteRule(rule: NotificationRule): Promise<void> {
    const viaWebhook = rule.channel === 'webhook';
    const confirmed = await this.confirm.ask({
      title: 'Delete this alert?',
      message: viaWebhook
        ? `The ${this.chatName(rule.webhook_url)} will no longer hear about new issues.`
        : `${rule.recipient_email} will no longer be emailed about new issues${rule.weekly_report ? ' or get the weekly report' : ''}.`,
      confirmLabel: 'Delete alert',
      danger: true,
      icon: 'bell',
    });
    if (!confirmed) return;

    this.ruleService.delete(rule.id).subscribe({
      next: () => {
        this.rules.update((rules) => rules.filter((r) => r.id !== rule.id));
        this.toasts.success('Alert deleted.');
      },
      error: () => this.toasts.error('Could not delete the alert.'),
    });
  }

  private replace(updated: NotificationRule): void {
    this.rules.update((rules) => rules.map((r) => (r.id === updated.id ? updated : r)));
  }

  private setBusy(id: string, what: 'test' | 'report' | 'pause' | undefined): void {
    this.busy.update((busy) => ({ ...busy, [id]: what }));
  }

  private fetchRules(orgId: string): void {
    this.isLoading.set(true);
    this.ruleService.list(orgId).subscribe({
      next: (page) => {
        this.rules.set(page.results);
        this.isLoading.set(false);
      },
      error: () => {
        this.errorMessage.set('Could not load alerts.');
        this.isLoading.set(false);
      },
    });
  }
}
