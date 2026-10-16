import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { RouterLink } from '@angular/router';
import { FixPlan, FixPlanStep, Member } from '../../core/models/models';
import { FindingService } from '../../core/services/finding-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { ToastService } from '../../core/services/toast.service';
import { EmptyState } from '../../shared/components/empty-state/empty-state';
import { Icon } from '../../shared/components/icon/icon';

const GRADE_ORDER = ['F', 'D', 'C', 'B', 'A', 'A+'];

/**
 * The open issues as a to-do list: grouped into the actions that fix
 * them, most urgent first, each with the grade the organization would
 * have once it and every step before it is done. Answers "what do we
 * do on Monday?" and "what does it get us?".
 */
@Component({
  selector: 'app-fix-plan',
  imports: [RouterLink, Icon, EmptyState],
  templateUrl: './fix-plan.html',
  styleUrl: './fix-plan.scss',
})
export class FixPlanPage {
  private readonly orgService = inject(OrganizationService);
  private readonly findingService = inject(FindingService);
  private readonly toasts = inject(ToastService);
  protected readonly orgContext = inject(OrganizationContextService);

  readonly plan = signal<FixPlan | null>(null);
  readonly isLoading = signal(true);
  readonly errorMessage = signal<string | null>(null);
  readonly members = signal<Member[]>([]);
  // index of the step whose hosts are listed
  readonly openStep = signal<number | null>(null);
  readonly assigningStep = signal<number | null>(null);

  /** The steps where the grade goes up: "fix 1-3 and you are a B". */
  readonly milestones = computed(() => {
    const plan = this.plan();
    if (!plan?.current_grade) return [];
    const result: { step: number; grade: string }[] = [];
    let best = plan.current_grade;
    plan.steps.forEach((step, index) => {
      if (step.grade_after && GRADE_ORDER.indexOf(step.grade_after) > GRADE_ORDER.indexOf(best)) {
        result.push({ step: index + 1, grade: step.grade_after });
        best = step.grade_after;
      }
    });
    return result;
  });

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      untracked(() => {
        if (!org) return;
        this.load(org.id);
        this.members.set([]);
        if (this.orgContext.canTriageFindings()) {
          this.orgService.members(org.id).subscribe({ next: (m) => this.members.set(m), error: () => undefined });
        }
      });
    });
  }

  /** Whether this step lifts the grade above the step before it. */
  raisesGrade(index: number): boolean {
    return this.milestones().some((m) => m.step === index + 1);
  }

  toggle(index: number): void {
    this.openStep.set(this.openStep() === index ? null : index);
  }

  assignAll(step: FixPlanStep, index: number, value: string): void {
    if (!value) return;
    const assignee = Number(value);
    this.assigningStep.set(index);
    this.findingService.bulk(step.items.map((i) => i.finding), { action: 'assign', assignee }).subscribe({
      next: (body) => {
        this.assigningStep.set(null);
        const who = this.members().find((m) => m.user_id === assignee)?.username ?? 'them';
        this.toasts.success(`Assigned ${body.updated} issue(s) to ${who}.`);
      },
      error: () => {
        this.assigningStep.set(null);
        this.toasts.error('Could not assign these issues.');
      },
    });
  }

  private load(orgId: string): void {
    this.isLoading.set(true);
    this.errorMessage.set(null);
    this.orgService.fixPlan(orgId).subscribe({
      next: (plan) => {
        this.plan.set(plan);
        this.isLoading.set(false);
      },
      error: () => {
        this.errorMessage.set('Could not load the fix plan.');
        this.isLoading.set(false);
      },
    });
  }
}
