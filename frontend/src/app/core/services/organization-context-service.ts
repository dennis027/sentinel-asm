import { Injectable, computed, inject, signal } from '@angular/core';
import { OrgRole, Organization } from '../models/models';
import { OrganizationService } from './organization-service';

const SELECTED_ORG_KEY = 'sentinel_selected_org_id';

const ROLE_RANK: Record<OrgRole, number> = { viewer: 0, analyst: 1, admin: 2, owner: 3 };

/**
 * Single source of truth for "which organization is currently
 * selected." Every page (dashboard, assets, scanners, findings,
 * notification-rules) reads `selectedOrganization()` instead of each
 * independently fetching the org list and grabbing results[0] --
 * that pattern meant switching orgs on one page had no effect on any
 * other page, and there was no actual switching UI at all.
 *
 * The selection persists in localStorage (just the id, not sensitive)
 * so it survives a reload, same reasoning as AuthService's token
 * persistence.
 */
@Injectable({ providedIn: 'root' })
export class OrganizationContextService {
  private readonly orgService = inject(OrganizationService);

  private readonly organizations = signal<Organization[]>([]);
  private readonly selectedOrgId = signal<string | null>(
    localStorage.getItem(SELECTED_ORG_KEY),
  );

  readonly allOrganizations = this.organizations.asReadonly();

  readonly selectedOrganization = computed<Organization | null>(() => {
    const orgs = this.organizations();
    const id = this.selectedOrgId();
    return orgs.find((o) => o.id === id) ?? orgs[0] ?? null;
  });

  readonly isLoaded = signal(false);
  readonly loadFailed = signal(false);

  // What the user may do in the selected organization. The API
  // enforces all of this regardless -- these only decide which
  // buttons are worth showing.
  readonly canTriggerScans = computed(() => this.hasRole('analyst'));
  readonly canTriageFindings = computed(() => this.hasRole('analyst'));
  readonly canManageSettings = computed(() => this.hasRole('admin'));

  /** Called once, from the Shell, when an authenticated session starts. */
  loadOrganizations(): void {
    this.loadFailed.set(false);
    this.orgService.list().subscribe({
      error: () => this.loadFailed.set(true),
      next: (page) => {
        this.organizations.set(page.results);
        const stillValid = page.results.some((o) => o.id === this.selectedOrgId());
        if (!stillValid && page.results.length > 0) {
          this.selectOrganization(page.results[0].id);
        }
        this.isLoaded.set(true);
      },
    });
  }

  selectOrganization(orgId: string): void {
    this.selectedOrgId.set(orgId);
    localStorage.setItem(SELECTED_ORG_KEY, orgId);
  }

  /** Adds a just-created organization and switches to it. */
  addOrganization(created: Organization): void {
    this.organizations.update((orgs) =>
      [...orgs, created].sort((a, b) => a.name.localeCompare(b.name)),
    );
    this.selectOrganization(created.id);
  }

  /** Drops an organization the user has left or deleted. */
  removeOrganization(orgId: string): void {
    this.organizations.update((orgs) => orgs.filter((o) => o.id !== orgId));
  }

  /** Swaps in a fresh copy of one organization (e.g. after verifying its domain). */
  updateOrganization(updated: Organization): void {
    this.organizations.update((orgs) => orgs.map((o) => (o.id === updated.id ? updated : o)));
  }

  private hasRole(minimum: OrgRole): boolean {
    const role = this.selectedOrganization()?.my_role;
    return !!role && ROLE_RANK[role] >= ROLE_RANK[minimum];
  }

  clear(): void {
    this.organizations.set([]);
    this.selectedOrgId.set(null);
    this.isLoaded.set(false);
    this.loadFailed.set(false);
    localStorage.removeItem(SELECTED_ORG_KEY);
  }
}