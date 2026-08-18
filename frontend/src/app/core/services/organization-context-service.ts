import { Injectable, computed, inject, signal } from '@angular/core';
import { Organization } from '../models/models';
import { OrganizationService } from './organization-service';

const SELECTED_ORG_KEY = 'sentinel_selected_org_id';

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

  /** Called once, from the Shell, when an authenticated session starts. */
  loadOrganizations(): void {
    this.orgService.list().subscribe({
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

  clear(): void {
    this.organizations.set([]);
    this.selectedOrgId.set(null);
    this.isLoaded.set(false);
    localStorage.removeItem(SELECTED_ORG_KEY);
  }
}