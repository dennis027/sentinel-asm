import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { EnvironmentProviders, Provider } from '@angular/core';
import { provideRouter } from '@angular/router';
import { Asset, Finding, Organization } from '../core/models/models';

/** What nearly every spec needs: a mock HTTP backend and a router. */
export function provideAppTesting(): (Provider | EnvironmentProviders)[] {
  return [provideHttpClient(), provideHttpClientTesting(), provideRouter([])];
}

export function makeOrganization(overrides: Partial<Organization> = {}): Organization {
  return {
    id: 'org-1',
    name: 'Acme',
    root_domain: 'acme.com',
    is_active: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    my_role: 'owner',
    domain_verified: true,
    domain_verified_at: '2026-01-02T00:00:00Z',
    verification_required: true,
    verification_record_name: '_sentinel-asm.acme.com',
    verification_record_value: 'sentinel-asm-verification=abc123',
    scans_allowed: true,
    sla_days: { critical: 7, high: 30, medium: 90, low: 180 },
    scope_exclusions: [],
    ...overrides,
  };
}

export function makeAsset(overrides: Partial<Asset> = {}): Asset {
  return {
    id: 'a1',
    organization: 'org-1',
    organization_name: 'Acme',
    asset_type: 'subdomain',
    value: 'shop.acme.com',
    source: 'discovered',
    is_active: true,
    first_seen: '2026-01-01T00:00:00Z',
    last_seen: '2026-01-02T00:00:00Z',
    technologies: [],
    risk_score: 100,
    risk_grade: 'A+',
    criticality: 'normal',
    tags: [],
    out_of_scope: false,
    ...overrides,
  };
}

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'finding-1',
    asset: 'asset-1',
    asset_value: 'acme.com',
    finding_type: 'open_port',
    severity: 'high',
    title: 'Open port 22/tcp',
    description: '',
    impact: '',
    remediation: '',
    raw_data: {},
    is_active: true,
    status: 'open',
    status_note: '',
    status_changed_at: null,
    status_changed_by: null,
    first_seen: '2026-01-01T00:00:00Z',
    last_seen: '2026-01-01T00:00:00Z',
    resolved_at: null,
    assignee: null,
    assignee_username: null,
    due_at: null,
    overdue: false,
    controls: [],
    accepted_until: null,
    reopened_count: 0,
    reopened_at: null,
    asset_criticality: 'normal',
    ...overrides,
  };
}

export function page<T>(results: T[], count = results.length) {
  return { count, next: null, previous: null, results };
}
