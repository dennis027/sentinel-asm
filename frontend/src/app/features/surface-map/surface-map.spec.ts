import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeAsset, makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { SurfaceMapPage } from './surface-map';

const API = environment.apiBaseUrl;

describe('SurfaceMapPage', () => {
  let fixture: ComponentFixture<SurfaceMapPage>;
  let el: HTMLElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [SurfaceMapPage], providers: [provideAppTesting()] }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));
    fixture = TestBed.createComponent(SurfaceMapPage);
    el = fixture.nativeElement;
    fixture.detectChanges();
    http.expectOne(`${API}/organizations/org-1/members/`).flush([]);
    http.expectOne(`${API}/organizations/org-1/surface-map/`).flush({
      root_domain: 'acme.com',
      total_assets: 120,
      assets_at_risk: 2,
      hidden: 117,
      nodes: [
        { id: 'a1', value: 'db.acme.com', risk_score: 20, risk_grade: 'F', open_findings: 6, critical_high: 3, clean: false, provider: '' },
        { id: 'a2', value: 'www.acme.com', risk_score: 80, risk_grade: 'B', open_findings: 1, critical_high: 0, clean: false, provider: 'AWS' },
        { id: 'a3', value: 'cdn.acme.com', risk_score: 100, risk_grade: 'A+', open_findings: 0, critical_high: 0, clean: true, provider: 'Cloudflare' },
      ],
    });
    fixture.detectChanges();
  });

  it('draws every host, coloured by grade and sized by open issues', () => {
    const nodes = Array.from(el.querySelectorAll('circle.node'));
    expect(nodes.length).toBe(3);
    expect(nodes[0].classList).toContain('bad');
    expect(nodes[1].classList).toContain('warn');
    expect(nodes[2].classList).toContain('good');
    expect(Number(nodes[0].getAttribute('r'))).toBeGreaterThan(Number(nodes[1].getAttribute('r')));
    expect(el.querySelector('.stats')?.textContent).toContain('117 more clean hosts not drawn');
    expect(el.querySelectorAll('.legend li').length).toBe(5);
  });

  it('opens a summary of a host when it is clicked', () => {
    const http = TestBed.inject(HttpTestingController);
    (el.querySelector('circle.node') as SVGElement).dispatchEvent(new MouseEvent('click'));
    http.expectOne(`${API}/assets/a1/`).flush(makeAsset({ id: 'a1', value: 'db.acme.com' }));
    fixture.detectChanges();
    http.expectOne((r) => r.url === `${API}/findings/`).flush(page([]));
    fixture.detectChanges();
    expect(el.querySelector('app-asset-peek h2')?.textContent).toContain('db.acme.com');
  });

  it('hides a grade from the legend and arranges hosts by hosting', () => {
    (el.querySelector('.legend button') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('circle.node.bad')?.classList).toContain('dimmed');
    const byHosting = Array.from(el.querySelectorAll('.toggle button')).find((b) => b.textContent?.includes('By hosting')) as HTMLButtonElement;
    byHosting.click();
    fixture.detectChanges();
    const labels = Array.from(el.querySelectorAll('.sector-label')).map((t) => t.textContent?.trim());
    expect(labels.length).toBe(3);
    expect(labels.join(' ')).toContain('AWS');
  });

  it('explains a host on hover', () => {
    (el.querySelector('circle.node') as SVGElement).dispatchEvent(new MouseEvent('mouseenter'));
    fixture.detectChanges();
    expect(el.querySelector('.tooltip')?.textContent).toContain('3 critical or high');
  });
});
