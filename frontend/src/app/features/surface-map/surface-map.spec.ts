import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { environment } from '../../../environments/environment';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

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
    http.expectOne(`${API}/organizations/org-1/surface-map/`).flush({
      root_domain: 'acme.com',
      total_assets: 120,
      assets_at_risk: 2,
      hidden: 117,
      nodes: [
        { id: 'a1', value: 'db.acme.com', risk_score: 20, risk_grade: 'F', open_findings: 6, critical_high: 3, clean: false },
        { id: 'a2', value: 'www.acme.com', risk_score: 80, risk_grade: 'B', open_findings: 1, critical_high: 0, clean: false },
        { id: 'a3', value: 'cdn.acme.com', risk_score: 100, risk_grade: 'A+', open_findings: 0, critical_high: 0, clean: true },
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

  it('opens a host\'s findings when it is clicked', () => {
    const navigate = spyOn(TestBed.inject(Router), 'navigate').and.resolveTo(true);
    (el.querySelector('circle.node') as SVGElement).dispatchEvent(new MouseEvent('click'));
    expect(navigate).toHaveBeenCalledWith(['/findings'], { queryParams: { asset: 'a1', assetName: 'db.acme.com' } });
  });

  it('explains a host on hover', () => {
    (el.querySelector('circle.node') as SVGElement).dispatchEvent(new MouseEvent('mouseenter'));
    fixture.detectChanges();
    expect(el.querySelector('.tooltip')?.textContent).toContain('3 critical or high');
  });
});
