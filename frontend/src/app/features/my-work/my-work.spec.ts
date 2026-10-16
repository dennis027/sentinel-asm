import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeFinding, makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { MyWork } from './my-work';

const API = environment.apiBaseUrl;
const inDays = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

describe('MyWork', () => {
  let fixture: ComponentFixture<MyWork>;
  let http: HttpTestingController;
  let el: HTMLElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [MyWork], providers: [provideAppTesting()] }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));
    fixture = TestBed.createComponent(MyWork);
    el = fixture.nativeElement;
    fixture.detectChanges();
  });

  afterEach(() => http.verify());

  it("groups the person's open issues by deadline", () => {
    const request = http.expectOne((r) => r.url === `${API}/findings/`);
    expect(request.request.params.get('assignee')).toBe('me');
    expect(request.request.params.get('triaged')).toBe('false');
    request.flush(
      page([
        makeFinding({ id: 'f1', title: 'Late one', due_at: inDays(-3), overdue: true }),
        makeFinding({ id: 'f2', title: 'Soon', due_at: inDays(2.5) }),
        makeFinding({ id: 'f3', title: 'Later', due_at: inDays(40) }),
      ]),
    );
    fixture.detectChanges();
    const sections = Array.from(el.querySelectorAll('.bucket'));
    expect(sections.map((s) => s.querySelector('h2')?.textContent?.trim().split(' ')[0])).toEqual(['Overdue', 'Due', 'Due']);
    expect(sections[0].textContent).toContain('3 days late');
    expect(sections[1].textContent).toContain('Soon');
    expect((sections[0].querySelector('a.title') as HTMLAnchorElement).getAttribute('href')).toBe('/findings/f1');
  });

  it('says when nothing is assigned', () => {
    http.expectOne((r) => r.url === `${API}/findings/`).flush(page([]));
    fixture.detectChanges();
    expect(el.textContent).toContain('Nothing assigned to you');
  });
});
