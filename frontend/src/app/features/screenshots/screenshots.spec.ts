import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { environment } from '../../../environments/environment';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { makeFinding, makeOrganization, page, provideAppTesting } from '../../testing/test-helpers';

import { Screenshots } from './screenshots';

const API = environment.apiBaseUrl;

function shot(id: string, title: string, url: string) {
  return makeFinding({
    id,
    finding_type: 'screenshot',
    severity: 'info',
    asset_value: 'shop.acme.com',
    raw_data: { page_title: title, final_url: url, screenshot_path: 'x.png' },
  });
}

describe('Screenshots', () => {
  let fixture: ComponentFixture<Screenshots>;
  let http: HttpTestingController;
  let el: HTMLElement;

  beforeEach(async () => {
    localStorage.clear();
    await TestBed.configureTestingModule({
      imports: [Screenshots],
      providers: [provideAppTesting()],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);

    TestBed.inject(OrganizationContextService).loadOrganizations();
    http.expectOne((r) => r.url === `${API}/organizations/`).flush(page([makeOrganization()]));

    fixture = TestBed.createComponent(Screenshots);
    el = fixture.nativeElement;
    fixture.detectChanges();
  });

  afterEach(() => http.verify());

  function expectList() {
    return http.expectOne((r) => r.url === `${API}/findings/`);
  }

  it('lists current screenshots for the organization as a gallery', () => {
    const request = expectList();
    const params = request.request.params;
    expect(params.get('finding_type')).toBe('screenshot');
    expect(params.get('organization')).toBe('org-1');
    expect(params.get('is_active')).toBe('true');
    expect(params.get('page_size')).toBe('24');
    request.flush(
      page([
        shot('s1', 'Acme Shop', 'https://shop.acme.com/'),
        shot('s2', 'Sign in', 'https://shop.acme.com/login'),
      ]),
    );
    http.expectOne(`${API}/findings/s1/screenshot/`).flush(new Blob(['a']));
    http.expectOne(`${API}/findings/s2/screenshot/`).flush(new Blob(['b']));
    fixture.detectChanges();

    const tiles = Array.from(el.querySelectorAll('.tile'));
    expect(tiles.length).toBe(2);
    expect(tiles[1].querySelector('.tile-title')?.textContent).toBe('Sign in');
    expect(tiles[1].querySelector('.tile-url')?.textContent).toBe('shop.acme.com/login');
    expect((tiles[0].querySelector('img') as HTMLImageElement).src).toMatch(/^blob:/);
  });

  it('opens a screenshot at full size and closes it again', () => {
    expectList().flush(page([shot('s1', 'Acme Shop', 'https://shop.acme.com/')]));
    http.expectOne(`${API}/findings/s1/screenshot/`).flush(new Blob(['a']));
    fixture.detectChanges();

    (el.querySelector('.tile') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('.viewer .viewer-title')?.textContent).toBe('Acme Shop');
    expect(el.querySelector('.viewer img.full')).not.toBeNull();

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    fixture.detectChanges();
    expect(el.querySelector('.viewer')).toBeNull();
  });

  it('steps through screenshots with the arrows and the arrow keys', () => {
    expectList().flush(
      page([
        shot('s1', 'Acme Shop', 'https://shop.acme.com/'),
        shot('s2', 'Sign in', 'https://shop.acme.com/login'),
      ]),
    );
    http.expectOne(`${API}/findings/s1/screenshot/`).flush(new Blob(['a']));
    http.expectOne(`${API}/findings/s2/screenshot/`).flush(new Blob(['b']));
    fixture.detectChanges();

    (el.querySelector('.tile') as HTMLButtonElement).click();
    fixture.detectChanges();
    const prev = () => el.querySelector('.nav.prev') as HTMLButtonElement;
    const next = () => el.querySelector('.nav.next') as HTMLButtonElement;
    expect(el.querySelector('.viewer-position')?.textContent?.trim()).toBe('1 of 2');
    expect(prev().disabled).toBeTrue();

    next().click();
    fixture.detectChanges();
    expect(el.querySelector('.viewer-title')?.textContent).toBe('Sign in');
    expect(el.querySelector('.viewer-position')?.textContent?.trim()).toBe('2 of 2');
    expect(next().disabled).toBeTrue();

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft' }));
    fixture.detectChanges();
    expect(el.querySelector('.viewer-title')?.textContent).toBe('Acme Shop');
  });

  it('loads the next gallery page when stepping past the last screenshot on this one', () => {
    const firstPage = Array.from({ length: 24 }, (_, i) =>
      shot(`s${i}`, `Page ${i}`, `https://shop.acme.com/${i}`),
    );
    expectList().flush(page(firstPage, 25));
    for (let i = 0; i < 24; i++) {
      http.expectOne(`${API}/findings/s${i}/screenshot/`).flush(new Blob(['a']));
    }
    fixture.detectChanges();

    (el.querySelectorAll('.tile')[23] as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('.viewer-position')?.textContent?.trim()).toBe('24 of 25');

    (el.querySelector('.nav.next') as HTMLButtonElement).click();
    const request = expectList();
    expect(request.request.params.get('page')).toBe('2');
    request.flush(page([shot('s24', 'Last page', 'https://shop.acme.com/last')], 25));
    http.expectOne(`${API}/findings/s24/screenshot/`).flush(new Blob(['z']));
    fixture.detectChanges();

    expect(el.querySelector('.viewer-title')?.textContent).toBe('Last page');
    expect(el.querySelector('.viewer-position')?.textContent?.trim()).toBe('25 of 25');
    expect((el.querySelector('.nav.next') as HTMLButtonElement).disabled).toBeTrue();

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft' }));
    const back = expectList();
    expect(back.request.params.get('page')).toBe('1');
    back.flush(page(firstPage, 25));
    for (let i = 0; i < 24; i++) {
      http.expectOne(`${API}/findings/s${i}/screenshot/`).flush(new Blob(['a']));
    }
    fixture.detectChanges();
    expect(el.querySelector('.viewer-title')?.textContent).toBe('Page 23');
  });

  it('shows a placeholder when an image file is gone', () => {
    expectList().flush(page([shot('s1', '', 'https://shop.acme.com/')]));
    http
      .expectOne(`${API}/findings/s1/screenshot/`)
      .flush(new Blob([]), { status: 404, statusText: 'Not Found' });
    fixture.detectChanges();
    expect(el.querySelector('.tile img')).toBeNull();
    // No page title: the host stands in for it.
    expect(el.querySelector('.tile-title')?.textContent).toBe('shop.acme.com');
  });

  it('searches by title or host and points to the scanner when there is nothing', async () => {
    expectList().flush(page([]));
    fixture.detectChanges();
    expect(el.querySelector('.empty')?.textContent).toContain('Run the Screenshot scanner');

    fixture.componentInstance.onSearchChange('login');
    await new Promise((resolve) => setTimeout(resolve, 350));
    const request = expectList();
    expect(request.request.params.get('search')).toBe('login');
    request.flush(page([]));
    fixture.detectChanges();
    expect(el.querySelector('.empty')?.textContent).toContain('No screenshots match');
  });
});
