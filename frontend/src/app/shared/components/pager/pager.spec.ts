import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Pager } from './pager';

describe('Pager', () => {
  let fixture: ComponentFixture<Pager>;
  let emitted: number[];

  function render(page: number, count: number): HTMLElement {
    fixture = TestBed.createComponent(Pager);
    fixture.componentRef.setInput('page', page);
    fixture.componentRef.setInput('count', count);
    emitted = [];
    fixture.componentInstance.pageChange.subscribe((p) => emitted.push(p));
    fixture.detectChanges();
    return fixture.nativeElement;
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [Pager] }).compileComponents();
  });

  it('renders nothing when everything fits on one page', () => {
    expect(render(1, 25).querySelector('.pager')).toBeNull();
  });

  it('shows the position and disables Previous on the first page', () => {
    const el = render(1, 60);
    expect(el.querySelector('.position')?.textContent).toContain('Page 1 of 3');
    const [previous, next] = Array.from(el.querySelectorAll('button'));
    expect(previous.disabled).toBeTrue();
    expect(next.disabled).toBeFalse();
  });

  it('emits the neighbouring page and disables Next on the last page', () => {
    const el = render(3, 60);
    const [previous, next] = Array.from(el.querySelectorAll('button'));
    expect(next.disabled).toBeTrue();
    previous.click();
    expect(emitted).toEqual([2]);
  });
});
