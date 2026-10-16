import { ComponentFixture, TestBed } from '@angular/core/testing';
import { TrendPoint } from '../../../core/models/models';

import { TrendChart } from './trend-chart';

function point(date: string, score: number | null): TrendPoint {
  return { date, score, grade: 'B', open_issues: 10, critical_high: 2, asset_count: 20 };
}

describe('TrendChart', () => {
  let fixture: ComponentFixture<TrendChart>;

  function render(points: TrendPoint[]): HTMLElement {
    fixture = TestBed.createComponent(TrendChart);
    fixture.componentRef.setInput('points', points);
    fixture.detectChanges();
    return fixture.nativeElement;
  }

  it('draws a line through the scored days and labels the dates', () => {
    const el = render([point('2026-09-01', 50), point('2026-09-02', null), point('2026-09-03', 80)]);
    const d = el.querySelector('path.line')?.getAttribute('d') ?? '';
    expect(d.split('L').length).toBe(2); // the unscored day is skipped
    expect(Array.from(el.querySelectorAll('.tick')).map((t) => t.textContent?.trim())).toEqual(['Sep 1', 'Sep 3']);
    expect(el.querySelector('svg')?.getAttribute('aria-label')).toBe('Risk score from 50 to 80 out of 100');
  });

  it('explains itself instead of drawing one lonely point', () => {
    const el = render([point('2026-09-01', 50)]);
    expect(el.querySelector('svg')).toBeNull();
    expect(el.textContent).toContain('fills in as the numbers are recorded');
  });

  it('shows the day under the pointer', () => {
    const el = render([point('2026-09-01', 50), point('2026-09-03', 80)]);
    fixture.componentInstance.hoverIndex.set(1);
    fixture.detectChanges();
    expect(el.querySelector('.tooltip')?.textContent).toContain('Score 80');
  });
});
