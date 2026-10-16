import { ComponentFixture, TestBed } from '@angular/core/testing';
import { TrendPoint } from '../../../core/models/models';

import { GradeCalendar } from './grade-calendar';

function daysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function point(date: string, grade: string, score: number): TrendPoint {
  return { date, grade, score, open_issues: 1, critical_high: 0, asset_count: 1 };
}

describe('GradeCalendar', () => {
  let fixture: ComponentFixture<GradeCalendar>;
  let el: HTMLElement;

  beforeEach(() => {
    fixture = TestBed.createComponent(GradeCalendar);
    el = fixture.nativeElement;
  });

  it('draws a square per day in weeks, coloured by that day’s grade', () => {
    fixture.componentRef.setInput('points', [point(daysAgo(0), 'C', 69), point(daysAgo(1), 'A+', 97), point(daysAgo(200), 'F', 5)]);
    fixture.detectChanges();
    expect(el.querySelectorAll('.calendar .day').length).toBe(91);
    expect(el.querySelectorAll('.week').length).toBe(13);
    const days = el.querySelectorAll('.calendar .day');
    expect(days[90].classList).toContain('g-C');
    expect(days[89].classList).toContain('g-Aplus');
    expect(days[90].getAttribute('title')).toContain('grade C (69)');
    // Outside the window, and days without a record, stay blank.
    expect(el.querySelectorAll('.calendar .g-F').length).toBe(0);
    expect(days[0].classList).toContain('none');
  });
});
