import { Component, computed, input } from '@angular/core';
import { DatePipe } from '@angular/common';
import { TrendPoint } from '../../../core/models/models';

interface Day {
  date: string;
  grade: string | null;
  score: number | null;
}

/**
 * One square per day, coloured by that day's grade, a week per column
 * -- like a contribution graph. Shows at a glance how long the
 * organization has spent at each grade, and when it changed.
 */
@Component({
  selector: 'app-grade-calendar',
  imports: [DatePipe],
  templateUrl: './grade-calendar.html',
  styleUrl: './grade-calendar.scss',
})
export class GradeCalendar {
  readonly points = input.required<TrendPoint[]>();
  readonly days = input(91);

  protected readonly legend = ['F', 'D', 'C', 'B', 'A', 'A+'];

  /** Weeks of seven days, oldest first, ending today; days without a record are blank. */
  readonly weeks = computed<Day[][]>(() => {
    const byDate = new Map(this.points().map((p) => [p.date, p]));
    const today = new Date();
    const days: Day[] = [];
    for (let offset = this.days() - 1; offset >= 0; offset--) {
      const day = new Date(today.getFullYear(), today.getMonth(), today.getDate() - offset);
      const key = `${day.getFullYear()}-${String(day.getMonth() + 1).padStart(2, '0')}-${String(day.getDate()).padStart(2, '0')}`;
      const point = byDate.get(key);
      days.push({ date: key, grade: point?.grade || null, score: point?.score ?? null });
    }
    const weeks: Day[][] = [];
    for (let i = 0; i < days.length; i += 7) weeks.push(days.slice(i, i + 7));
    return weeks;
  });

  gradeClass(grade: string | null): string {
    return grade ? 'g-' + grade.replace('+', 'plus') : 'none';
  }
}
