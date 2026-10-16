import { Component, computed, input, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { TrendPoint } from '../../../core/models/models';

const WIDTH = 640;
const HEIGHT = 200;
const PAD = { top: 12, right: 12, bottom: 26, left: 34 };

// Score thresholds where the letter grade changes, drawn as faint guides.
const GRADE_LINES = [
  { score: 85, label: 'A' },
  { score: 70, label: 'B' },
  { score: 50, label: 'C' },
];

/**
 * The organization's risk score over time: one line, 0 to 100, with
 * the grade boundaries as faint guides. Hovering shows the day's
 * numbers. A single series, so the panel title names it -- no legend.
 */
@Component({
  selector: 'app-trend-chart',
  imports: [DatePipe],
  templateUrl: './trend-chart.html',
  styleUrl: './trend-chart.scss',
})
export class TrendChart {
  readonly points = input.required<TrendPoint[]>();

  protected readonly width = WIDTH;
  protected readonly height = HEIGHT;
  protected readonly pad = PAD;
  protected readonly gradeLines = GRADE_LINES;

  readonly hoverIndex = signal<number | null>(null);

  readonly scored = computed(() => this.points().filter((point) => point.score !== null));

  protected x(index: number): number {
    const count = this.scored().length;
    const span = WIDTH - PAD.left - PAD.right;
    return PAD.left + (count <= 1 ? span : (index / (count - 1)) * span);
  }

  protected y(score: number): number {
    return PAD.top + (1 - score / 100) * (HEIGHT - PAD.top - PAD.bottom);
  }

  readonly linePath = computed(() =>
    this.scored()
      .map((point, i) => `${i === 0 ? 'M' : 'L'}${this.x(i).toFixed(1)},${this.y(point.score ?? 0).toFixed(1)}`)
      .join(' '),
  );

  readonly areaPath = computed(() => {
    const points = this.scored();
    if (points.length < 2) return '';
    const bottom = this.y(0);
    return `${this.linePath()} L${this.x(points.length - 1).toFixed(1)},${bottom} L${this.x(0).toFixed(1)},${bottom} Z`;
  });

  // Three date labels: first, middle, last.
  readonly ticks = computed(() => {
    const points = this.scored();
    if (points.length < 2) return [];
    const indexes = [...new Set([0, Math.floor((points.length - 1) / 2), points.length - 1])];
    return indexes.map((i) => ({ x: this.x(i), date: points[i].date, anchor: i === 0 ? 'start' : i === points.length - 1 ? 'end' : 'middle' }));
  });

  readonly hovered = computed(() => {
    const index = this.hoverIndex();
    return index === null ? null : { point: this.scored()[index], x: this.x(index), y: this.y(this.scored()[index].score ?? 0) };
  });

  // Keeps the tooltip inside the chart near the right-hand edge.
  readonly tooltipLeft = computed(() => {
    const hovered = this.hovered();
    if (!hovered) return 0;
    return Math.min(Math.max((hovered.x / WIDTH) * 100, 12), 82);
  });

  onMove(event: MouseEvent): void {
    const points = this.scored();
    if (!points.length) return;
    const svg = event.currentTarget as SVGElement;
    const box = svg.getBoundingClientRect();
    const xInChart = ((event.clientX - box.left) / box.width) * WIDTH;
    const fraction = (xInChart - PAD.left) / (WIDTH - PAD.left - PAD.right);
    this.hoverIndex.set(Math.min(points.length - 1, Math.max(0, Math.round(fraction * (points.length - 1)))));
  }
}
