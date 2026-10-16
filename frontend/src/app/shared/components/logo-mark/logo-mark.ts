import { Component, input } from '@angular/core';

let nextId = 0;

/**
 * The Densight mark: a D whose bowl holds a radar eye -- the sweep,
 * the pupil, and one exposure found (amber). Drawn inline so it is
 * crisp at any size and needs no extra request. Same artwork as
 * public/brand/mark.svg.
 */
@Component({
  selector: 'app-logo-mark',
  template: `
    <svg [attr.width]="size()" [attr.height]="size()" viewBox="0 0 64 64" aria-hidden="true">
      <defs>
        <linearGradient [attr.id]="gradientId" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#6366F1" />
          <stop offset="1" stop-color="#4338CA" />
        </linearGradient>
      </defs>
      <rect width="64" height="64" rx="15" [attr.fill]="'url(#' + gradientId + ')'" />
      <path
        d="M17.5 14.5H30C41.1 14.5 49 22.3 49 32S41.1 49.5 30 49.5H17.5z"
        fill="none"
        stroke="#fff"
        stroke-width="5"
        stroke-linejoin="round"
      />
      <path d="M30.5 32L37.2 25.3A9.5 9.5 0 0 1 37.2 38.7Z" fill="#fff" opacity="0.25" />
      <path
        d="M37.2 25.3A9.5 9.5 0 0 1 37.2 38.7"
        fill="none"
        stroke="#fff"
        stroke-width="2.2"
        stroke-linecap="round"
        opacity="0.8"
      />
      <circle cx="30.5" cy="32" r="3.8" fill="#fff" />
      <circle cx="37.2" cy="25.3" r="2.7" fill="#FBBF24" />
    </svg>
  `,
  styles: [':host { display: block; flex: none; line-height: 0; }'],
})
export class LogoMark {
  readonly size = input(32);
  // Unique per instance: several marks on one page must not share a gradient id.
  protected readonly gradientId = `densight-mark-${nextId++}`;
}
