import { Component, computed, inject, input } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

// The app's icon set: 24px grid, 2px rounded strokes, drawn to match.
// Add an icon by adding its inner SVG markup here.
const ICONS = {
  // navigation
  dashboard:
    '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  assets:
    '<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/>',
  findings: '<path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v4M12 17h.01"/>',
  scanners: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 12h.01"/>',
  history: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/>',
  bell: '<path d="M6 8a6 6 0 1 1 12 0c0 5 2 6 2 6H4s2-1 2-6Z"/><path d="M10 20a2 2 0 0 0 4 0"/>',
  users:
    '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.5a3.5 3.5 0 0 1 0 7M18 14.5a6.5 6.5 0 0 1 3.5 5.5"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  shield: '<path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/>',

  // scanners
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9S14.5 18.4 12 21c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3Z"/>',
  plug: '<path d="M9 2v5M15 2v5M6 7h12v4a6 6 0 0 1-12 0V7ZM12 17v5"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14.500v2.5"/>',
  'shield-check': '<path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
  network:
    '<rect x="9" y="2.5" width="6" height="5" rx="1"/><rect x="2.5" y="16.5" width="6" height="5" rx="1"/><rect x="15.5" y="16.5" width="6" height="5" rx="1"/><path d="M12 7.500V12M5.5 16.500V12h13v4.5"/>',
  bug: '<rect x="8" y="7" width="8" height="13" rx="4"/><path d="M9 4l1.5 3M15 4l-1.5 3M3 13h5M16 13h5M4 8l4 2M20 8l-4 2M4 19l4-2M20 19l-4-2"/>',
  camera:
    '<path d="M3 8.500A1.5 1.5 0 0 1 4.5 7H7l1.5-2.500h7L17 7h2.500A1.5 1.5 0 0 1 21 8.500V18a1.5 1.5 0 0 1-1.5 1.500h-15A1.5 1.5 0 0 1 3 18V8.500Z"/><circle cx="12" cy="13" r="3.5"/>',

  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3.5 7 8.5 6 8.5-6"/>',
  unlink:
    '<path d="M9.5 14.5 7 17a3.5 3.5 0 0 1-5-5l2.5-2.5M14.5 9.5 17 7a3.5 3.5 0 0 1 5 5l-2.5 2.5M8 3v2.5M3 8h2.5M16 21v-2.5M21 16h-2.5"/>',
  key: '<circle cx="8" cy="15" r="4.5"/><path d="m11.5 11.5 8.5-8.5M17 6l3 3M14 9l2 2"/>',
  package: '<path d="M12 2.5 3.5 7v10l8.5 4.5 8.5-4.5V7L12 2.5Z"/><path d="M3.5 7 12 11.5 20.5 7M12 11.5v10"/>',
  file: '<path d="M6 2.5h8l4.5 4.5v14.5H6V2.5Z"/><path d="M14 2.5V7h4.5M9 12h6M9 16h6"/>',

  'file-alert': '<path d="M6 2.5h8l4.5 4.5v14.5H6V2.5Z"/><path d="M14 2.5V7h4.5M12 11v4M12 18h.01"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 13 9 5 9-5M3 17.5l9 5 9-5"/>',
  share: '<circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="m8.2 10.9 7.6-3.800M8.2 13.100l7.6 3.8"/>',
  cookie: '<path d="M12 3a9 9 0 1 0 9 9 4 4 0 0 1-4-4 4 4 0 0 1-5-5Z"/><path d="M9 10h.01M14 14h.01M9.5 15.500h.01"/>',
  'lock-open': '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 7.5-2M12 14.500v2.5"/>',

  map: '<path d="M9 4 3 6.5v13.5L9 17.5l6 2.5 6-2.5V4l-6 2.5L9 4Z"/><path d="M9 4v13.5M15 6.5V20"/>',
  activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  clipboard: '<rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 4V3h6v1M9 11h6M9 15h4"/><path d="m9 8 1.5 1.5L13 7"/>',

  // actions and states
  play: '<path d="M7 4.500v15l12-7.500L7 4.500Z"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  download: '<path d="M12 3v12M7 10.500l5 5 5-5M4 20h16"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
  check: '<path d="m5 12.5 4.5 4.500L19 7.5"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h8"/>',
  chevron: '<path d="m6 9 6 6 6-6"/>',
  'chevron-left': '<path d="m15 6-6 6 6 6"/>',
  'chevron-right': '<path d="m9 6 6 6-6 6"/>',
  'arrow-left': '<path d="M19 12H5M11 18l-6-6 6-6"/>',
  wrench:
    '<path d="M14.700 6.300a4 4 0 0 0-5.400 5.400L3 18v3h3l6.300-6.300a4 4 0 0 0 5.400-5.400l-2.600 2.600-2.400-.6-.6-2.400 2.600-2.600Z"/>',
  inbox: '<path d="M3 13h5l1.500 3h5L16 13h5"/><path d="M5.500 5h13L21 13v6H3v-6l2.500-8Z"/>',
  message: '<path d="M4 5h16v11H9l-5 4V5Z"/>',
  repeat: '<path d="M17 2l3 3-3 3"/><path d="M4 11V9a4 4 0 0 1 4-4h12M7 22l-3-3 3-3"/><path d="M20 13v2a4 4 0 0 1-4 4H4"/>',
  gem: '<path d="M6 3h12l3 6-9 12L3 9l3-6Z"/><path d="M3 9h18M12 21 8 9l4-6 4 6-4 12"/>',
  tag: '<path d="M3 12V4a1 1 0 0 1 1-1h8l9 9-9 9-9-9Z"/><path d="M7.500 7.500h.01"/>',
  upload: '<path d="M12 15V3M7 8l5-5 5 5M4 20h16"/>',
  calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',
  smartphone: '<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="1.500"/><rect x="3" y="13" width="18" height="7" rx="1.500"/><path d="M7 7.500h.01M7 16.500h.01"/>',
  'eye-off': '<path d="M3 3l18 18M10.600 6.100A9.800 9.800 0 0 1 12 6c5 0 9 6 9 6a17 17 0 0 1-2.300 2.900M6.600 6.600C4.300 8.100 3 12 3 12s4 6 9 6a8.900 8.900 0 0 0 4.400-1.100M9.900 9.900a3 3 0 0 0 4.200 4.200"/>',

  // theme
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.900l1.4 1.400M17.7 17.700l1.4 1.400M2 12h2M20 12h2M4.9 19.100l1.4-1.400M17.7 6.300l1.4-1.4"/>',
  moon: '<path d="M20.5 14.500A8.5 8.5 0 0 1 9.5 3.500a8.5 8.5 0 1 0 11 11Z"/>',
  monitor: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
} as const;

export type IconName = keyof typeof ICONS;

@Component({
  selector: 'app-icon',
  template: `
    <svg
      [attr.width]="size()"
      [attr.height]="size()"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      [innerHTML]="markup()"
    ></svg>
  `,
  styles: ':host { display: inline-flex; flex-shrink: 0; }',
})
export class Icon {
  private readonly sanitizer = inject(DomSanitizer);

  readonly name = input.required<IconName>();
  readonly size = input(18);

  // Safe to trust: the markup only ever comes from the constant above,
  // never from data. (Angular's default sanitizer strips SVG shapes.)
  readonly markup = computed(() => this.sanitizer.bypassSecurityTrustHtml(ICONS[this.name()]));
}

const SCANNER_ICONS: Record<string, IconName> = {
  subfinder: 'globe',
  nmap: 'plug',
  httpx: 'shield-check',
  ssl_expiry: 'lock',
  dns_monitor: 'network',
  nuclei: 'bug',
  screenshot: 'camera',
  email_security: 'mail',
  subdomain_takeover: 'unlink',
  tls_config: 'key',
  outdated_software: 'package',
  security_txt: 'file',
  exposed_files: 'file-alert',
  dns_zone_transfer: 'layers',
  cors: 'share',
  cookie_security: 'cookie',
  https_enforcement: 'lock-open',
  lookalike_domains: 'eye-off',
};

/** The icon for a scanner plugin; new plugins get the generic one. */
export function scannerIcon(scannerName: string): IconName {
  return SCANNER_ICONS[scannerName] ?? 'scanners';
}
