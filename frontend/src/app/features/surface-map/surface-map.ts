import { PluralPipe } from '../../shared/pipes/plural';
import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { Asset, Member, SurfaceMap, SurfaceNode } from '../../core/models/models';
import { AssetService } from '../../core/services/asset-service';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';
import { AssetPeek } from '../../shared/components/asset-peek/asset-peek';

const SIZE = 640;
const CENTER = SIZE / 2;

type Tone = 'bad' | 'serious' | 'warn' | 'minor' | 'good';
type Arrangement = 'risk' | 'hosting';

interface PlacedNode extends SurfaceNode {
  x: number;
  y: number;
  r: number;
  tone: Tone;
}

interface Sector {
  provider: string;
  count: number;
  // Where its label sits.
  x: number;
  y: number;
  anchor: 'start' | 'middle' | 'end';
  // The boundary line before it.
  x1: number;
  y1: number;
}

const LEGEND: { tone: Tone; label: string }[] = [
  { tone: 'bad', label: 'Grade D or F' },
  { tone: 'serious', label: 'Grade C' },
  { tone: 'warn', label: 'Grade B' },
  { tone: 'minor', label: 'Grade A, minor issues' },
  { tone: 'good', label: 'No open issues' },
];

/**
 * The organization as an outsider sees it: the domain in the middle,
 * its hosts around it. Hosts with open issues sit closest, sized by how
 * many issues they have and coloured by grade; clean hosts form the
 * outer ring. Arranged by hosting, each provider gets its own slice.
 * Clicking a host opens a summary of it beside the map.
 */
@Component({
  selector: 'app-surface-map',
  imports: [PluralPipe, DecimalPipe, AssetPeek],
  templateUrl: './surface-map.html',
  styleUrl: './surface-map.scss',
})
export class SurfaceMapPage {
  private readonly orgService = inject(OrganizationService);
  private readonly assetService = inject(AssetService);
  protected readonly orgContext = inject(OrganizationContextService);

  protected readonly size = SIZE;
  protected readonly center = CENTER;
  protected readonly legend = LEGEND;

  readonly map = signal<SurfaceMap | null>(null);
  readonly isLoading = signal(true);
  readonly hovered = signal<PlacedNode | null>(null);
  readonly arrangement = signal<Arrangement>('risk');
  // Grades switched off in the legend.
  readonly hiddenTones = signal<ReadonlySet<Tone>>(new Set());
  readonly peeking = signal<Asset | null>(null);
  readonly members = signal<Member[]>([]);

  private readonly placed = computed(() => {
    const map = this.map();
    if (!map) return { nodes: [] as PlacedNode[], sectors: [] as Sector[] };
    return this.arrangement() === 'hosting' ? this.byHosting(map.nodes) : { nodes: this.byRisk(map.nodes), sectors: [] };
  });
  readonly nodes = computed(() => this.placed().nodes);
  readonly sectors = computed(() => this.placed().sectors);
  readonly toneCounts = computed(() => {
    const counts: Partial<Record<Tone, number>> = {};
    for (const node of this.nodes()) counts[node.tone] = (counts[node.tone] ?? 0) + 1;
    return counts;
  });

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      untracked(() => {
        if (!org) return;
        this.isLoading.set(true);
        this.peeking.set(null);
        this.orgService.surfaceMap(org.id).subscribe({
          next: (map) => {
            this.map.set(map);
            this.isLoading.set(false);
          },
          error: () => this.isLoading.set(false),
        });
        this.orgService.members(org.id).subscribe({ next: (m) => this.members.set(m), error: () => this.members.set([]) });
      });
    });
  }

  isHidden(node: PlacedNode): boolean {
    return this.hiddenTones().has(node.tone);
  }

  toggleTone(tone: Tone): void {
    const next = new Set(this.hiddenTones());
    if (next.has(tone)) next.delete(tone);
    else next.add(tone);
    this.hiddenTones.set(next);
  }

  open(node: SurfaceNode): void {
    this.assetService.get(node.id).subscribe({ next: (asset) => this.peeking.set(asset) });
  }

  private byRisk(all: SurfaceNode[]): PlacedNode[] {
    const risky = all.filter((n) => !n.clean);
    const clean = all.filter((n) => n.clean);
    // Risky hosts on one or two inner rings, clean ones on the outside.
    const rings: { nodes: SurfaceNode[]; radius: number }[] = [];
    rings.push({ nodes: risky.slice(0, 14), radius: 130 });
    if (risky.length > 14) rings.push({ nodes: risky.slice(14), radius: 205 });
    rings.push({ nodes: clean, radius: risky.length > 14 ? 278 : 250 });

    const maxFindings = Math.max(1, ...risky.map((n) => n.open_findings));
    return rings.flatMap((ring, ringIndex) =>
      ring.nodes.map((node, i) => {
        const angle = (i / Math.max(1, ring.nodes.length)) * Math.PI * 2 - Math.PI / 2 + ringIndex * 0.35;
        return this.place(node, angle, ring.radius, maxFindings);
      }),
    );
  }

  /** One slice per provider, sized by its share of hosts; riskier hosts nearer the middle. */
  private byHosting(all: SurfaceNode[]): { nodes: PlacedNode[]; sectors: Sector[] } {
    const groups = new Map<string, SurfaceNode[]>();
    for (const node of all) {
      const key = node.provider || 'Not identified';
      groups.set(key, [...(groups.get(key) ?? []), node]);
    }
    const ordered = [...groups.entries()].sort((a, b) => b[1].length - a[1].length);
    const maxFindings = Math.max(1, ...all.map((n) => n.open_findings));
    const nodes: PlacedNode[] = [];
    const sectors: Sector[] = [];
    let start = -Math.PI / 2;
    for (const [provider, members] of ordered) {
      const span = (members.length / all.length) * Math.PI * 2;
      const sorted = [...members].sort((a, b) => b.open_findings - a.open_findings);
      sorted.forEach((node, i) => {
        // Spread along the slice, alternating between two radii so neighbours don't touch.
        const angle = start + span * ((i + 0.5) / sorted.length);
        const radius = node.clean ? 250 - (i % 2) * 28 : 120 + (i % 3) * 42;
        nodes.push(this.place(node, angle, radius, maxFindings));
      });
      const middle = start + span / 2;
      const labelX = CENTER + Math.cos(middle) * 300;
      sectors.push({
        provider,
        count: members.length,
        x: labelX,
        y: CENTER + Math.sin(middle) * 300,
        anchor: Math.abs(labelX - CENTER) < 40 ? 'middle' : labelX > CENTER ? 'start' : 'end',
        x1: CENTER + Math.cos(start) * 290,
        y1: CENTER + Math.sin(start) * 290,
      });
      start += span;
    }
    return { nodes, sectors: sectors.length > 1 ? sectors : sectors.map((s) => ({ ...s, x1: CENTER, y1: CENTER })) };
  }

  private place(node: SurfaceNode, angle: number, radius: number, maxFindings: number): PlacedNode {
    return {
      ...node,
      x: CENTER + Math.cos(angle) * radius,
      y: CENTER + Math.sin(angle) * radius,
      r: node.clean ? 5 : 8 + 12 * Math.sqrt(node.open_findings / maxFindings),
      tone: this.tone(node),
    };
  }

  private tone(node: SurfaceNode): Tone {
    if (node.clean) return 'good';
    if (['D', 'F'].includes(node.risk_grade)) return 'bad';
    if (node.risk_grade === 'C') return 'serious';
    if (node.risk_grade === 'B') return 'warn';
    return 'minor';
  }
}
