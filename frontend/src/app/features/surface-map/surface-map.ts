import { PluralPipe } from '../../shared/pipes/plural';
import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { Router } from '@angular/router';
import { SurfaceMap, SurfaceNode } from '../../core/models/models';
import { OrganizationContextService } from '../../core/services/organization-context-service';
import { OrganizationService } from '../../core/services/organization-service';

const SIZE = 640;
const CENTER = SIZE / 2;

interface PlacedNode extends SurfaceNode {
  x: number;
  y: number;
  r: number;
  tone: 'bad' | 'serious' | 'warn' | 'good';
}

/**
 * The organization as an outsider sees it: the domain in the middle,
 * its hosts around it. Hosts with open issues sit closest, sized by how
 * many issues they have and coloured by grade; clean hosts form the
 * outer ring. Clicking a host opens its findings.
 */
@Component({
  selector: 'app-surface-map',
  imports: [PluralPipe, DecimalPipe],
  templateUrl: './surface-map.html',
  styleUrl: './surface-map.scss',
})
export class SurfaceMapPage {
  private readonly orgService = inject(OrganizationService);
  private readonly router = inject(Router);
  protected readonly orgContext = inject(OrganizationContextService);

  protected readonly size = SIZE;
  protected readonly center = CENTER;

  readonly map = signal<SurfaceMap | null>(null);
  readonly isLoading = signal(true);
  readonly hovered = signal<PlacedNode | null>(null);

  readonly legend = [
    { tone: 'bad', label: 'Grade D or F' },
    { tone: 'serious', label: 'Grade C' },
    { tone: 'warn', label: 'Grade B or A' },
    { tone: 'good', label: 'No open issues' },
  ];

  readonly nodes = computed<PlacedNode[]>(() => {
    const map = this.map();
    if (!map) return [];
    const risky = map.nodes.filter((n) => !n.clean);
    const clean = map.nodes.filter((n) => n.clean);
    // Risky hosts on one or two inner rings, clean ones on the outside.
    const rings: { nodes: SurfaceNode[]; radius: number }[] = [];
    rings.push({ nodes: risky.slice(0, 14), radius: 130 });
    if (risky.length > 14) rings.push({ nodes: risky.slice(14), radius: 205 });
    rings.push({ nodes: clean, radius: risky.length > 14 ? 278 : 250 });

    const maxFindings = Math.max(1, ...risky.map((n) => n.open_findings));
    return rings.flatMap((ring, ringIndex) =>
      ring.nodes.map((node, i) => {
        const angle = (i / Math.max(1, ring.nodes.length)) * Math.PI * 2 - Math.PI / 2 + ringIndex * 0.35;
        const r = node.clean ? 5 : 8 + 12 * Math.sqrt(node.open_findings / maxFindings);
        return {
          ...node,
          x: CENTER + Math.cos(angle) * ring.radius,
          y: CENTER + Math.sin(angle) * ring.radius,
          r,
          tone: this.tone(node),
        };
      }),
    );
  });

  constructor() {
    effect(() => {
      const org = this.orgContext.selectedOrganization();
      untracked(() => {
        if (!org) return;
        this.isLoading.set(true);
        this.orgService.surfaceMap(org.id).subscribe({
          next: (map) => {
            this.map.set(map);
            this.isLoading.set(false);
          },
          error: () => this.isLoading.set(false),
        });
      });
    });
  }

  open(node: SurfaceNode): void {
    this.router.navigate(['/findings'], { queryParams: { asset: node.id, assetName: node.value } });
  }

  private tone(node: SurfaceNode): PlacedNode['tone'] {
    if (node.clean) return 'good';
    if (['D', 'F'].includes(node.risk_grade)) return 'bad';
    if (node.risk_grade === 'C') return 'serious';
    return 'warn';
  }
}
