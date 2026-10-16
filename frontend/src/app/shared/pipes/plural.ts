import { Pipe, PipeTransform } from '@angular/core';

/** "1 finding", "48 findings": `{{ count | plural: 'finding' }}`. */
@Pipe({ name: 'plural' })
export class PluralPipe implements PipeTransform {
  transform(count: number | null | undefined, singular: string, plural = singular + 's'): string {
    const n = count ?? 0;
    return `${n.toLocaleString('en-US')} ${n === 1 ? singular : plural}`;
  }
}
