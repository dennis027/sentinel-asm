import { DestroyRef, NgZone, inject } from '@angular/core';

/**
 * Runs `tick` every `ms` while the component lives, skipping ticks while the
 * browser tab is hidden (nobody is looking, so no requests). The timer runs
 * outside Angular's zone so pages and tests still settle; each tick re-enters
 * it, so whatever the tick changes is shown.
 *
 * Call from a constructor or field initializer (it uses inject()).
 */
export function every(ms: number, tick: () => void): () => void {
  const zone = inject(NgZone);
  let handle: ReturnType<typeof setInterval> | undefined;
  zone.runOutsideAngular(() => {
    handle = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      zone.run(tick);
    }, ms);
  });
  const stop = () => clearInterval(handle);
  inject(DestroyRef).onDestroy(stop);
  return stop;
}
