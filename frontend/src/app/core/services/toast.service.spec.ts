import { TestBed, fakeAsync, tick } from '@angular/core/testing';

import { ToastService } from './toast.service';

describe('ToastService', () => {
  let service: ToastService;

  beforeEach(() => {
    service = TestBed.inject(ToastService);
  });

  it('shows messages and lets them be dismissed', () => {
    service.success('Saved');
    service.error('Failed');
    expect(service.toasts().map((t) => [t.kind, t.message])).toEqual([
      ['success', 'Saved'],
      ['error', 'Failed'],
    ]);

    service.dismiss(service.toasts()[0].id);
    expect(service.toasts().map((t) => t.message)).toEqual(['Failed']);
  });

  it('removes a message by itself after a few seconds', fakeAsync(() => {
    service.success('Saved');
    tick(4000);
    expect(service.toasts().length).toBe(1);
    tick(1500);
    expect(service.toasts().length).toBe(0);
  }));
});
