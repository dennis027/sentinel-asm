import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ConfirmService } from '../../../core/services/confirm.service';

import { ConfirmDialog } from './confirm-dialog';

describe('ConfirmDialog', () => {
  let fixture: ComponentFixture<ConfirmDialog>;
  let service: ConfirmService;
  let el: HTMLElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [ConfirmDialog] }).compileComponents();
    fixture = TestBed.createComponent(ConfirmDialog);
    service = TestBed.inject(ConfirmService);
    el = fixture.nativeElement;
    fixture.detectChanges();
  });

  function buttons(): HTMLButtonElement[] {
    return Array.from(el.querySelectorAll('.actions button'));
  }

  it('is not shown until something asks', () => {
    expect(el.querySelector('.dialog')).toBeNull();
  });

  it('shows the question and resolves true when confirmed', async () => {
    const answer = service.ask({
      title: 'Run Port scan on all 41,698 assets?',
      message: ['One scan per asset.', 'This can take a long time.'],
      confirmLabel: 'Run scan',
    });
    fixture.detectChanges();

    expect(el.querySelector('h2')?.textContent).toBe('Run Port scan on all 41,698 assets?');
    expect(Array.from(el.querySelectorAll('.message p')).map((p) => p.textContent)).toEqual([
      'One scan per asset.',
      'This can take a long time.',
    ]);
    expect(buttons().map((b) => b.textContent?.trim())).toEqual(['Cancel', 'Run scan']);

    buttons()[1].click();
    expect(await answer).toBeTrue();
    fixture.detectChanges();
    expect(el.querySelector('.dialog')).toBeNull();
  });

  it('resolves false on Cancel, on Escape and on a click outside', async () => {
    const ask = () => {
      const answer = service.ask({ title: 'Sure?', message: 'Really?', confirmLabel: 'Yes' });
      fixture.detectChanges();
      return answer;
    };

    let answer = ask();
    buttons()[0].click();
    expect(await answer).toBeFalse();

    answer = ask();
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(await answer).toBeFalse();

    answer = ask();
    (el.querySelector('.backdrop') as HTMLElement).click();
    expect(await answer).toBeFalse();
  });

  it('a click inside the dialog does not cancel it', () => {
    service.ask({ title: 'Sure?', message: 'Really?', confirmLabel: 'Yes' });
    fixture.detectChanges();
    (el.querySelector('.dialog') as HTMLElement).click();
    fixture.detectChanges();
    expect(el.querySelector('.dialog')).not.toBeNull();
  });

  it('marks destructive questions and starts focus on Cancel for them', () => {
    service.ask({ title: 'Remove vic?', message: 'They lose access.', confirmLabel: 'Remove', danger: true });
    fixture.detectChanges();
    expect(buttons()[1].classList).toContain('danger');
    expect(el.querySelector('.mark')?.classList).toContain('danger');
    expect(document.activeElement).toBe(buttons()[0]);
  });

  it('starts focus on the confirm button for ordinary questions', () => {
    service.ask({ title: 'Run it?', message: 'Go.', confirmLabel: 'Run scan' });
    fixture.detectChanges();
    expect(document.activeElement).toBe(buttons()[1]);
  });
});
