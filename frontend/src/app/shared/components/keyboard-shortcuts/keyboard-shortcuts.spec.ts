import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { SearchService } from '../../../core/services/search.service';
import { provideAppTesting } from '../../../testing/test-helpers';

import { KeyboardShortcuts } from './keyboard-shortcuts';

function press(key: string, target: EventTarget = document.body): void {
  target.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true }));
}

describe('KeyboardShortcuts', () => {
  let fixture: ComponentFixture<KeyboardShortcuts>;
  let navigate: jasmine.Spy;

  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [KeyboardShortcuts], providers: [provideAppTesting()] }).compileComponents();
    navigate = spyOn(TestBed.inject(Router), 'navigateByUrl').and.resolveTo(true);
    fixture = TestBed.createComponent(KeyboardShortcuts);
    fixture.detectChanges();
  });

  it('jumps to a page with g and a letter', () => {
    press('g');
    press('p');
    expect(navigate).toHaveBeenCalledWith('/fix-plan');
    // A letter on its own does nothing.
    navigate.calls.reset();
    press('f');
    expect(navigate).not.toHaveBeenCalled();
  });

  it('shows the list with ? and opens search with /', () => {
    press('?');
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.sheet')?.textContent).toContain('Fix plan');
    press('Escape');
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.sheet')).toBeNull();
    press('/');
    expect(TestBed.inject(SearchService).isOpen()).toBeTrue();
  });

  it('stays out of the way while typing', () => {
    const input = document.createElement('input');
    document.body.appendChild(input);
    press('g', input);
    press('d', input);
    expect(navigate).not.toHaveBeenCalled();
    input.remove();
  });
});
