import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideAppTesting } from '../../../testing/test-helpers';

import { ComingSoon } from './coming-soon';

describe('ComingSoon', () => {
  let component: ComingSoon;
  let fixture: ComponentFixture<ComingSoon>;

  beforeEach(async () => {
    localStorage.clear();
    await TestBed.configureTestingModule({
      imports: [ComingSoon],
      providers: [provideAppTesting()],
    }).compileComponents();

    fixture = TestBed.createComponent(ComingSoon);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
