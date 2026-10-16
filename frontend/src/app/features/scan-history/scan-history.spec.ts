import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideAppTesting } from '../../testing/test-helpers';

import { ScanHistory } from './scan-history';

describe('ScanHistory', () => {
  let component: ScanHistory;
  let fixture: ComponentFixture<ScanHistory>;

  beforeEach(async () => {
    localStorage.clear();
    await TestBed.configureTestingModule({
      imports: [ScanHistory],
      providers: [provideAppTesting()],
    }).compileComponents();

    fixture = TestBed.createComponent(ScanHistory);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
