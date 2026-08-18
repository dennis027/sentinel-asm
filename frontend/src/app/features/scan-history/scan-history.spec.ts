import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ScanHistory } from './scan-history';

describe('ScanHistory', () => {
  let component: ScanHistory;
  let fixture: ComponentFixture<ScanHistory>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ScanHistory]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ScanHistory);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
