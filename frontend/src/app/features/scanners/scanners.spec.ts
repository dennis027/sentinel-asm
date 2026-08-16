import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Scanners } from './scanners';

describe('Scanners', () => {
  let component: Scanners;
  let fixture: ComponentFixture<Scanners>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Scanners]
    })
    .compileComponents();

    fixture = TestBed.createComponent(Scanners);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
