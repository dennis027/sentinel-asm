import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Findings } from './findings';

describe('Findings', () => {
  let component: Findings;
  let fixture: ComponentFixture<Findings>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Findings]
    })
    .compileComponents();

    fixture = TestBed.createComponent(Findings);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
