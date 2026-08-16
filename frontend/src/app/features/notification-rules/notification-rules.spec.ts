import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NotificationRules } from './notification-rules';

describe('NotificationRules', () => {
  let component: NotificationRules;
  let fixture: ComponentFixture<NotificationRules>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [NotificationRules]
    })
    .compileComponents();

    fixture = TestBed.createComponent(NotificationRules);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
