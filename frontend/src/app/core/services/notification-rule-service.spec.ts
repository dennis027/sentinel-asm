import { TestBed } from '@angular/core/testing';

import { NotificationRuleService } from './notification-rule-service';

describe('NotificationRuleService', () => {
  let service: NotificationRuleService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(NotificationRuleService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
