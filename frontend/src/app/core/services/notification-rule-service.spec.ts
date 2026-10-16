import { TestBed } from '@angular/core/testing';
import { provideAppTesting } from '../../testing/test-helpers';

import { NotificationRuleService } from './notification-rule-service';

describe('NotificationRuleService', () => {
  let service: NotificationRuleService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({ providers: [provideAppTesting()] });
    service = TestBed.inject(NotificationRuleService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
