import { TestBed } from '@angular/core/testing';
import { provideAppTesting } from '../../testing/test-helpers';

import { OrganizationService } from './organization-service';

describe('OrganizationService', () => {
  let service: OrganizationService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({ providers: [provideAppTesting()] });
    service = TestBed.inject(OrganizationService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
