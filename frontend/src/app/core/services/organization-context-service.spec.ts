import { TestBed } from '@angular/core/testing';

import { OrganizationContextService } from './organization-context-service';

describe('OrganizationContextService', () => {
  let service: OrganizationContextService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(OrganizationContextService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
