import { TestBed } from '@angular/core/testing';

import { ScanJobService } from './scan-job.service';

describe('ScanJobService', () => {
  let service: ScanJobService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(ScanJobService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
