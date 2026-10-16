import { TestBed } from '@angular/core/testing';
import { provideAppTesting } from '../../testing/test-helpers';

import { ScannerService } from './scanner-service';

describe('ScannerService', () => {
  let service: ScannerService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({ providers: [provideAppTesting()] });
    service = TestBed.inject(ScannerService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
