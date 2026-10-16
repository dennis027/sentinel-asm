import { TestBed } from '@angular/core/testing';
import { provideAppTesting } from '../../testing/test-helpers';

import { AssetService } from './asset-service';

describe('AssetService', () => {
  let service: AssetService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({ providers: [provideAppTesting()] });
    service = TestBed.inject(AssetService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
