import { HttpErrorResponse } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { provideAppTesting } from '../testing/test-helpers';
import { ErrorReporter } from './error-reporter';

describe('ErrorReporter', () => {
  it('reports each distinct error once and leaves out failed API calls', async () => {
    await TestBed.configureTestingModule({ providers: [provideAppTesting(), ErrorReporter] }).compileComponents();
    const reporter = TestBed.inject(ErrorReporter);
    const fetchSpy = spyOn(window, 'fetch').and.resolveTo(new Response(null, { status: 204 }));
    spyOn(console, 'error');

    reporter.handleError(new TypeError("Cannot read properties of undefined (reading 'id')"));
    reporter.handleError(new TypeError("Cannot read properties of undefined (reading 'id')"));
    reporter.handleError(new HttpErrorResponse({ status: 500 }));

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.calls.mostRecent().args as [string, RequestInit];
    expect(url).toContain('/client-errors/');
    expect(JSON.parse(init.body as string)).toEqual(jasmine.objectContaining({ type: 'TypeError' }));
  });
});
