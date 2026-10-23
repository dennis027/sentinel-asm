import { ErrorHandler, Injectable, inject } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { AuthService } from './services/auth.service';

const MAX_REPORTS = 20;

/**
 * Reports unexpected errors in the web app to the API, which logs them
 * like a backend error (with Densight's self-logging on, they appear under
 * Logs -> Errors with the browser's stack trace). Failed API calls are left
 * out (the server already logged them); each distinct error is sent once
 * per page load, at most 20 in all, and a failed report is never retried.
 */
@Injectable()
export class ErrorReporter extends ErrorHandler {
  private readonly auth = inject(AuthService);
  private readonly sent = new Set<string>();

  override handleError(error: unknown): void {
    super.handleError(error);
    try {
      this.report(error);
    } catch {
      // Reporting must never cause another error.
    }
  }

  private report(error: unknown): void {
    const actual = (error as { rejection?: unknown })?.rejection ?? error;
    if (actual instanceof HttpErrorResponse) return;
    const err = actual instanceof Error ? actual : new Error(String(actual));
    const key = `${err.name}:${err.message}`;
    if (this.sent.has(key) || this.sent.size >= MAX_REPORTS) return;
    this.sent.add(key);

    const token = this.auth.getAccessToken();
    fetch(`${environment.apiBaseUrl}/client-errors/`, {
      method: 'POST',
      keepalive: true,
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({
        type: err.name || 'Error',
        message: (err.message || 'Unknown error').slice(0, 2000),
        stack: (err.stack ?? '').slice(0, 10000),
        url: location.href.slice(0, 1000),
      }),
    }).catch(() => undefined);
  }
}
