import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';

const AUTH_FREE_PATHS = ['/auth/login/', '/token/refresh/', '/token/'];

/**
 * Attaches the access token to every request. On a 401 (expired
 * access token), attempts ONE silent refresh via the refresh token and
 * retries the original request -- if that also fails, the session is
 * genuinely over: clear it and redirect to /login with a `redirect`
 * query param so the user lands back where they were after logging
 * back in, rather than always bouncing to the dashboard.
 */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  const router = inject(Router);

  const isAuthFree = AUTH_FREE_PATHS.some((path) => req.url.includes(path));
  const token = auth.getAccessToken();

  const authedReq = token && !isAuthFree
    ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
    : req;

  return next(authedReq).pipe(
    catchError((error: unknown) => {
      const is401 = error instanceof HttpErrorResponse && error.status === 401;
      if (!is401 || isAuthFree || !auth.hasRefreshToken()) {
        return throwError(() => error);
      }

      return auth.refreshAccessToken().pipe(
        switchMap((tokens) => {
          const retriedReq = req.clone({
            setHeaders: { Authorization: `Bearer ${tokens.access}` },
          });
          return next(retriedReq);
        }),
        catchError(() => {
          // Refresh itself failed -- the session is genuinely over.
          auth.clearSession();
          router.navigate(['/login'], {
            queryParams: { redirect: router.url },
          });
          return throwError(() => error);
        }),
      );
    }),
  );
};