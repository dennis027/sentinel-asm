import { Routes } from '@angular/router';
import { authGuard } from './core/guards/auth.guard';

export const routes: Routes = [
  {
    path: 'login',
    loadComponent: () => import('./features/login/login').then((m) => m.Login),
  },
  {
    path: '',
    canActivate: [authGuard],
    loadComponent: () => import('./shared/components/shell/shell').then((m) => m.Shell),
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      {
        path: 'dashboard',
        loadComponent: () => import('./features/dashboard/dashboard').then((m) => m.Dashboard),
      },
      {
        path: 'assets',
        loadComponent: () => import('./features/assets/assets').then((m) => m.Assets),
      },
      {
        path: 'scanners',
        loadComponent: () => import('./features/scanners/scanners').then((m) => m.Scanners),
      },
      {
        path: 'findings',
        loadComponent: () => import('./features/findings/findings').then((m) => m.Findings),
      },
      {
        path: 'notification-rules',
        loadComponent: () =>
          import('./features/notification-rules/notification-rules').then((m) => m.NotificationRules),
      },
      {
        path: 'scan-history',
        loadComponent: () => import('./features/scan-history/scan-history').then((m) => m.ScanHistory),
      },
    ],
  },
];