import { inject } from '@angular/core';
import { Routes } from '@angular/router';
import { authGuard } from './core/guards/auth.guard';
import { AuthService } from './core/services/auth.service';

export const routes: Routes = [
  {
    // The public front page. Only matches for visitors who aren't
    // signed in; for everyone else "/" falls through to the app below
    // and lands on the dashboard.
    path: '',
    pathMatch: 'full',
    title: 'Densight · Know what you expose',
    canMatch: [() => !inject(AuthService).isAuthenticated()],
    loadComponent: () => import('./features/home/home').then((m) => m.Home),
  },
  {
    path: 'login',
    title: 'Sign in · Densight',
    loadComponent: () => import('./features/login/login').then((m) => m.Login),
  },
  {
    // Full screen, without the sidebar: for a meeting room or a wall screen.
    path: 'board',
    title: 'Board · Densight',
    canActivate: [authGuard],
    loadComponent: () => import('./features/board/board').then((m) => m.Board),
  },
  {
    path: '',
    canActivate: [authGuard],
    loadComponent: () => import('./shared/components/shell/shell').then((m) => m.Shell),
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      {
        path: 'dashboard',
        title: 'Dashboard · Densight',
        loadComponent: () => import('./features/dashboard/dashboard').then((m) => m.Dashboard),
      },
      {
        path: 'fix-plan',
        title: 'Fix plan · Densight',
        loadComponent: () => import('./features/fix-plan/fix-plan').then((m) => m.FixPlanPage),
      },
      {
        path: 'my-work',
        title: 'My work · Densight',
        loadComponent: () => import('./features/my-work/my-work').then((m) => m.MyWork),
      },
      {
        path: 'assets',
        title: 'Assets · Densight',
        loadComponent: () => import('./features/assets/assets').then((m) => m.Assets),
      },
      {
        path: 'assets/:id',
        title: 'Host · Densight',
        loadComponent: () => import('./features/asset-detail/asset-detail').then((m) => m.AssetDetail),
      },
      {
        path: 'inventory',
        title: 'Inventory · Densight',
        loadComponent: () => import('./features/inventory/inventory').then((m) => m.Inventory),
      },
      {
        path: 'scanners',
        title: 'Scanners · Densight',
        loadComponent: () => import('./features/scanners/scanners').then((m) => m.Scanners),
      },
      {
        path: 'findings',
        title: 'Findings · Densight',
        loadComponent: () => import('./features/findings/findings').then((m) => m.Findings),
      },
      {
        path: 'findings/:id',
        title: 'Finding · Densight',
        loadComponent: () => import('./features/finding-detail/finding-detail').then((m) => m.FindingDetail),
      },
      {
        path: 'surface-map',
        title: 'Attack surface · Densight',
        loadComponent: () => import('./features/surface-map/surface-map').then((m) => m.SurfaceMapPage),
      },
      {
        path: 'compliance',
        title: 'Compliance · Densight',
        loadComponent: () => import('./features/compliance/compliance').then((m) => m.Compliance),
      },
      {
        path: 'activity',
        title: 'Activity · Densight',
        loadComponent: () => import('./features/activity/activity').then((m) => m.Activity),
      },
      {
        path: 'screenshots',
        title: 'Screenshots · Densight',
        loadComponent: () => import('./features/screenshots/screenshots').then((m) => m.Screenshots),
      },
      {
        path: 'notification-rules',
        title: 'Alerts & reports · Densight',
        loadComponent: () =>
          import('./features/notification-rules/notification-rules').then((m) => m.NotificationRules),
      },
      {
        path: 'scan-history',
        title: 'Scan history · Densight',
        loadComponent: () => import('./features/scan-history/scan-history').then((m) => m.ScanHistory),
      },
      {
        path: 'organization',
        title: 'Organization · Densight',
        loadComponent: () =>
          import('./features/organization/organization').then((m) => m.OrganizationPage),
      },
      {
        path: 'account-settings',
        title: 'Account · Densight',
        loadComponent: () =>
          import('./features/account-settings/account-settings').then((m) => m.AccountSettings),
      },
    ],
  },
  // Unknown URLs go home instead of rendering a blank page.
  { path: '**', redirectTo: '' },
];
