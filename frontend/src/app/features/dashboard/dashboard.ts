import { Component, inject } from '@angular/core';
import { AuthService } from '../../core/services/auth.service';

@Component({
  selector: 'app-dashboard',
  template: `
    <div style="padding: 24px;">
      <h1>Dashboard</h1>
      <p>Signed in as {{ auth.currentUsername() }}</p>
      <button (click)="auth.logout()">Sign out</button>
    </div>
  `,
})
export class Dashboard {
  protected readonly auth = inject(AuthService);
}