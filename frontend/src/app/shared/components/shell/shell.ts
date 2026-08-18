import { Component, OnInit, inject } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from '../../../core/services/auth.service';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-shell',
  imports: [RouterOutlet, RouterLink, RouterLinkActive,FormsModule],
  templateUrl: './shell.html',
  styleUrl: './shell.scss',
})
export class Shell implements OnInit {
  protected readonly auth = inject(AuthService);
  protected readonly orgContext = inject(OrganizationContextService);

  ngOnInit(): void {
    this.orgContext.loadOrganizations();
  }

  onOrgChange(orgId: string): void {
    this.orgContext.selectOrganization(orgId);
  }
}