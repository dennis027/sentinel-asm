import { Component, inject } from '@angular/core';
import { ThemePreference, ThemeService } from '../../../core/services/theme.service';
import { Icon, IconName } from '../icon/icon';

/**
 * Light / match system / dark, for pages outside the signed-in shell
 * (the home and sign-in pages). The sidebar has its own copy styled
 * for its dark background; both drive the same ThemeService.
 */
@Component({
  selector: 'app-theme-switch',
  imports: [Icon],
  templateUrl: './theme-switch.html',
  styleUrl: './theme-switch.scss',
})
export class ThemeSwitch {
  protected readonly theme = inject(ThemeService);

  protected readonly options: { value: ThemePreference; label: string; icon: IconName }[] = [
    { value: 'light', label: 'Light theme', icon: 'sun' },
    { value: 'system', label: 'Match system theme', icon: 'monitor' },
    { value: 'dark', label: 'Dark theme', icon: 'moon' },
  ];
}
