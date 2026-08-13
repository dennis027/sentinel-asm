import { Component, input } from '@angular/core';

@Component({
  selector: 'app-coming-soon',
  template: `
    <div style="padding: 24px;">
      <h1 style="font-size: 20px; margin: 0 0 4px;">{{ title() }}</h1>
      <p style="color: #6b7280; font-size: 13px;">Built in the next module.</p>
    </div>
  `,
})
export class ComingSoon {
  readonly title = input('Coming soon');
}