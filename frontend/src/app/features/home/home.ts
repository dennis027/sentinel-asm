import { LogoMark } from '../../shared/components/logo-mark/logo-mark';
import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Icon, IconName } from '../../shared/components/icon/icon';
import { ThemeSwitch } from '../../shared/components/theme-switch/theme-switch';

/**
 * The public front page: what this is, in the time it takes to scroll
 * once. Only shown to visitors who aren't signed in (see app.routes.ts);
 * signed-in users go straight to their dashboard.
 */
@Component({
  selector: 'app-home',
  imports: [LogoMark, RouterLink, Icon, ThemeSwitch],
  templateUrl: './home.html',
  styleUrl: './home.scss',
})
export class Home {
  protected readonly problems: { icon: IconName; title: string; text: string }[] = [
    {
      icon: 'globe',
      title: 'You have more online than you think',
      text: 'Staging servers, old campaign sites, a subdomain someone set up years ago. Nobody keeps the full list, so nobody is watching all of it.',
    },
    {
      icon: 'history',
      title: 'It changes when you are not looking',
      text: 'A certificate expires. A database port gets opened for a quick test and never closed. Last month\u2019s audit does not show this week\u2019s mistake.',
    },
    {
      icon: 'findings',
      title: 'Scanner output is not an answer',
      text: '\u201cOpen port 3389/tcp\u201d means little to the person who has to decide whether to act. They need to know why it matters and what to do.',
    },
  ];

  protected readonly steps: { title: string; text: string }[] = [
    {
      title: 'Add your domain',
      text: 'Tell Densight the domain to watch and prove it is yours with a DNS record. Nothing is scanned until you do.',
    },
    {
      title: 'It maps and checks everything',
      text: 'It finds the hosts under your domain, then checks each one: open ports, certificates, security headers, known vulnerabilities, and what the site looks like. Then it does it again every day.',
    },
    {
      title: 'You hear what matters',
      text: 'One grade, what changed since last week, and the issues worth fixing first, each explained in plain language. New findings go to your inbox or chat.',
    },
  ];

  protected readonly features: { image: string; title: string; text: string; points: string[] }[] = [
    {
      image: 'findings',
      title: 'Findings you can act on',
      text: 'Issues are listed worst first, and every one says why it matters and how to fix it.',
      points: [
        'Plain-language impact and fix for each issue, and the attacker technique it enables',
        'A fix plan that ranks the work and shows the grade each fix earns',
        'Mark accepted risks (until a date, if you like) and false positives so they stop counting',
        'Export to CSV, JSON or PDF',
      ],
    },
    {
      image: 'scanners',
      title: 'One click covers the whole domain',
      text: 'Each scanner runs across every host you have, with progress you can watch. Or leave it: they all run daily.',
      points: [
        'Eighteen checks, from exposed files and open ports to email spoofing and lookalike domains',
        'New scanners are plugins: one file, no other changes',
        'Refuses targets that point at private networks',
      ],
    },
  ];

  protected readonly year = new Date().getFullYear();
}
