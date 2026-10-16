import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideAppTesting } from '../../testing/test-helpers';

import { Home } from './home';

describe('Home', () => {
  let fixture: ComponentFixture<Home>;
  let el: HTMLElement;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Home],
      providers: [provideAppTesting()],
    }).compileComponents();
    fixture = TestBed.createComponent(Home);
    el = fixture.nativeElement;
    fixture.detectChanges();
  });

  it('says what the product is and offers a way in', () => {
    expect(el.querySelector('h1')?.textContent).toContain('Know everything you expose to the internet');
    const signIn = Array.from(el.querySelectorAll('a')).filter((a) => a.textContent?.includes('Sign in'));
    expect(signIn.length).toBeGreaterThan(0);
    expect(signIn.every((a) => a.getAttribute('href') === '/login')).toBeTrue();
  });

  it('explains how it works in three steps', () => {
    const steps = Array.from(el.querySelectorAll('.steps h3')).map((h) => h.textContent);
    expect(steps).toEqual(['Add your domain', 'It maps and checks everything', 'You hear what matters']);
  });

  it('describes every screenshot for people who cannot see it', () => {
    const light = Array.from(el.querySelectorAll<HTMLImageElement>('img.shot-light'));
    expect(light.length).toBe(3);
    expect(light.every((img) => !!img.alt)).toBeTrue();
  });
});
