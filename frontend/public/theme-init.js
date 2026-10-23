// Apply a saved light/dark choice before first paint (see ThemeService).
// A file rather than an inline script, so the Content-Security-Policy can
// forbid inline scripts.
try {
  var theme = localStorage.getItem('sentinel_theme');
  if (theme === 'light' || theme === 'dark') document.documentElement.setAttribute('data-theme', theme);
} catch (e) {}
