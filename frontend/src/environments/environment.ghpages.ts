// Swapped in for environment.ts by `ng build --configuration ghpages`: the
// app on GitHub Pages (static files only) calls the API on Render directly.
// The API must list https://dennis027.github.io in CORS_ALLOWED_ORIGINS.
export const environment = {
  production: true,
  apiBaseUrl: 'https://densight-api.onrender.com/api',
};
