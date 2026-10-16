// Swapped in for environment.ts by `ng build --configuration production`
// (see fileReplacements in angular.json). Relative: the production
// nginx serves the app and proxies /api on the same origin.
export const environment = {
  production: true,
  apiBaseUrl: '/api',
};
