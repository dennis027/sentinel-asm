# Densight web app

The Angular 20 single-page app for [Densight](../README.md). Everything about the product, running the
whole stack and deploying it is in the README at the repository root; this page is only the frontend's
own commands.

```bash
npm install
npm start                      # http://localhost:4200, talks to the API on http://localhost:8000
npm run lint
npm test -- --watch=false --browsers=ChromeHeadless
npm run build                  # production build in dist/frontend (adds the Content-Security-Policy)
npx ng build --configuration ghpages   # the GitHub Pages build (base href /sentinel-asm/)
```

## Layout

| Path | What is in it |
|---|---|
| `src/app/features/` | One folder per page: dashboard, findings, assets, changes, policies, logs… |
| `src/app/shared/components/` | Pieces used on several pages: the shell and sidebar, quick-view panel, saved views, the check before a scan, charts, dialogs |
| `src/app/core/services/` | One service per API resource, plus sign-in, the selected organization, theme and toasts |
| `src/app/core/models/models.ts` | The types the API returns |
| `src/app/core/labels.ts` | Plain-language names for values the API sends as identifiers |
| `src/environments/` | Where the API is, per build (`environment.ts` for development, `.prod.ts`, `.ghpages.ts`) |
| `src/styles.scss` | Design tokens (colours, spacing) for light and dark, and the shared classes (`.panel`, `.badge`, `.btn`, `.toggle`) |

Pages are standalone components, loaded lazily from `src/app/app.routes.ts`, with signals for state.
Every component has a spec next to it; `src/app/testing/test-helpers.ts` has the fixtures.
