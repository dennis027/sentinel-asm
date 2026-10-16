# Builds the Angular app and serves it with nginx, which also reverse-
# proxies the API (see nginx.conf) so the browser only ever talks to
# one origin -- no CORS, no API port exposed.
FROM node:22-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npx ng build --configuration production


FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist/frontend/browser /usr/share/nginx/html

EXPOSE 80
