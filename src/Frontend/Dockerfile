# syntax=docker/dockerfile:1

FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.29-alpine
# API_UPSTREAM: where /api and /hubs are proxied. Resolved per request through the container's DNS
# (NGINX_ENTRYPOINT_LOCAL_RESOLVERS), so the UI starts even before the API is reachable.
ENV API_UPSTREAM=http://server:8080 \
    NGINX_ENTRYPOINT_LOCAL_RESOLVERS=1
RUN rm -f /etc/nginx/conf.d/default.conf \
    && chown -R nginx:nginx /etc/nginx/conf.d /var/cache/nginx
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
