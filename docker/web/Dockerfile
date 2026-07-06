# syntax=docker/dockerfile:1.7
# =============================================================================
# FORENSIA — imagen del servicio `web`
#
# Multi-stage: node compila la SPA React de web/ (typecheck incluido) y nginx
# sirve dist/ proxificando /api y /ws hacia el servicio `api` por la red
# interna del compose (misma-origen: el navegador solo habla con este puerto).
#
# Contexto de build = raíz del repo (ver docker-compose.yml y .dockerignore,
# que solo deja entrar web/ sin node_modules ni dist).
#
# El compose publica el puerto como 127.0.0.1:5173 (SECURITY INVARIANT 1).
# =============================================================================
FROM node:20-bookworm-slim AS build

WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM nginx:1.27-alpine

COPY docker/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
