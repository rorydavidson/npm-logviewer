# syntax=docker/dockerfile:1

# --- build the frontend ------------------------------------------------------
FROM node:24-bookworm-slim AS web
WORKDIR /web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# --- build the backend -------------------------------------------------------
FROM node:24-bookworm-slim AS server
WORKDIR /server
COPY server/package*.json ./
RUN npm ci
COPY server/ ./
RUN npm run build && npm prune --omit=dev

# --- runtime -----------------------------------------------------------------
FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production \
    WEB_DIR=/app/web \
    STATE_DB=/state/logviewer.sqlite \
    PORT=8090
WORKDIR /app

# Copy built server, its production deps, and the static frontend.
COPY --from=server /server/dist ./dist
COPY --from=server /server/node_modules ./node_modules
COPY --from=server /server/package.json ./package.json
COPY --from=web /web/dist ./web

# State directory for our own parsed-log database (mount a volume here).
RUN mkdir -p /state && chown -R node:node /app /state

# Entrypoint runs as root only to fix the mounted volume's ownership, then drops
# to the unprivileged `node` user via runuser before starting the app.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8090

# node:sqlite is built in; no native modules to compile.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "dist/index.js"]
