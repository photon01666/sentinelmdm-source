FROM node:24-alpine

WORKDIR /app

COPY package*.json ./
# better-sqlite3 v13+ ships prebuilt N-API binaries for linuxmusl-x64 (Alpine) in
# prebuilds/. At runtime, lib/binding.js loads the .node directly — no compilation.
# However, npm auto-detects binding.gyp and forces `node-gyp rebuild` during install
# even though no `install` script is declared. Disable that with node_gyp=false so
# npm ci skips the unnecessary compile (which would fail without build tools).
# Hard-require express so a broken install FAILS the build loudly.
RUN npm ci --omit=dev --ignore-scripts \
 && node -e "require('express')" \
 && node -e "require('better-sqlite3')"

COPY . .

# Prepare writable paths for the non-root `node` user (uid 1000), then drop root below.
# App state lives in Postgres/Redis/R2; locally it only needs the entrypoint's
# /data/streams scratch plus any /app/{uploads,apk} writes. node_modules + code stay
# root-owned (read-only to node) so the image isn't bloated by a recursive chown.
RUN chmod +x /app/entrypoint.sh \
 && mkdir -p /data/streams /app/uploads /app/apk \
 && chown -R node:node /data \
 && chown node:node /app /app/uploads /app/apk

EXPOSE 3000

ENV NODE_ENV=production

# Drop root: run the server as the built-in unprivileged `node` user (uid 1000).
USER node

# Swarm health probe — returns 200 only after auto-unlock completes.
# start-period covers the ~15s auto-unlock window so the first few failures
# during boot don't count against the retries threshold.
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:3000/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["/app/entrypoint.sh"]
