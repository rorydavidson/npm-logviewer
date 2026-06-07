# NPM Log Viewer

A modern dashboard for the access and error logs that [Nginx Proxy Manager](https://nginxproxymanager.com/) (NPM) writes for each proxy host. It runs as a second container in the same Docker Compose project as NPM, reads the shared `/data` volume, and maps each log file back to its proxy host using NPM's own database. Login reuses your existing NPM credentials.

Nothing is sent anywhere. Geolocation uses a bundled offline database, so the dashboard makes no outbound calls.

## What you get

- **Overview**: requests over time (stacked by status class), unique visitors, bandwidth, error rate, success rate, status-code donut, HTTP methods, top paths, top clients, top referrers, top user agents, and a top-countries breakdown.
- **Hosts**: per proxy host traffic, visitors, errors, error rate, bandwidth, and share of total.
- **Access logs**: searchable, filterable, paginated raw entries.
- **Errors**: parsed `error.log` entries grouped by host with client, request, and upstream context.
- **Live tail**: real-time stream of new requests and errors over Server-Sent Events.
- Filter everything by time range, proxy host, status class, method, and path search.

## How it works

```
NPM container                     Log Viewer container
  /data/logs/*.log      ─ ro ─►     ingest (tail + parse) ─► /state/logviewer.sqlite
  /data/database.sqlite ─ ro ─►     host map + auth                    │
                                    Fastify API + React UI ◄───────────┘
```

- The NPM `data` volume is mounted **read-only**. The viewer never writes to NPM's files.
- Parsed log rows live in the viewer's **own** SQLite database on a separate writable `/state` volume.
- Log files are read incrementally with a persisted byte offset and inode per file, so restarts resume cleanly and NPM's log rotation is handled without gaps or duplicates.
- The proxy-host list is refreshed from NPM's database every 60 seconds, so new or renamed hosts appear without a restart.

### Parsing

NPM's default `proxy` and `standard` log formats are both supported. If you have customised NPM's log format, lines that do not match are skipped rather than mis-parsed.

### Authentication

Login verifies the email and password against NPM's `user` and `auth` tables using the same bcrypt hash NPM stores. Disabled and deleted users are rejected. The NPM database is opened read-only. On success the viewer issues its own signed, HTTP-only session cookie.

If NPM ever changes its database schema, the only code that needs updating is `server/src/npm/npmDb.ts`.

## Deploy

### Mount points (the part that matters)

| Container path | Mode | What it is |
| --- | --- | --- |
| `/data` | read-only | The **same** volume source NPM mounts at its `/data`. Gives access to `/data/logs` and `/data/database.sqlite`. |
| `/state` | read-write | A separate volume for the viewer's own parsed-log database. |

The `/data` source must point at the exact same host path (or named volume) that your NPM service uses, otherwise the viewer sees no logs.

### Steps

1. Clone this repo next to your NPM compose file (or build and push the image).
2. Add the `logviewer` service from [`docker-compose.snippet.yml`](docker-compose.snippet.yml) into your existing NPM compose, adjusting `./data` and the `depends_on` service name to match yours.
3. Create a `.env` with a strong secret:
   ```sh
   echo "LOGVIEWER_SECRET=$(openssl rand -hex 32)" >> .env
   ```
4. `docker compose up -d --build logviewer`
5. (Recommended) Add a proxy host in NPM pointing a domain at `logviewer:8090`, enable SSL, and set `SECURE_COOKIE=true`. Then remove the published port so the viewer is only reachable through NPM.

A complete worked example, including NPM itself, is in [`docker-compose.example.yml`](docker-compose.example.yml).

## Configuration

All via environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `NPM_DATA` | `/data` | Root of the mounted NPM data volume. |
| `LOGS_DIR` | `$NPM_DATA/logs` | Override the logs directory. |
| `NPM_DB` | `$NPM_DATA/database.sqlite` | Override the NPM database path. |
| `STATE_DB` | `/state/logviewer.sqlite` | Where the viewer stores parsed rows. |
| `BACKFILL_DAYS` | `14` | Days of existing logs to index on first boot, and the retention window. |
| `SESSION_SECRET` | _(required in prod)_ | Secret for signing session cookies. |
| `SESSION_TTL` | `43200` | Session lifetime in seconds (12h). |
| `SECURE_COOKIE` | `false` | Set `true` when served over HTTPS. |
| `PORT` | `8090` | HTTP port. |
| `PUID` / `PGID` | `1000` | User the app runs as. Set both to `0` if NPM's `/data` files are only readable by root, or if you see "unable to open database file". |

### Troubleshooting

**`unable to open database file` on startup** — the `/state` volume is not writable
by the app's user. The entrypoint chowns it automatically; if it persists (e.g. a
bind mount with locked-down ownership), set `PUID=0` and `PGID=0` in compose.

**Empty dashboard / cannot read logs** — the app's user cannot read NPM's `/data`.
NPM runs as root, so its files may be root-only. Set `PUID=0` `PGID=0` to match.

## Development

Backend and frontend are separate packages.

```sh
# Backend (needs Node 24+ for the built-in node:sqlite module)
cd server
npm install
NPM_DATA=/path/to/npm/data STATE_DB=./state/dev.sqlite SESSION_SECRET=dev-secret npm run dev

# Frontend (proxies /api to localhost:8090)
cd web
npm install
npm run dev
```

Tests:

```sh
cd server && npm test     # parser, analytics, auth, session, NPM DB reader
```

## Notes and trade-offs

- **Geo accuracy** is city-level at best and comes from the bundled GeoLite data; treat it as indicative. The country breakdown is the primary geo view by design, to avoid shipping external map tiles. A world map can be layered on later using the per-country lat/lon already returned by `/api/geo`.
- **Response time** is not charted because NPM's default log format does not record `$request_time`. Bandwidth and status are used as the health signals instead.
- The parsed-log database grows with traffic; `BACKFILL_DAYS` doubles as a daily retention window so it stays bounded.
- Requires **Node 24+** at runtime for the built-in `node:sqlite` module. There are no native modules to compile.
