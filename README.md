# ProxyLogs — NPM Log Viewer

A modern dashboard for the access and error logs that [Nginx Proxy Manager](https://nginxproxymanager.com/) (NPM) writes for each proxy host. It runs as a second container in the same Docker Compose project as NPM, reads the shared `/data` volume, and maps each log file back to its proxy host using NPM's own database. Login reuses your existing NPM credentials.

Nothing is sent anywhere. Geolocation uses a bundled offline database, so the dashboard makes no outbound calls.

## What you get

- **Overview**: requests over time (stacked by status class), unique visitors, bandwidth, error rate, success rate, status-code donut, HTTP methods, top paths, top clients, top referrers, top user agents, and a top-countries breakdown.
- **Hosts**: per proxy host traffic, visitors, errors, error rate, bandwidth, and share of total. Click a host to drill the whole dashboard into it.
- **World**: an offline choropleth of requests by country with a ranked breakdown; click a country to filter everything by it.
- **Access logs**: searchable, filterable, paginated raw entries.
- **Errors**: parsed `error.log` entries grouped by host with client, request, and upstream context.
- **Threats**: background detection of suspicious activity (scanning, brute force, exploit probing, injection payloads, hacking-tool agents, flooding, cross-host scanning, fuzzing, and more), with severities you can tune in the UI and optional email alerts.
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
| `RESEND_API_KEY` | _(empty)_ | Resend API key. When set, the Threats tab can email alerts. Empty disables sending. |
| `ALERT_FROM` | `ProxyLogs <onboarding@resend.dev>` | From address for alert emails. Must be a sender verified in your Resend account (the `onboarding@resend.dev` default only delivers to your own Resend login email). |
| `TRUST_PROXY` | `true` | Trust `X-Forwarded-For` so the login rate limiter sees the real client IP. Keep `true` behind NPM; set `false` only if the app is exposed directly with no proxy. |
| `LOGIN_MAX_ATTEMPTS` | `10` | Failed logins per IP allowed within the window before throttling. |
| `LOGIN_WINDOW_MINUTES` | `15` | Login throttle window. |

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
cd server && npm test     # parser, analytics, auth, session, NPM DB, networks, threats, security
```

## Behind Cloudflare (or any reverse proxy): logging the real visitor IP

If your sites are proxied through Cloudflare, NPM logs the **Cloudflare edge IP** as the client (`$remote_addr`), not the actual visitor. Geolocation of those edge IPs is meaningless, so the viewer detects Cloudflare's ranges (and private/Docker ranges) and leaves them off the world map rather than mislocating them.

To get accurate visitor geolocation, tell NPM to trust Cloudflare and use the real client IP. This rewrites `$remote_addr` to the visitor before it is logged, so the **default log format keeps working** and the viewer picks up real IPs automatically.

In NPM, edit the proxy host → **Advanced** tab → **Custom Nginx Configuration**, and add:

```nginx
# Trust Cloudflare and use the real visitor IP (https://www.cloudflare.com/ips)
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;

real_ip_header CF-Connecting-IP;
real_ip_recursive on;
```

Apply it, then new requests will log the visitor IP. Existing rows keep their old (wrong) location until they age out of `BACKFILL_DAYS`; to clear them immediately, remove the `logviewer-state` volume and restart so logs are re-ingested.

## Threat detection and alerts

The **Threats** tab runs a set of detectors over a rolling window (default 10 minutes) every minute, in the background, even when nobody is looking. Each finding has a tunable severity. Detectors include:

- 404 scanning, path fuzzing, and cross-host scanning by a single client
- auth brute force (repeated 401/403)
- requests for known exploit paths (`.env`, `.git`, `wp-login`, phpMyAdmin, …)
- SQLi / XSS / path-traversal payloads in the URL
- hacking-tool user agents (sqlmap, nikto, nmap, masscan, …)
- request floods, unusual HTTP methods, direct-IP probing, and 5xx surges

Everything is editable in the UI: enable/disable each rule, change its severity, adjust thresholds, and edit the match patterns for the pattern-based rules. Settings persist in the state database.

**Exceptions:** add trusted IPs or CIDR ranges (e.g. your own address) so they are ignored by every rule. Use the **Trust IP** button on any finding, or edit the list in Settings. Existing findings for a newly trusted address are removed on the next cycle.

### Email alerts (Resend)

1. Set `RESEND_API_KEY` (and optionally `ALERT_FROM`) in the container environment.
2. In the Threats tab → **Settings**, set the alert email address, the minimum severity to alert on, and a cooldown (to avoid repeat spam).
3. Use **Send test email** to confirm delivery.

When findings reach the chosen severity, ProxyLogs sends one bundled email per cycle (respecting the per-rule cooldown) via the Resend HTTP API. No alerting happens until both `RESEND_API_KEY` and an alert email are set.

## Security

The viewer is built to sit on the public internet behind NPM, so it ships with sensible defaults:

- **Authentication** on every API route and page, reusing NPM's credentials (bcrypt verified, NPM DB opened read-only). Constant-time comparison and a dummy hash avoid user-enumeration via timing.
- **Sessions** are signed (HMAC-SHA256), HTTP-only cookies with `SameSite=Lax`. Set `SECURE_COOKIE=true` behind HTTPS to add the `Secure` flag and enable HSTS.
- **Login rate limiting** per client IP (`LOGIN_MAX_ATTEMPTS` / `LOGIN_WINDOW_MINUTES`) to blunt brute force. Keep `TRUST_PROXY=true` so the limit keys on the real visitor, not NPM.
- **Security headers** on every response: a locked-down same-origin Content-Security-Policy, `X-Frame-Options: DENY` and `frame-ancestors 'none'` (clickjacking), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, and HSTS when served over HTTPS.
- **Same-origin only** — no CORS is enabled, so other sites cannot read the API from a browser.
- **Not indexable** — ships a `robots.txt` that disallows everything plus a `noindex` meta tag, so the dashboard stays out of search engines.
- **Read-only on NPM** — the NPM database is opened read-only and `/data` is mounted read-only; the viewer only ever writes to its own `/state` database.
- **Input handling** — all SQL uses bound parameters; the threat-config endpoint clamps and whitelists its input. The container runs as a non-root user.

For defence in depth, you can also put the viewer behind an NPM Access List (HTTP basic) or your SSO, and only expose it over HTTPS.

## Notes and trade-offs

- **Geo accuracy** is city-level at best and comes from the bundled GeoLite data; treat it as indicative. The country breakdown is the primary geo view by design, to avoid shipping external map tiles. Cloudflare and private/Docker IPs are excluded from geolocation (see above).
- **Response time** is not charted because NPM's default log format does not record `$request_time`. Bandwidth and status are used as the health signals instead.
- The parsed-log database grows with traffic; `BACKFILL_DAYS` doubles as a daily retention window so it stays bounded.
- Requires **Node 24+** at runtime for the built-in `node:sqlite` module. There are no native modules to compile.

## Built with

- Backend: [Fastify](https://fastify.dev/), Node's built-in `node:sqlite`, [geoip-lite](https://github.com/geoip-lite/node-geoip) (offline geolocation), [bcryptjs](https://github.com/dcodeIO/bcrypt.js), [chokidar](https://github.com/paulmillr/chokidar).
- Frontend: [React](https://react.dev/), [Vite](https://vitejs.dev/), [Tailwind CSS](https://tailwindcss.com/), [Recharts](https://recharts.org/), [react-svg-worldmap](https://github.com/MarcoRapaccini/react-svg-worldmap).
- Email alerts via the [Resend](https://resend.com/) HTTP API.

## Thanks

Huge thanks to **[Jamie Curnow (jc21)](https://github.com/jc21)** and the contributors behind [Nginx Proxy Manager](https://nginxproxymanager.com/). NPM does the hard work of running the proxy and writing these logs; this project is just a friendly window onto them. If you find NPM useful, consider [supporting it](https://nginxproxymanager.com/).

This is an independent, unofficial companion tool and is not affiliated with or endorsed by the Nginx Proxy Manager project.

## Licence

MIT — see [LICENSE](LICENSE).
