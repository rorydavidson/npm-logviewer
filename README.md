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
- **Bans**: a block list of IPs/CIDRs enforced via an nginx `deny` snippet, with manual and automatic banning.
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

### Container image

Prebuilt multi-arch images (amd64 + arm64) are published to Docker Hub by CI, so you can pull instead of build:

```sh
docker pull rorydavidson/npm-logviewer:latest
```

Use it in compose with `image: rorydavidson/npm-logviewer:latest` instead of `build:`. Tags: `latest` (default branch), `X.Y.Z` and `X.Y` (on version tags), and a short commit SHA.

To publish from your own fork, add these in the GitHub repo settings:

- **Secrets**: `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` (a Docker Hub access token).
- **Variable** (optional): `DOCKERHUB_IMAGE` to set the image name, e.g. `yourname/npm-logviewer`. If unset, it defaults to `<github-owner>/<repo>`.

The workflow ([.github/workflows/docker-publish.yml](.github/workflows/docker-publish.yml)) runs the tests, then builds and pushes on every push to `main`, on `v*.*.*` tags, and on manual dispatch.

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
| `SITE_URL` | _(empty)_ | Public base URL of the dashboard (e.g. `https://logs.example.com`). Used to add clickable deep links in alert emails. |
| `TRUST_PROXY` | `true` | Trust `X-Forwarded-For` so the login rate limiter sees the real client IP. Keep `true` behind NPM; set `false` only if the app is exposed directly with no proxy. |
| `LOGIN_MAX_ATTEMPTS` | `10` | Failed logins per IP allowed within the window before throttling. |
| `LOGIN_WINDOW_MINUTES` | `15` | Login throttle window. |
| `NGINX_CUSTOM_DIR` | `$NPM_DATA/nginx/custom` | Where the ban `deny` snippet is written. Must be NPM's custom-config dir, mounted read-write. |
| `NPM_CONTAINER` | _(empty)_ | NPM container name. Set it (and mount the Docker socket) to reload nginx automatically when bans change. |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Docker socket path, used only to reload nginx in the NPM container. |

### Troubleshooting

**`unable to open database file` on startup** — the `/state` volume is not writable
by the app's user. The entrypoint chowns it automatically; if it persists (e.g. a
bind mount with locked-down ownership), set `PUID=0` and `PGID=0` in compose.

**Empty dashboard / cannot read logs** — the app's user cannot read NPM's `/data`.
NPM runs as root, so its files may be root-only. Set `PUID=0` `PGID=0` to match.

**Alert emails say "SITE_URL is not set"** — a value in `.env` is only used for
`${...}` interpolation in compose; it is not passed into the container by itself.
Make sure the `logviewer` service forwards it, e.g. `SITE_URL: ${SITE_URL}` (or a
literal `SITE_URL: https://logs.example.com`) under `environment:`, then recreate
the container. The startup log prints the `siteUrl` it actually loaded.

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

Each finding shows the attacker IP (with country flag) and the **proxy hosts it has been hitting**, with per-host counts. Click a target host, or **View logs →**, to jump straight to the matching access-log entries (pre-filtered by IP, time window, and optionally host).

**Exceptions:** add trusted IPs or CIDR ranges (e.g. your own address) so they are ignored by every rule. Use the **Trust IP** button on any finding, or edit the list in Settings. Existing findings for a newly trusted address are removed on the next cycle.

### Email alerts (Resend)

1. Set `RESEND_API_KEY` (and optionally `ALERT_FROM`) in the container environment.
2. Set `SITE_URL` so the emails can include clickable links back to the dashboard.
3. In the Threats tab → **Settings**, set the alert email address, the minimum severity to alert on, a cooldown (to avoid repeat spam), and **how many findings** must appear in a cycle before an email is sent.
4. Use **Send test email** to confirm delivery.

When findings reach the chosen severity, ProxyLogs sends one bundled email per cycle (respecting the per-rule cooldown) via the Resend HTTP API. No alerting happens until both `RESEND_API_KEY` and an alert email are set.

**Concerted-attack threshold:** "Email only after N findings" lets you avoid noise from a single stray hit. Set it to `1` to be told about every qualifying threat, or higher to only be emailed when several findings fire together (a coordinated probe). 

**Deep links:** when `SITE_URL` is set, each email links to the Threats tab and, per finding, to the access logs pre-filtered to the offending IP and time window, so you can jump straight to the entry in question.

Alerts are sent as formatted **HTML** (with a plain-text fallback) and include, per finding: severity, rule, source IP and its location, the targeted proxy hosts with counts, hit count, detail, first/last seen, a sample request, and the deep link.

## Banning IPs

The **Bans** tab maintains a block list of IPs/CIDRs. ProxyLogs enforces it by writing an nginx `deny` snippet (`proxylogs-bans.conf`) into NPM's custom-config directory and ensuring NPM includes it in every proxy host. You can ban manually (the **Ban IP** button on a finding, or the Bans tab), or have it happen automatically.

**Auto-ban** (Threats → Settings → "Auto-ban attackers", off by default): when an IP trips at least N distinct findings at or above a chosen severity within the detection window, it is added to the ban list. Trusted (exception-list) and private addresses are never banned, so you cannot lock yourself out — add your own IP to the exceptions first.

### Making bans take effect

1. **Mount NPM's custom dir read-write** so ProxyLogs can write the snippet. Keep `/data` read-only and add a narrow read-write mount just for the custom dir:
   ```yaml
       volumes:
         - ./data:/data:ro
         - ./data/nginx/custom:/data/nginx/custom:rw
         - logviewer-state:/state
   ```
2. **Reload nginx** so new bans apply. Either:
   - **Automatic** — set `NPM_CONTAINER` (your NPM service's container name) and mount the Docker socket, and ProxyLogs reloads nginx itself on every change:
     ```yaml
         environment:
           NPM_CONTAINER: npm-app
         volumes:
           - /var/run/docker.sock:/var/run/docker.sock
     ```
     Note: mounting the Docker socket grants the container significant host privileges — only do this if you accept that trade-off.
   - **Manual / passive** — leave it off; bans are written to the file and apply on NPM's next reload or restart. The Bans tab shows which mode is active.

> **Behind Cloudflare:** bans match nginx's `$remote_addr`. Unless you have configured NPM to use the real client IP (see the Cloudflare section above), that is the Cloudflare edge IP, so banning would block the CDN, not the visitor. Configure real-IP first for meaningful bans.

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

## Performance impact on NPM

Under normal use the impact on NPM is negligible: ProxyLogs reads `/data` and NPM's database read-only on its own connection, and all parsing/queries run in its own container. Things to be aware of over time:

- **Ban list size.** Bans become nginx `deny` rules, which nginx checks per request. A few hundred entries is invisible; tens of thousands (from aggressive long-running auto-ban) add a small per-request cost and slow config reloads. Prefer banning CIDRs over many single IPs, and periodically prune stale bans. Auto-ban is conservative by default (critical + multiple findings) to keep the list small.
- **nginx reloads.** Ban changes trigger an `nginx -s reload` only when automatic reload is enabled. ProxyLogs batches all of a detection cycle's bans into a single reload, and skips the reload entirely when the rule file is unchanged, so even under sustained attack it reloads at most once per cycle.
- **Disk.** The parsed-log database grows with traffic but is capped by `BACKFILL_DAYS` (daily prune). It shares the host disk with NPM, so size `BACKFILL_DAYS` to your retention needs and disk.

## Built with

- Backend: [Fastify](https://fastify.dev/), Node's built-in `node:sqlite`, [geoip-lite](https://github.com/geoip-lite/node-geoip) (offline geolocation), [bcryptjs](https://github.com/dcodeIO/bcrypt.js), [chokidar](https://github.com/paulmillr/chokidar).
- Frontend: [React](https://react.dev/), [Vite](https://vitejs.dev/), [Tailwind CSS](https://tailwindcss.com/), [Recharts](https://recharts.org/), [react-svg-worldmap](https://github.com/MarcoRapaccini/react-svg-worldmap).
- Email alerts via the [Resend](https://resend.com/) HTTP API.

## Thanks

Huge thanks to **[Jamie Curnow (jc21)](https://github.com/jc21)** and the contributors behind [Nginx Proxy Manager](https://nginxproxymanager.com/). NPM does the hard work of running the proxy and writing these logs; this project is just a friendly window onto them. If you find NPM useful, consider [supporting it](https://nginxproxymanager.com/).

This is an independent, unofficial companion tool and is not affiliated with or endorsed by the Nginx Proxy Manager project.

## Licence

MIT — see [LICENSE](LICENSE).
