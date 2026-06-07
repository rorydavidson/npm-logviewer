#!/bin/sh
set -e

# Run the app as this uid/gid. Defaults to the image's `node` user (1000). If
# NPM's /data files are only readable by root, set PUID=0 PGID=0 in compose.
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

# A mounted volume (named or bind) lands on /state owned by root, shadowing the
# ownership set at build time. Fix it so the chosen user can write its database.
STATE_DIR="$(dirname "${STATE_DB:-/state/logviewer.sqlite}")"
mkdir -p "$STATE_DIR"
chown -R "$PUID:$PGID" "$STATE_DIR" 2>/dev/null || true

if [ "$PUID" = "0" ]; then
  exec "$@"
fi

# setpriv exec's directly (no fork), so the app runs as PID 1 and receives
# SIGTERM for graceful shutdown.
exec setpriv --reuid "$PUID" --regid "$PGID" --init-groups "$@"
