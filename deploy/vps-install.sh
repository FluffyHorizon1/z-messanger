#!/usr/bin/env bash
# One-command Z relay install for your own Linux VPS, with automatic HTTPS/TLS
# via Caddy. Run as root on a fresh Ubuntu/Debian box that has a domain name
# pointed at it (an A record → this server's IP).
#
#   curl -fsSL https://raw.githubusercontent.com/USER/z-messenger/main/deploy/vps-install.sh | sudo bash -s relay.example.com
#
# …or copy this repo to the server and run:  sudo bash deploy/vps-install.sh relay.example.com
set -euo pipefail

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
  echo "Usage: sudo bash deploy/vps-install.sh <your-domain>"
  echo "  (point the domain's DNS A record at this server first)"
  exit 1
fi

echo ">> Installing Docker if needed…"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi

# Resolve the repo's server/ directory whether run from a clone or piped.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" 2>/dev/null && pwd || echo .)"
if [ -f "$SCRIPT_DIR/../server/server.js" ]; then
  SRC="$SCRIPT_DIR/../server"
else
  echo ">> Fetching relay source…"
  SRC="$(mktemp -d)/server"
  mkdir -p "$SRC"
  # If you forked the repo, change this URL to yours.
  base="https://raw.githubusercontent.com/USER/z-messenger/main/server"
  for f in server.js package.json Dockerfile; do
    curl -fsSL "$base/$f" -o "$SRC/$f"
  done
fi

WORK=/opt/z-relay
mkdir -p "$WORK"
cp "$SRC"/server.js "$SRC"/package.json "$SRC"/Dockerfile "$WORK"/

cat > "$WORK/Caddyfile" <<EOF
$DOMAIN {
    reverse_proxy z-relay:8080
}
EOF

cat > "$WORK/docker-compose.yml" <<'EOF'
services:
  z-relay:
    build: .
    read_only: true
    restart: unless-stopped
    environment:
      LOG_LEVEL: info
      QUEUE_TTL_HOURS: "72"
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - z-relay
volumes:
  caddy_data:
  caddy_config:
EOF

echo ">> Starting relay + Caddy (automatic TLS for $DOMAIN)…"
cd "$WORK"
docker compose up -d --build

echo
echo "Done. In ~30s your relay is live at:  wss://$DOMAIN"
echo "Check:  https://$DOMAIN/health"
