#!/bin/sh
# Sileo bootstrap for the rootful layout. Run after / is writable.
set -e
ROOT=${MELA_ROOT:-}

PATH="/usr/bin:/usr/sbin:/bin:/sbin:$PATH"
if [ -n "$ROOT" ]; then
    PATH="$ROOT/usr/bin:$ROOT/usr/sbin:$PATH"
fi
export PATH

mkdir -p "$ROOT/var/lib/dpkg/info" "$ROOT/var/lib/dpkg/updates" \
         "$ROOT/var/lib/dpkg/triggers" "$ROOT/etc/apt/sources.list.d" \
         "$ROOT/etc/apt/preferences.d" "$ROOT/var/cache/apt/archives/partial"
touch "$ROOT/var/lib/dpkg/status"

cat > "$ROOT/etc/apt/sources.list.d/sileo.sources" <<'EOF'
Types: deb
URIs: https://repo.getsileo.app
Suites: ./
Components:
EOF

apt-get update || true
apt-get -y install sileo || true

# rootful: apt already put it in /usr/bin. rootless: bridge it into /usr/bin.
if [ -n "$ROOT" ] && [ ! -e /usr/bin/sileo ]; then
    ln -sf "$ROOT/usr/bin/sileo" /usr/bin/sileo
fi
uicache -a 2>/dev/null || true

echo "sileo: ${ROOT:-}/usr/bin/sileo"
