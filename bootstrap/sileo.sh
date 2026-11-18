#!/bin/sh
# Sileo bootstrap for the rootful layout. Run after / is writable.
set -e
JB=/var/jb
export PATH="$JB/usr/bin:$JB/usr/sbin:$JB/bin:$JB/sbin:$PATH"

mkdir -p "$JB/var/lib/dpkg/info" "$JB/var/lib/dpkg/updates" \
         "$JB/var/lib/dpkg/triggers" "$JB/etc/apt/sources.list.d" \
         "$JB/etc/apt/preferences.d" "$JB/var/cache/apt/archives/partial"
touch "$JB/var/lib/dpkg/status"

cat > "$JB/etc/apt/sources.list.d/sileo.sources" <<'EOF'
Types: deb
URIs: https://repo.getsileo.app
Suites: ./
Components:
EOF

apt-get update || true
apt-get -y install sileo || true

ln -sf "$JB/usr/bin/sileo" /usr/bin/sileo
uicache -a 2>/dev/null || true

echo "sileo: $JB/usr/bin/sileo"
