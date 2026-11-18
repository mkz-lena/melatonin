#!/bin/sh
# TrollStore-lite install: place a .app in /Applications, re-sign, refresh UI.
# usage: app-install.sh <App.app>
set -e

SRC="$1"
[ -n "$SRC" ] && [ -d "$SRC" ] || { echo "usage: $0 <App.app>"; exit 1; }

NAME=$(basename "$SRC")
DEST="/Applications/$NAME"
LDID=/var/jb/usr/bin/ldid

rm -rf "$DEST"
cp -a "$SRC" "$DEST"
chown -R 0:0 "$DEST"
chmod -R 755 "$DEST"

if [ -x "$LDID" ]; then
    find "$DEST" -type f -perm -111 -exec "$LDID" -S {} \; 2>/dev/null || true
fi

uicache -a 2>/dev/null || true
killall -9 installd 2>/dev/null || true

echo "installed $DEST"
