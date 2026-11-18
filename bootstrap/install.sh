#!/bin/sh
# rootful bootstrap, run by melatonind after / is writable
set -e
JB=/var/jb

mkdir -p "$JB/usr/bin" "$JB/usr/libexec" "$JB/usr/lib" "$JB/var/lib/dpkg"

[ -f /tmp/sileo.tar.gz ] && tar -xzf /tmp/sileo.tar.gz -C "$JB"
[ -f /tmp/libhooker.deb ] && dpkg -i --root="$JB" /tmp/libhooker.deb || true

ln -sf "$JB/usr/bin/sileo" /usr/bin/sileo
mkdir -p /etc/apt
[ -d "$JB/etc/apt" ] && cp -a "$JB/etc/apt/." /etc/apt/ 2>/dev/null || true

echo "bootstrap laid at $JB"
[ -x "$JB/usr/libexec/sshd" ] && echo "sshd: root@127.0.0.1 -p 2222"
