#!/bin/sh
# rootful bootstrap, run by melatonind after / is writable.
#
# rootful means the jailbreak root is /: no /var/jb prefix anywhere. MELA_ROOT
# exists so a rootless port flips one variable and every path below follows.
set -e
ROOT=${MELA_ROOT:-}

mkdir -p "$ROOT/usr/bin" "$ROOT/usr/libexec" "$ROOT/usr/lib" "$ROOT/var/lib/dpkg"

if [ -f /tmp/sileo.tar.gz ]; then
    tar -xzf /tmp/sileo.tar.gz -C "${ROOT:-/}"
fi
if [ -f /tmp/libhooker.deb ]; then
    dpkg -i --root="${ROOT:-/}" /tmp/libhooker.deb || true
fi

mkdir -p /etc/apt
if [ -d "$ROOT/etc/apt" ]; then
    cp -a "$ROOT/etc/apt/." /etc/apt/ 2>/dev/null || true
fi

echo "bootstrap laid at ${ROOT:-/}"
if [ -x "$ROOT/usr/libexec/sshd" ]; then
    echo "sshd: root@127.0.0.1 -p 2222"
fi
