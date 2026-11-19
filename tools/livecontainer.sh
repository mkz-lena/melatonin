#!/bin/sh
# push an unsigned .app into LiveContainer and leave it tappable.
#
# LiveContainer re-signs guest apps with its own certificate, so this is the
# one on-device execution channel that does not need a developer identity or a
# Mac. it is how melatonin's own UI reaches the phone.
#
# usage: tools/livecontainer.sh [--rm] <App.app>
set -e

BID=${LIVE_BUNDLE:-com.kdt.livecontainer.Y7855LPY79}
RM=0
[ "$1" = "--rm" ] && { RM=1; shift; }
[ -n "$1" ] && [ -d "$1" ] || { echo "usage: $0 [--rm] <App.app>"; exit 2; }

APP=$(basename "$1")
DEST="Applications/$APP"

if ! timeout 10 idevice_id -l 2>/dev/null | grep -q .; then
    echo "no device on usbmuxd; plug the phone in and unlock it"
    exit 1
fi

if [ "$RM" = 1 ]; then
    timeout 30 pymobiledevice3 apps rm --documents "$BID" "$DEST" 2>/dev/null || true
fi

timeout 120 pymobiledevice3 apps push --documents "$BID" "$1" "$DEST"
echo "pushed $DEST"
echo "open LiveContainer and tap ${APP%.app}"
