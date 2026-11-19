#!/usr/bin/env bash
# device.sh - read the exact build off a connected iPhone, and show what Apple
# still signs for it. no jailbreak, no pairing tricks: lockdown only.
#
#   tools/device.sh          # version, build, product type
#   tools/device.sh fw       # full firmware table for this model
#   tools/device.sh fw 27    # filter by version prefix
#
# requires: usbmuxd (running), libimobiledevice or pymobiledevice3.
set -u

say() { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

ensure_usbmuxd() {
    [ -S /var/run/usbmuxd ] && return 0
    if have systemctl; then
        sudo -n systemctl start usbmuxd 2>/dev/null && sleep 1 && return 0
    fi
    if have usbmuxd; then
        sudo -n usbmuxd -f -u >/dev/null 2>&1 &
        sleep 1
        [ -S /var/run/usbmuxd ] && return 0
    fi
    say "usbmuxd is not running. start it once:  sudo systemctl start usbmuxd" >&2
    return 1
}

lockdown() {
    # $1 = key
    if have ideviceinfo; then
        ideviceinfo -k "$1" 2>/dev/null && return 0
    fi
    if have pymobiledevice3; then
        pymobiledevice3 lockdown info --key "$1" 2>/dev/null && return 0
    fi
    return 1
}

info() {
    ensure_usbmuxd || return 1
    local ver build model name
    ver=$(lockdown ProductVersion)   || { say "no device (plug in, unlock, trust this computer)" >&2; return 1; }
    build=$(lockdown BuildVersion)   || build="?"
    model=$(lockdown ProductType)    || model="?"
    name=$(lockdown DeviceName)      || name="iPhone"

    say "device   $name"
    say "model    $model"
    say "ios      $ver"
    say "build    $build"

    if [[ "$build" == 24A5* ]]; then
        say "note     beta-cycle build (24A5xx). not a public release: it predates"
        say "         27.0.1 and every 27.2 fix. treat it as the target."
    elif [[ "$build" == 24A4* ]]; then
        say "note     public 27.0.x build. 27.2 fixes still absent."
    else
        say "note     not a 27.0.x build."
    fi

    if have python3; then
        python3 - "$model" "$build" <<'PY'
import json, sys, urllib.request
model, build = sys.argv[1], sys.argv[2]
try:
    d = json.load(urllib.request.urlopen(
        f"https://api.ipsw.me/v4/device/{model}?type=ipsw", timeout=20))
except Exception:
    sys.exit(0)
for f in d.get("firmwares", []):
    if f["buildid"] == build:
        print(f"match    {f['version']} {f['buildid']} signed={f['signed']}")
        print(f"url      {f['url']}")
        break
else:
    print("match    none - the connected build is not a public IPSW")
PY
    fi
}

firmware() {
    local want="${1:-}" model
    model=${MELA_MODEL:-}
    if [ -z "$model" ]; then
        ensure_usbmuxd >/dev/null 2>&1 && model=$(lockdown ProductType 2>/dev/null)
    fi
    [ -z "$model" ] && model="iPhone17,5"
    say "firmware for $model (override with MELA_MODEL=...)"
    python3 - "$model" "$want" <<'PY'
import json, sys, urllib.request
model, want = sys.argv[1], sys.argv[2]
d = json.load(urllib.request.urlopen(
    f"https://api.ipsw.me/v4/device/{model}?type=ipsw", timeout=30))
for f in d.get("firmwares", []):
    if want and not f["version"].startswith(want):
        continue
    print(f"{f['version']:<10} {f['buildid']:<10} "
          f"{'signed' if f['signed'] else 'unsigned':<9} "
          f"{f['releasedate'][:10]}  {f['filesize']/1e9:.1f}G")
PY
}

dev() {
    ensure_usbmuxd || return 1
    if ! have pymobiledevice3; then
        say "needs pymobiledevice3"; return 1
    fi
    say "developer surface"
    timeout 40 pymobiledevice3 mounter list 2>/dev/null \
        | python3 -c '
import json, sys
try:
    imgs = json.load(sys.stdin)
except Exception:
    print("  ddi        unknown"); raise SystemExit
hit = [i for i in imgs if i.get("MountPath") == "/System/Developer"]
if not hit:
    print("  ddi        not mounted (developer mode off, or never paired)")
    raise SystemExit
i = hit[0]
kind = i.get("DiskImageType", "?")
mode = "ro" if i.get("IsReadOnly") else "rw"
print(f"  ddi        {kind}, {mode}, /System/Developer")
' 2>/dev/null
    if timeout 30 pymobiledevice3 developer dvt proclist >/dev/null 2>&1; then
        n=$(timeout 30 pymobiledevice3 developer dvt proclist 2>/dev/null \
            | grep -c '"pid"')
        say "  dvt        responding, ${n:-?} processes"
    else
        say "  dvt        not responding"
    fi
}

case "${1:-info}" in
    info|"") info ;;
    fw|firmware) shift; firmware "${1:-}" ;;
    dev) dev ;;
    *) say "usage: $0 [info|dev|fw [version-prefix]]"; exit 2 ;;
esac
