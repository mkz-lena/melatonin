#!/usr/bin/env bash
# wiki_push.sh - publish wiki/ to the GitHub wiki.
#
# usage: tools/wiki_push.sh [message]
#
# the wiki git repo (melatonin.wiki.git) only exists once a first page has been
# created through the web UI. if this script fails with "Repository not found",
# open https://github.com/mkz-lena/melatonin/wiki once and click
# "Create the first page" (any title, any body), then run this script again.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
src=$root/wiki
remote=${WIKI_REMOTE:-git@github.com:mkz-lena/melatonin.wiki.git}
msg=${1:-"update wiki"}

[ -d "$src" ] || { echo "no $src"; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if GIT_SSH_COMMAND="ssh -o BatchMode=yes" git clone -q "$remote" "$work/wiki" 2>/dev/null; then
    :
else
    echo "wiki repo not found yet - create the first page through the web UI first:"
    echo "  https://github.com/mkz-lena/melatonin/wiki"
    exit 1
fi

# mirror wiki/ into the checkout, removing stale pages
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "$src/" "$work/wiki/"
else
    find "$work/wiki" -mindepth 1 -maxdepth 1 -type f -name '*.md' -delete
    cp -a "$src/." "$work/wiki/"
fi

cd "$work/wiki"
git config user.name "lena"
git config user.email "mkz-lena@users.noreply.github.com"
git add -A
if git diff --cached --quiet; then
    echo "nothing to push"
    exit 0
fi
git commit -q -m "$msg"
GIT_SSH_COMMAND="ssh -o BatchMode=yes" git push -q
echo "pushed wiki"
