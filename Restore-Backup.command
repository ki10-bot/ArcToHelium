#!/bin/bash
# ---------------------------------------------------------------------------
#  Emergency: restore Helium cookies to the state before the last migration.
#  Just double-click. Automatically uses the newest backup.
# ---------------------------------------------------------------------------
set -u
cd "$HOME" 2>/dev/null || cd /

echo "=================================================================="
echo "  ARC -> HELIUM  |  Restore backup"
echo "=================================================================="

SUP="$HOME/Library/Application Support/ArcToHelium/Backups"
latest=""
if [ -d "$SUP" ]; then
    for d in "$SUP"/*/; do
        [ -d "${d}Helium-before" ] && latest="$d"
    done
fi

if [ -z "$latest" ]; then
    echo ""
    echo "  No backup found under:"
    echo "  $SUP"
    echo ""
    sleep 4
    exit 1
fi
echo "  Using: $latest"
echo ""

# Quit Helium (without Apple Events / without a permission dialog)
pids=$(/bin/ps -axww -o pid=,command= 2>/dev/null | /usr/bin/awk -v me="$$" \
      '$1 != me && tolower($0) ~ /helium\.app\/contents\/macos\// { print $1 }')
if [ -n "$pids" ]; then
    echo "  Quitting Helium ..."
    kill $pids 2>/dev/null || true
    sleep 3
    kill -9 $pids 2>/dev/null || true
fi

SRC="${latest}Helium-before"
n=0
# 1) Main databases; remove existing WAL/SHM at the destination, otherwise
#    Helium would pick up the old state from the WAL on launch.
while IFS= read -r -d '' f; do
    rel="${f#./}"
    case "$rel" in *-wal|*-shm) continue ;; esac
    dest="$HOME/$rel"
    mkdir -p "$(dirname "$dest")" || continue
    rm -f "$dest-wal" "$dest-shm" 2>/dev/null || true
    cp -p "$SRC/$rel" "$dest" && n=$((n + 1))
done < <(cd "$SRC" && /usr/bin/find . -type f -print0)

# 2) Add WAL/SHM files from the backup (if present)
while IFS= read -r -d '' f; do
    rel="${f#./}"
    case "$rel" in *-wal|*-shm) ;; *) continue ;; esac
    dest="$HOME/$rel"
    mkdir -p "$(dirname "$dest")" || continue
    cp -p "$SRC/$rel" "$dest" && n=$((n + 1))
done < <(cd "$SRC" && /usr/bin/find . -type f -print0)

echo ""
if [ "$n" -gt 0 ]; then
    echo "  Done: $n file(s) restored."
    echo "  You can now open Helium as usual."
    RC=0
else
    echo "  ERROR: The backup contained no restorable files."
    RC=1
fi
echo ""
sleep 4
exit "$RC"
