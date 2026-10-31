#!/usr/bin/env bash
# Usage: make_bootstrap.sh <stopped mainnet datadir> <output dir> [part size, default 1900M]
# Builds innovabootstrap.zip.NNN parts and innovabootstrap.sha256 from a node's chain data.
# Linux only (GNU split and sha256sum).
set -euo pipefail

DATADIR="${1:?datadir required}"
OUT="${2:?output dir required}"
PART="${3:-1900M}"
NAME=innovabootstrap.zip

[ -f "$DATADIR/blk0001.dat" ] && [ -d "$DATADIR/txleveldb" ] || { echo "no chain data in $DATADIR" >&2; exit 1; }
if [ -f "$DATADIR/innovad.pid" ] && kill -0 "$(cat "$DATADIR/innovad.pid")" 2>/dev/null; then
    echo "innovad is running on $DATADIR; stop it first" >&2
    exit 1
fi
DATADIR="$(cd "$DATADIR" && pwd)"
if pgrep -f -- "-datadir=$DATADIR( |/?$)" >/dev/null 2>&1; then
    echo "a node is running on $DATADIR; stop it first" >&2
    exit 1
fi

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
rm -f "$OUT/$NAME" "$OUT/$NAME".[0-9][0-9][0-9] "$OUT/innovabootstrap.sha256"

python3 - "$DATADIR" "$OUT/$NAME" <<'PY'
import os, sys, zipfile
src, dst = sys.argv[1], sys.argv[2]
names = sorted(n for n in os.listdir(src) if n.startswith("blk") and n.endswith(".dat"))
for root, _, files in os.walk(os.path.join(src, "txleveldb")):
    for f in sorted(files):
        if f not in ("LOCK", "LOG", "LOG.old"):
            names.append(os.path.relpath(os.path.join(root, f), src))
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as z:
    for n in names:
        z.write(os.path.join(src, n), n)
PY
(cd "$OUT" && split -b "$PART" -d -a 3 --numeric-suffixes=1 "$NAME" "$NAME.")
(cd "$OUT" && sha256sum "$NAME".[0-9][0-9][0-9] "$NAME" > innovabootstrap.sha256)
rm -f "$OUT/$NAME"

ls -l "$OUT"
