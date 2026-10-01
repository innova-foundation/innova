#!/bin/bash
# Replace ~/.innova chain data with the published bootstrap. Wallet files are kept.
set -uo pipefail

DATADIR="${INNOVA_DATADIR:-$HOME/.innova}"
LATEST="https://github.com/innova-foundation/innova/releases/latest/download/innovabootstrap.zip"
LEGACY="https://github.com/innova-foundation/innova/releases/download/v4.3.9.5/innovabootstrap.rar"
WORK=$(mktemp -d)

echo "Downloading bootstrap"
if curl -fsSL -o "$WORK/innovabootstrap.zip" "$LATEST"; then
    ARCHIVE="$WORK/innovabootstrap.zip"
else
    echo "No bootstrap on the latest release; using the v4.3.9.5 archive"
    curl -fsSL -o "$WORK/innovabootstrap.rar" "$LEGACY" || { echo "download failed" >&2; exit 1; }
    ARCHIVE="$WORK/innovabootstrap.rar"
fi

if command -v innovad >/dev/null 2>&1; then
    innovad -datadir="$DATADIR" stop >/dev/null 2>&1 && sleep 15
fi

echo "Cleaning chain data in $DATADIR"
mkdir -p "$DATADIR"
rm -rf "$DATADIR/database" "$DATADIR/smsgDB" "$DATADIR/txleveldb"
rm -f "$DATADIR"/blk0001.dat "$DATADIR"/banlist.dat "$DATADIR"/innovanamesindex.dat \
      "$DATADIR"/peers.dat "$DATADIR"/smsg.ini

echo "Extracting bootstrap"
case "$ARCHIVE" in
    *.zip) sudo apt-get install -y unzip >/dev/null; unzip -q -o "$ARCHIVE" -d "$WORK/x" ;;
    *.rar) sudo apt-get install -y unrar >/dev/null; mkdir -p "$WORK/x"; (cd "$WORK/x" && unrar x -r -o+ "$ARCHIVE" >/dev/null) ;;
esac
src="$WORK/x"; [ -d "$WORK/x/innovabootstrap" ] && src="$WORK/x/innovabootstrap"
cp -a "$src"/. "$DATADIR"/
rm -rf "$WORK"

echo "Bootstrap installed. Start the node with: innovad -daemon"
