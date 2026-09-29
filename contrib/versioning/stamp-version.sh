#!/bin/bash
# Writes A.B.C.D into every file that carries the release version.
# usage: contrib/versioning/stamp-version.sh 5.0.1.0
set -euo pipefail
v="${1:?usage: stamp-version.sh A.B.C.D}"
[[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || { echo "not A.B.C.D: $v" >&2; exit 1; }
A=${BASH_REMATCH[1]} B=${BASH_REMATCH[2]} C=${BASH_REMATCH[3]} D=${BASH_REMATCH[4]}
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
sed -i.bak -E "s/^(snapshot|release|candidate)-version=.*/\1-version=$v/" build.properties
sed -i.bak -E "s/^(#define CLIENT_VERSION_MAJOR +)[0-9]+/\1$A/; s/^(#define CLIENT_VERSION_MINOR +)[0-9]+/\1$B/; s/^(#define CLIENT_VERSION_REVISION +)[0-9]+/\1$C/; s/^(#define CLIENT_VERSION_BUILD +)[0-9]+/\1$D/" src/clientversion.h
sed -i.bak -E "s/^VERSION = .*/VERSION = $v/" innova-qt.pro
sed -i.bak -E "s/^(project\(Innova VERSION )[0-9.]+/\1$A.$B.$C/" CMakeLists.txt
sed -i.bak -E "s/^version: '.*'/version: '$v'/" snapcraft.yaml
rm -f build.properties.bak src/clientversion.h.bak innova-qt.pro.bak CMakeLists.txt.bak snapcraft.yaml.bak
echo "stamped $v"
