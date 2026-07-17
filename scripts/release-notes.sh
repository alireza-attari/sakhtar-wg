#!/bin/sh
set -eu

TAG=${1:?usage: scripts/release-notes.sh vX.Y.Z}
VERSION=${TAG#v}
awk -v heading="## [$VERSION]" '
  index($0, heading) == 1 { found=1; next }
  found && /^## \[/ { exit }
  found && /^\[[^]]+\]:/ { exit }
  found { print }
' CHANGELOG.md
