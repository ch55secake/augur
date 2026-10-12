#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
sh -n "$ROOT/scripts/install.sh"
sh -n "$ROOT/scripts/install-macos.sh"
"$ROOT/scripts/install.sh" --help >/dev/null
"$ROOT/scripts/install-macos.sh" --help >/dev/null
"$ROOT/scripts/install.sh" --version invalid >/dev/null 2>&1 && exit 1 || true
echo "installer script checks passed"
