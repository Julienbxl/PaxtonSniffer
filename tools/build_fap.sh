#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
UFBT=${UFBT:-ufbt}

if [ "$#" -gt 1 ]; then
    printf 'Usage: %s [custom-sdk.zip]\n' "$0" >&2
    exit 2
fi
if [ "$#" -eq 1 ]; then
    "$UFBT" update --hw-target f7 --local "$1"
fi

cd "$ROOT/app"
"$UFBT"
cp dist/paxton_sniffer.fap "$ROOT/PaxtonSniffer.fap"
printf '\nBuilt %s/PaxtonSniffer.fap\n' "$ROOT"
