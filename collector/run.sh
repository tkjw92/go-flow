#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="$SCRIPT_DIR"
INGEST_ARGS=("$@")

"$RUNTIME_DIR/bin/goflow2" \
  -listen 'netflow://:2055' \
  -transport.file.sep= \
  -format=bin |
"$RUNTIME_DIR/bin/enricher" \
  -db.asn "$RUNTIME_DIR/db/asn.mmdb" \
  -db.country "$RUNTIME_DIR/db/country.mmdb" |
(
  cd "$SCRIPT_DIR"
  if [[ -x "$RUNTIME_DIR/ingest" ]]; then
    exec "$RUNTIME_DIR/ingest" "${INGEST_ARGS[@]}"
  fi
  exec go run . "${INGEST_ARGS[@]}"
)
