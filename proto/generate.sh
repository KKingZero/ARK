#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUT_DIR="$PROJECT_ROOT/pkg/pb"

mkdir -p "$OUT_DIR"

protoc \
  --proto_path="$SCRIPT_DIR" \
  --go_out="$OUT_DIR" \
  --go_opt=paths=source_relative \
  --go-grpc_out="$OUT_DIR" \
  --go-grpc_opt=paths=source_relative \
  "$SCRIPT_DIR"/c2.proto \
  "$SCRIPT_DIR"/listener.proto \
  "$SCRIPT_DIR"/api.proto

python3 "$SCRIPT_DIR/gen_c_task_types.py" \
  "$SCRIPT_DIR/c2.proto" \
  "$PROJECT_ROOT/cimplant/include/ark/pb_task_types.h"

echo "Protobuf generation complete: $OUT_DIR"
