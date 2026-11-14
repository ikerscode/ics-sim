#!/usr/bin/env bash
# Containerised network mode (optional; ./run.sh is the normal in-process mode).
#   ./netmode.sh verify   build the image, start the stack, replay every scenario's Modbus
#                         traffic through the gateway, compare decisions, stop the stack
#   ./netmode.sh up       build and start; PLC HUD on http://127.0.0.1:8124/
#   ./netmode.sh down     stop and remove the containers
umask 077
set -euo pipefail
cd "$(dirname "$0")"
PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
# Builds and runs share the lab-wide CPU lock and low priority so they never pile up.
LOCK="${XDG_RUNTIME_DIR:-/tmp}/seclab-cpu.lock"
quiet() { flock "$LOCK" nice -n 19 env OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 "$@"; }
COMPOSE=(docker compose -f deploy/compose.yml -p ics-sim-net)
case "${1:-verify}" in
  verify) quiet "$PY" -m icssim netmode verify ;;
  up)     quiet "${COMPOSE[@]}" build && "${COMPOSE[@]}" up -d && echo "PLC HUD: http://127.0.0.1:8124/" ;;
  down)   "${COMPOSE[@]}" down --remove-orphans ;;
  *)      echo "usage: $0 verify|up|down" >&2; exit 2 ;;
esac
