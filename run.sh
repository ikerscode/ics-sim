#!/usr/bin/env bash
# Start ics-sim: HUD on http://127.0.0.1:8104/ and Modbus/TCP on 127.0.0.1:5020.
umask 077  # data (captured credentials, samples, intel) is private to this user
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  python3 -m venv --system-site-packages .venv
fi
.venv/bin/pip install -q -r requirements.txt
exec .venv/bin/python -m icssim serve --host 127.0.0.1 --port "${PORT:-8104}"
