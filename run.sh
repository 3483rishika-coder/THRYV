#!/usr/bin/env bash
# One command: ./run.sh  -> http://127.0.0.1:8000
set -e; cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate; pip install -q -r requirements.txt
exec python -m thryv serve
