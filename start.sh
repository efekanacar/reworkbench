#!/usr/bin/env bash
set -eu
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
rewb_python=python3
if [ -x .venv/bin/python ]; then
    rewb_python=.venv/bin/python
fi
exec "$rewb_python" -m reworkbench.webapp "$@"
