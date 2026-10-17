#!/usr/bin/env bash
set -eu
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
python3 -m compileall -q reworkbench tests scripts
python3 -m unittest discover -s tests -v
if command -v node >/dev/null 2>&1; then
    node --check reworkbench/web/app.js
    node tests/test_frontend.cjs
else
    echo 'Node yok; frontend geliştirme testleri yapılmadı (çalışma zamanı için gerekli değil).'
fi
if command -v ruff >/dev/null 2>&1; then
    ruff format --check reworkbench tests scripts
    ruff check reworkbench tests scripts
else
    echo 'ruff kullanılamıyor; biçim/lint kontrolü yapılmadı.'
fi
