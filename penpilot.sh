#!/usr/bin/env bash
# Keep the caller's working directory: relative output belongs to the caller.
set -euo pipefail
launcher_source="$(readlink -f -- "${BASH_SOURCE[0]}")"
project_root="$(dirname -- "$launcher_source")"
python_bin="$project_root/.venv/bin/python"
if [[ ! -x "$python_bin" ]]; then
    python_bin="$(command -v python3 || true)"
fi
if [[ -z "$python_bin" ]]; then
    echo 'Erro: Python 3.11+ não encontrado.' >&2
    exit 1
fi
export PYTHONPATH="$project_root${PYTHONPATH:+:$PYTHONPATH}"
exec "$python_bin" -m penpilot "$@"
