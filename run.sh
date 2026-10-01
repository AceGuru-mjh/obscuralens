#!/usr/bin/env sh
# One-command launcher: creates .venv on first use, installs dependencies,
# then runs ObscuraLens. Examples:
#   ./run.sh
#   ./run.sh ip 8.8.8.8 -f json
#   ./run.sh investigate example.com

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$root"

venv="$root/.venv"
venv_python="$venv/bin/python"

if [ ! -x "$venv_python" ]; then
    echo "Creating virtual environment in .venv ..."
    "${PYTHON:-python3}" -m venv "$venv"
fi

"$venv_python" -m pip install --quiet --upgrade pip
"$venv_python" -m pip install --quiet -r requirements.txt

exec "$venv_python" -m obscuralens "$@"
