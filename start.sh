#!/usr/bin/env sh
# ---------------------------------------------------------------------------
# ObscuraLens one-command launcher.
#
#   ./start.sh                     -> create .venv (first run), install deps,
#                                     start the web UI and open the browser
#   ./start.sh --no-browser        -> same, without opening a browser
#   ./start.sh --port 9000         -> listen on another port
#   ./start.sh --host 0.0.0.0      -> bind on all interfaces
#   ./start.sh --cli ...           -> pass through to the CLI instead
#                                     (e.g. ./start.sh --cli ip 8.8.8.8)
#   ./start.sh --reset             -> recreate the virtualenv from scratch
#
# Everything after the flags above is forwarded to `obscuralens` when --cli
# is used. First run needs internet access for pip; later runs start in
# seconds. Data (history, cases, watchlist, cache) lives under ./data and
# survives restarts.
# ---------------------------------------------------------------------------
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$root"

venv="$root/.venv"
stamp="$venv/.obscuralens-deps-v5"
python="$venv/bin/python"
[ -n "${PYTHON:-}" ] && create_with="$PYTHON" || create_with="python3"

port="${OBSCURALENS_PORT:-8000}"
host="${OBSCURALENS_HOST:-127.0.0.1}"
open_browser=1
mode=web
cli_args=""

say() { printf '\033[36m[obscuralens]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[obscuralens] error:\033[0m %s\n' "$*" >&2; exit 1; }

# ---- parse arguments ------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --no-browser) open_browser=0 ;;
        --port)       [ $# -ge 2 ] || die "--port needs a value"; port="$2"; shift ;;
        --port=*)     port="${1#*=}" ;;
        --host)       [ $# -ge 2 ] || die "--host needs a value"; host="$2"; shift ;;
        --host=*)     host="${1#*=}" ;;
        --cli)        mode=cli ;;
        --reset)      rm -rf "$venv"; say "removed $venv — it will be rebuilt" ;;
        -h|--help)    sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)            cli_args="$cli_args $(printf '%q' "$1")" ;;
    esac
    shift
done

# ---- sanity ----------------------------------------------------------------
command -v "$create_with" >/dev/null 2>&1 \
    || die "no python3 found — install Python 3.9+ first (https://python.org)"

if [ ! -x "$python" ]; then
    say "creating virtual environment in .venv (first run)…"
    "$create_with" -m venv "$venv" \
        || die "could not create .venv (pip/venv missing? try: $create_with -m pip install --user virtualenv)"
    # venv bootstrapping on Debian/Ubuntu needs pip itself sometimes
    "$python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
fi

# ---- dependencies (skipped when the stamp is fresh) ------------------------
if [ ! -f "$stamp" ]; then
    say "installing dependencies (first run only — this can take a minute)…"
    "$python" -m pip install --quiet --disable-pip-version-check \
        requests phonenumbers PyYAML tabulate jinja2 \
        fastapi uvicorn "python-multipart>=0.0.9" \
        || die "pip install failed — check your internet connection / proxy"
    # Optional niceties: charts + PDF reports. Failures are non-fatal.
    "$python" -m pip install --quiet --disable-pip-version-check \
        matplotlib numpy wordcloud reportlab >/dev/null 2>&1 || \
        say "optional chart/report packages skipped (web UI works without them)"
    touch "$stamp"
else
    say "dependencies already installed — remove .venv/.obscuralens-deps-v5 to force a refresh"
fi

export OBSCURALENS_CONFIG_DIR="${OBSCURALENS_CONFIG_DIR:-$root/config}"
mkdir -p "$root/data" "$root/reports" "$root/config"

# ---- launch ----------------------------------------------------------------
if [ "$mode" = "cli" ]; then
    if [ -n "$cli_args" ]; then
        # shellcheck disable=SC2086
        exec "$python" -m obscuralens $cli_args
    fi
    exec "$python" -m obscuralens
fi

url="http://$host:$port"
say "starting ObscuraLens web UI on $url"
say "press Ctrl+C to stop · data stays in ./data"

if [ "$open_browser" = "1" ]; then
    (
        sleep 1.5
        command -v xdg-open >/dev/null 2>&1 && xdg-open "$url" >/dev/null 2>&1 || true
        command -v open     >/dev/null 2>&1 && open "$url" >/dev/null 2>&1 || true
    ) &
fi

exec "$python" -m obscuralens serve --host "$host" --port "$port" --open
