#!/usr/bin/env python3
"""
Scheduled watchlist check for cron, Task Scheduler or GitHub Actions.

Reads targets from a file, looks each one up, compares the flatten()-ed result
against a JSON state file and reports what changed. Snapshot state persists in
the state file between runs (which is what makes diffing work off a workstation).

Usage:
    python scripts/scheduled_check.py --targets watch_targets.txt \
        --state .watch-state.json --report watch-report.json \
        [--webhook https://example/hook]

Exit codes: 0 = no changes, 1 = changes detected, 2 = usage/config error.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from obscuralens.investigate import detect_kind  # noqa: E402
from obscuralens.trackers import (  # noqa: E402
    DomainTracker,
    EmailTracker,
    IPTracker,
    PhoneTracker,
    UsernameTracker,
)
from obscuralens.watchlist import diff_snapshots, flatten  # noqa: E402

TRACKERS = {
    'ip': IPTracker,
    'phone': PhoneTracker,
    'username': UsernameTracker,
    'email': EmailTracker,
    'domain': DomainTracker,
}


def read_targets(path: str):
    """Read one target per line; blank lines and # comments are ignored."""
    targets = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        value = line.split('#', 1)[0].strip()
        if value:
            targets.append(value)
    return targets


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Scheduled watchlist check')
    parser.add_argument('--targets', required=True,
                        help='file with one target per line (# comments allowed)')
    parser.add_argument('--state', default='.watch-state.json',
                        help='JSON snapshot file (default: .watch-state.json)')
    parser.add_argument('--report', help='write the JSON report to this file')
    parser.add_argument('--webhook', help='POST the report to this URL on changes')
    args = parser.parse_args(argv)

    targets_path = Path(args.targets)
    if not targets_path.exists():
        print(f"targets file not found: {targets_path}", file=sys.stderr)
        return 2
    targets = read_targets(args.targets)
    if not targets:
        print('no targets found in file', file=sys.stderr)
        return 2

    state_path = Path(args.state)
    state = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding='utf-8'))
        except ValueError:
            print('state file is not valid JSON; starting fresh', file=sys.stderr)

    new_state = dict(state)
    results = []
    changes = []

    for target in targets:
        kind = detect_kind(target)
        if kind is None:
            print(f"skip: cannot determine target type for {target!r}",
                  file=sys.stderr)
            continue
        try:
            result = TRACKERS[kind]().track(target)
        except Exception as e:  # one bad target must not stop the run
            print(f"error: {target}: {type(e).__name__}: {e}", file=sys.stderr)
            continue

        fields = flatten(result)
        old = (state.get(target) or {}).get('fields', {})
        first_run = not old
        added, removed, changed = (
            ({}, {}, {}) if first_run else diff_snapshots(old, fields))
        new_state[target] = {'kind': kind, 'fields': fields}

        entry = {
            'target': target,
            'kind': kind,
            'first_run': first_run,
            'success': bool(result.get('success', True)),
            'added': added,
            'removed': removed,
            'changed': changed,
        }
        results.append(entry)
        if not first_run and (added or removed or changed):
            changes.append(entry)
            print(f"[changed] {target} (+{len(added)} -{len(removed)} "
                  f"~{len(changed)})", file=sys.stderr)
        else:
            print(f"[ok] {target}"
                  + (" (first run)" if first_run else ""), file=sys.stderr)

    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(new_state, indent=2, sort_keys=True),
                          encoding='utf-8')

    report = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'targets': targets,
        'change_count': len(changes),
        'changes': changes,
        'results': results,
    }
    if args.report:
        Path(args.report).write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str),
            encoding='utf-8')

    if changes and args.webhook:
        try:
            import requests
            requests.post(args.webhook, json=report, timeout=30)
        except Exception as e:
            print(f"webhook failed: {type(e).__name__}: {e}", file=sys.stderr)

    return 1 if changes else 0


if __name__ == '__main__':
    sys.exit(main())
