# Scheduled monitoring

`scripts/scheduled_check.py` looks up a list of targets, compares each result
against a JSON snapshot, and reports what changed (new ports, subdomains,
breaches, DNS records, username status, …). It is designed to be driven by any
scheduler and returns:

| exit code | meaning |
|---|---|
| `0` | no changes |
| `1` | changes detected |
| `2` | usage/config error |

```powershell
python scripts/scheduled_check.py `
  --targets watch_targets.txt `
  --state .watch-state.json `
  --report watch-report.json
```

Add `--webhook https://...` to POST the JSON report when something changes.

## Windows Task Scheduler

```powershell
$action  = New-ScheduledTaskAction -Execute "python" `
  -Argument "scripts/scheduled_check.py --targets watch_targets.txt --state .watch-state.json" `
  -WorkingDirectory "D:\ObscuraLens"
$trigger = New-ScheduledTaskTrigger -Daily -At 6am
Register-ScheduledTask -TaskName "ObscuraLens watch" -Action $action -Trigger $trigger
```

## cron (Linux/macOS)

```cron
0 6 * * * cd /opt/ObscuraLens && /usr/bin/python3 scripts/scheduled_check.py --targets watch_targets.txt --state .watch-state.json >> /var/log/obscuralens-watch.log 2>&1
```

## systemd timer

`/etc/systemd/system/obscuralens-watch.service`:

```ini
[Unit]
Description=ObscuraLens watchlist check

[Service]
Type=oneshot
WorkingDirectory=/opt/ObscuraLens
ExecStart=/usr/bin/python3 scripts/scheduled_check.py --targets watch_targets.txt --state .watch-state.json
```

`/etc/systemd/system/obscuralens-watch.timer`:

```ini
[Unit]
Description=Run the ObscuraLens watchlist check daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Then `systemctl enable --now obscuralens-watch.timer`.

## GitHub Actions

`.github/workflows/watch.yml` runs the same script daily (and on demand from
the Actions tab), caches the state file between runs, uploads the report as an
artifact and opens an issue when a change is detected. Edit `watch_targets.txt`
to choose what is monitored.
