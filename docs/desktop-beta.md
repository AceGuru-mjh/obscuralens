# ObscuraLens Desktop Beta

The desktop edition packages the whole of ObscuraLens -- the 14-kind
investigation engine, the analyst toolbox, the local web UI and the full
CLI -- into **one portable executable per platform**. No Python
installation, no `pip`, no virtualenv, no admin rights: download the file,
run it, and a browser window opens the same single-page web UI that
`obscuralens serve` would give you, served from a loopback-only web server
inside the exe. The same binary is also the complete command-line client,
so scriptable use and the desktop experience ship in one download.

This is a **beta pre-release program**. The binaries are unsigned, the
feature set may still move, and we would rather ship early and fix things
than polish silently. If something breaks, [tell
us](#feedback) -- the `--diagnostics` report (see
[Diagnostics](#diagnostics)) exists precisely so bug reports carry enough
context to act on.

Related documentation: [README.md](../README.md) for the general platform
tour, [docs/api.md](api.md) for the REST API the desktop web UI exposes,
[docs/web-ui.md](web-ui.md) for the UI itself, [docs/v5.1.md](v5.1.md) for
the release notes of the version you are running.

## Contents

- [Downloading](#downloading)
- [Installing](#installing)
- [First run](#first-run)
- [The desktop launcher reference](#the-desktop-launcher-reference)
- [Single-instance behavior](#single-instance-behavior)
- [Update checks](#update-checks)
- [Diagnostics](#diagnostics)
- [What is inside the executable](#what-is-inside-the-executable)
- [Troubleshooting](#troubleshooting)
- [Security and privacy](#security-and-privacy)
- [FAQ](#faq)
- [Feedback](#feedback)

## Downloading

All desktop builds are published on the GitHub releases page:

<https://github.com/AceGuru-mjh/obscuralens/releases>

Every tagged beta release carries the same asset set:

| Asset | Platform | Notes |
|---|---|---|
| `ObscuraLens-<version>-win-x64.exe` | Windows 10/11, 64-bit | the primary desktop beta artifact; single-file PyInstaller exe |
| `ObscuraLens-<version>-linux-x64` | Linux, x86-64, glibc | convenience binary; `chmod +x` before running |
| `ObscuraLens-<version>-macos-arm64` | macOS 13+ on Apple Silicon | convenience binary; no `.app` bundle, run from a terminal |
| `checksums.sha256` | all | SHA-256 digests for every asset in that release, one line per file |

For the first beta, `<version>` is `5.1.0-beta.1`, so the Windows asset is
`ObscuraLens-5.1.0-beta.1-win-x64.exe` and its download URL looks like:

```text
https://github.com/AceGuru-mjh/obscuralens/releases/download/v5.1.0-beta.1/ObscuraLens-5.1.0-beta.1-win-x64.exe
```

Asset names are produced by `obscuralens.desktop.channel.asset_name()`
(`ObscuraLens-<version>-<platform><ext>`); Windows assets carry the `.exe`
suffix, Linux and macOS assets carry none.

### Tagged betas vs the nightly channel

Two separate workflows publish desktop builds, and they serve different
purposes:

| | Tagged beta | Nightly |
|---|---|---|
| Workflow | `desktop-beta.yml` | `desktop-nightly.yml` |
| Trigger | pushing a tag matching `v*-beta*` (or manual dispatch) | schedule, every day at **03:00 UTC** |
| Source | the tagged commit | the default branch tip |
| Platforms | win-x64, linux-x64, macos-arm64 (3-way matrix) | Windows x64 only |
| GitHub release | one pre-release per tag (`v5.1.0-beta.1`) | one rolling pre-release under the `nightly` tag |
| Asset names | `ObscuraLens-<version>-<platform>` | `ObscuraLens-nightly-<YYYYMMDD>-<commit7>-win-x64.exe` |
| Audience | beta testers | testing only; prefer tagged betas for anything serious |

The nightly release is *refreshed*, not appended: each night's build
replaces the previous asset on the rolling `nightly` tag, and the asset
name embeds the build date and the first seven characters of the commit SHA
so you can always tell which nightly you have. Nightlies track `main` and
may be less stable than beta or stable builds -- the release notes on the
nightly page say the same thing.

### Verifying the download

Each release ships `checksums.sha256`. Verify the file you downloaded
against it before running anything:

```powershell
# Windows (PowerShell)
Get-FileHash .\ObscuraLens-5.1.0-beta.1-win-x64.exe -Algorithm SHA256
# compare with the matching line in checksums.sha256
```

```bash
# Linux
sha256sum ObscuraLens-5.1.0-beta.1-linux-x64

# macOS
shasum -a 256 ObscuraLens-5.1.0-beta.1-macos-arm64
```

This matters more than usual here because the binaries are **not code
signed** (see the [FAQ](#are-the-binaries-signed)); the checksum is the
only cryptographic statement that the bytes you have are the bytes the
build produced.

## Installing

There is no installer. The executable is self-contained: put it anywhere
you like (a `Tools` folder, `Downloads`, a USB stick) and run it. The
sections below cover the per-OS quirks.

### Windows

1. Download `ObscuraLens-<version>-win-x64.exe` from the release page.
2. Open PowerShell or Windows Terminal in the folder holding the download
   (in Explorer: *File > Open Windows PowerShell*, or shift-right-click >
   *Open PowerShell window here*).
3. Run it:

   ```powershell
   .\ObscuraLens-5.1.0-beta.1-win-x64.exe desktop
   ```

   Your browser opens the local web UI at <http://127.0.0.1:8000>.

**SmartScreen, "unknown publisher".** The first launch will almost
certainly be blocked by Windows SmartScreen with a *"Windows protected
your PC"* dialog, because the binary is unsigned. That is expected, not an
attack indicator by itself. To proceed: click **More info**, then **Run
anyway**. Before doing that, verify the SHA-256 checksum as shown above so
you know the file matches the release. Why unsigned? Code-signing
certificates for Windows require a paid, identity-verified organizational
certificate; a hobby OSINT project does not carry one, and self-signed
signatures would change nothing about the SmartScreen verdict. This is the
trade-off of the beta program -- the checksum is the compensating control,
and the build is reproducible from source (`pyinstaller
scripts/obscuralens.spec`) if you prefer to build your own.

### Linux

```bash
chmod +x ObscuraLens-5.1.0-beta.1-linux-x64
./ObscuraLens-5.1.0-beta.1-linux-x64 desktop
```

The binary is built on GitHub's Ubuntu runner with Python 3.12, so it
needs a reasonably recent glibc. If you see an error like:

```text
version `GLIBC_2.3x' not found
```

your distribution is older than the build environment; fall back to the
pip route (`pip install obscuralens[web]`) or Docker, both documented in
the [README](../README.md#installation).

### macOS

The beta ships an **arm64** (Apple Silicon) binary only.

```bash
chmod +x ObscuraLens-5.1.0-beta.1-macos-arm64
./ObscuraLens-5.1.0-beta.1-macos-arm64 desktop
```

**Gatekeeper.** A downloaded, unsigned binary is quarantined; the first
run is refused with *"cannot be opened because the developer cannot be
verified"*. Remove the quarantine attribute (this is the standard, minimal
fix -- do it only after verifying the checksum):

```bash
xattr -d com.apple.quarantine ./ObscuraLens-5.1.0-beta.1-macos-arm64
```

Alternatively right-click the file and choose *Open* once, which presents
a bypass dialog. **Rosetta is not needed**: the binary is native arm64.
Intel Macs are not part of the beta (see the [FAQ](#is-there-a-build-for-macos-intel-or-windows-32-bit)).

## First run

### Starting the desktop UI

From the folder holding the executable:

```powershell
.\ObscuraLens-5.1.0-beta.1-win-x64.exe desktop        # Windows
```

```bash
./ObscuraLens-5.1.0-beta.1-linux-x64 desktop          # Linux / macOS
```

(`desktop` is the CLI subcommand that routes into the desktop launcher;
the pip-installed equivalent is the `obscuralens-desktop` console script.)
What happens, in order:

1. **Banner.** A pure-ASCII splash box prints the logo, the version, the
   channel badge (`[ BETA CHANNEL ]`) and the beta disclaimer. ASCII only,
   so it renders on a stock `cmd.exe`.
2. **Single-instance lock.** A `desktop.lock` file is created in your
   ObscuraLens config directory. If another desktop instance is already
   running, this one prints the running instance's URL and exits `0`
   without starting anything (details in [Single-instance
   behavior](#single-instance-behavior)).
3. **Port probe.** The launcher probes TCP ports starting at 8000 and
   walking up to 8020. Each candidate is probed with a real `bind(2)` --
   deliberately *without* `SO_REUSEADDR`, so a socket sitting in TIME_WAIT
   still counts as taken -- and the probe socket is closed again. The
   first bindable port wins; if all 21 are busy the launcher exits `1`
   with a message telling you to pass `--port`.
4. **Staged startup lines.** Five splash lines print, one per stage:
   `init` (loading the desktop runtime), `config` (reading configuration
   and API keys), `data-packs` (checking offline data packs),
   `web-server` (starting the local web server), `browser` (opening the
   web UI).
5. **Server boot.** The FastAPI app is built and handed to uvicorn on a
   daemon thread (log level `warning`, access log off). If the optional
   web stack is unavailable -- only possible in a plain Python install,
   never in the exe -- the launcher prints a friendly
   `pip install "obscuralens[web]"` hint instead of a traceback and exits
   `1`.
6. **Readiness poll.** The launcher polls
   `http://127.0.0.1:<port>/api/stats` every quarter second for up to 15
   seconds. Any HTTP answer -- even a 4xx/5xx -- counts as ready: it
   proves the server is accepting connections.
7. **Browser.** About one second after readiness, the system browser
   opens <http://127.0.0.1:8000> (or whichever port was picked) in a new
   window. `OBSCURALENS_NO_BROWSER=1` or `--no-browser` suppresses this.
8. **Run.** The terminal prints `Listening on http://127.0.0.1:8000` and
   blocks. **Press `Ctrl+C` in that terminal to stop the desktop app** --
   the server is asked to exit, the lock is released, and the process
   exits `0`.

Exit codes: `0` for a clean shutdown *and* for "another instance is
already running"; `1` when no port is free or the web stack is
unavailable.

If port 8000 was taken by something else, the launcher silently moves to
8001, 8002 ... 8020 -- check the `Listening on` line (or the second
instance's message) for the real URL.

### CLI-only usage

The exe is the full ObscuraLens CLI; you never have to open the browser:

```powershell
.\ObscuraLens-5.1.0-beta.1-win-x64.exe --help
.\ObscuraLens-5.1.0-beta.1-win-x64.exe ip 8.8.8.8 -f json
.\ObscuraLens-5.1.0-beta.1-win-x64.exe investigate example.com --risk
.\ObscuraLens-5.1.0-beta.1-win-x64.exe report domain example.com
```

Every command from the [README](../README.md#ways-to-run) works unchanged
-- the 14 lookups, `investigate`, `risk`, `timeline`, `correlate`, `case`,
`watch`, `pipeline`, `intel`, `tools ...`, `report`, `patterns`, `export`,
`serve` and the rest. Script it in PowerShell, bash or CI exactly as you
would the pip-installed CLI. The desktop-specific commands are:

| Command | What it does |
|---|---|
| `... desktop` | launch the desktop experience (browser UI + local server, runs until Ctrl+C) |
| `... update check` | check GitHub for a newer release on your channel and print a notice |
| `... desktop --diagnostics` | print the full environment report (see [Diagnostics](#diagnostics)) |
| `... desktop --check-update` | same update check, via the launcher's own flag |

## The desktop launcher reference

The launcher (`obscuralens.desktop.launcher`) is driven by one dataclass,
`LaunchOptions`, exposed through the `obscuralens-desktop` console script
and the `desktop` CLI subcommand.

### `LaunchOptions`

| Option | Type / default | Meaning |
|---|---|---|
| `host` | `str`, `"127.0.0.1"` | interface to bind. Loopback only by default, like `serve`. Do not set `0.0.0.0` unless you understand what you are exposing. |
| `port` | `int`, `8000` | preferred TCP port; the first free port at or above it inside `port_range` is used |
| `port_range` | `(int, int)`, `(8000, 8020)` | inclusive probe window for the port search |
| `no_browser` | `bool`, `False` | never open a browser window automatically |
| `open_delay` | `float`, `1.0` | seconds to wait after readiness before opening the browser (gives uvicorn a moment to finish logging) |
| `timeout_ready` | `float`, `15.0` | seconds to wait for the readiness endpoint before printing a "no answer yet" notice |
| `channel` | `Optional[str]`, `None` | release channel to report/check (`stable` / `beta` / `nightly`); `None` uses the package channel |
| `single_instance` | `bool`, `True` | acquire `desktop.lock` before starting |
| `browser` | `Optional[str]`, `None` | browser to open (`firefox`, `chrome`, `chromium`, `edge`, `safari`, `opera`) or `None` for the system default |

From Python (a pip install or your own build):

```python
from obscuralens.desktop import LaunchOptions, launch

launch(LaunchOptions(port=8123, no_browser=True, browser="firefox"))
```

`launch()` never raises; it returns a process exit code (`0` / `1`).

### CLI flags

`obscuralens-desktop` (and `obscuralens desktop`) accept:

| Flag | Default | Meaning |
|---|---|---|
| `--host HOST` | `127.0.0.1` | interface to bind (loopback only) |
| `--port N` | `8000` | preferred port; first free port up to 8020 is used |
| `--no-browser` | off | never open a browser window automatically |
| `--browser NAME` | system default | `firefox`, `chrome`, `chromium`, `edge`, `safari` or `opera` |
| `--channel NAME` | package channel (`beta`) | release channel to report/check (`stable`, `beta`, `nightly`) |
| `--version` | - | print the desktop version (e.g. `ObscuraLens Desktop v5.1.0 (beta channel)`) and exit |
| `--diagnostics` | - | print the full diagnostics report and exit |
| `--check-update` | - | check GitHub for a newer release and exit |

`--version`, `--diagnostics` and `--check-update` short-circuit: nothing
is launched. The update check is informational and always exits `0`.

### Environment variables

| Variable | Effect |
|---|---|
| `OBSCURALENS_NO_BROWSER` | any truthy value (`1`, `yes`, `on` ...) disables automatic browser opening; `0`/`false`/`no`/`off` and unset leave it enabled |
| `OBSCURALENS_CONFIG_DIR` | directory for the desktop lock file, config, history database, cache and reports (defaults below) |
| `OBSCURALENS_REPO_SLUG` | override the GitHub repository the updater talks to -- a bare slug, a `https://github.com/<slug>` URL or a `*.git` clone URL; useful for forks. Invalid values are ignored in favour of `AceGuru-mjh/obscuralens` |
| `OBSCURALENS_DESKTOP_TAG` | override the display tag of this build (`v5.1.0-beta.1` style); the release workflows inject the real tag into tagged builds |
| `OBSCURALENS_NIGHTLY` | marks the running build as a nightly (checked by the branding module alongside the channel value) |
| `NO_COLOR` / `OBSCURALENS_NO_COLOR` | disable the launcher's ANSI colour output (the box drawing itself is pure ASCII either way) |

Default config directories (where `desktop.lock` lives) when
`OBSCURALENS_CONFIG_DIR` is unset:

| OS | Path |
|---|---|
| Windows | `%APPDATA%\ObscuraLens` (falling back to the home directory) |
| macOS | `~/Library/Caches/obscuralens` |
| Linux / other | `$XDG_CACHE_HOME/obscuralens`, else `~/.cache/obscuralens` |

## Single-instance behavior

Two copies of the desktop app racing for the same port, the same SQLite
history database and the same cache directory would produce confusing
behavior, so the launcher refuses to start when another instance is
already running.

Mechanics:

- The lock is a small file, `desktop.lock`, in the config directory (see
  the table above). Creation is atomic: `os.open(path, O_CREAT | O_EXCL |
  O_WRONLY)`.
- A held lock records three lines: the PID, a Unix timestamp, and the URL
  the instance is serving. A second launch reads that file, prints
  something like `ObscuraLens Desktop is already running:
  http://127.0.0.1:8000`, tells you to close the other window, and exits
  `0` -- no error, because nothing is wrong.
- **Stale lock takeover.** A lock is considered stale, and silently
  reclaimed, when:
  - on POSIX, the recorded PID no longer exists (`os.kill(pid, 0)` probe;
    a `PermissionError` means the process exists but belongs to another
    user and is very much alive), or
  - on Windows (which has no reliable PID probe), the lock file has not
    been touched for more than **24 hours**, or
  - the lock file carries no parseable PID and is older than 24 hours.
- Release only deletes the file when it still refers to this process, so
  a lock that was reclaimed by a newer instance is never clobbered.

Manual cleanup, should you ever need it (crash + fresh lock within 24h on
Windows): delete `desktop.lock` from the config directory shown by
`--diagnostics`.

## Update checks

The desktop edition **never auto-downloads anything**. Update checks query
the GitHub Releases API, compare versions, and print a notice; downloading
is always your decision, from your browser.

How a check works:

1. The channel registry (`obscuralens.desktop.channel`) decides which feed
   to ask:
   - `stable` -> `GET /repos/<slug>/releases/latest` (GitHub's endpoint
     that deliberately ignores pre-releases),
   - `beta` -> `GET /repos/<slug>/releases?per_page=20`, then pick the
     first entry that is flagged `prerelease` *and* beta-tagged
     (`v*-beta*`). The list scan exists because `releases/latest` ignores
     pre-releases, so the beta channel cannot use it,
   - `nightly` -> `GET /repos/<slug>/releases/tags/nightly` (the rolling
     nightly tag always has exactly one attached release).
2. The newest tag is compared against the running version with
   pre-release-aware ordering: `5.1.0-beta.1 < 5.1.0`, `beta.10 >
   beta.9` (numeric, not lexicographic), `rc.1 > beta.9` (label rank:
   nightly < dev/alpha < beta < rc), bare `nightly` tags sort below every
   numbered version, and PEP 440 short forms (`5.1.0b1`) equal their long
   forms (`5.1.0-beta.1`).
3. The asset list is scanned for the file matching your platform
   (`ObscuraLens-<version>-win-x64.exe` and friends), and the notice
   prints the version, the download URL, the release page, the publish
   timestamp and a short excerpt of the release notes.

Trigger a check from either surface:

```bash
obscuralens update check                 # CLI subcommand
obscuralens-desktop --check-update       # launcher flag
obscuralens-desktop --check-update --channel nightly
```

From Python: `obscuralens.desktop.check_for_updates()` (never raises,
returns an `UpdateInfo` or `None` with a `.last_error` explanation), or
the `UpdateChecker` class for more control, including an injectable
`fetch` callable so tests never touch the network. The check sends only a
`User-Agent` header (`ObscuraLens-Desktop/<version>`), GitHub's required
API headers, and nothing else.

Offline, the check fails gracefully: a boxed notice explains the reason
("could not reach the update service") and suggests retrying later. It is
never an error exit.

## Diagnostics

```bash
obscuralens-desktop --diagnostics
```

prints a sectioned, pure-ASCII environment report (safe to paste into a
GitHub issue as-is). It is **offline by default**; the optional network
probe only runs when `collect_diagnostics(check_network=True)` is called
from Python. Sections:

| Section | Contents |
|---|---|
| `Python` | interpreter version, implementation, platform, machine, processor, executable path |
| `Application` | product name, package version, channel, frozen-build flag, exe path |
| `Paths` | config directory, SQLite database, HTTP cache, report directory (resolved against the current working directory when relative) |
| `Dependencies` | one line per tracked optional dependency: `requests`, `yaml` (PyYAML), `jinja2`, `fastapi`, `uvicorn`, `textual`, `matplotlib`, `numpy`, `reportlab`, `phonenumbers`, `PyInstaller` -- each marked `ok`/`missing` with the installed version |
| `Data packs` | the offline data-pack directory plus per-pack entry counts and byte sizes (see [docs/data-packs.md](data-packs.md)) |
| `Environment` | working directory, command line, locale, preferred encoding, whether `OBSCURALENS_CONFIG_DIR` is set, colour preference |
| `Network` | (only with `check_network=True`) HEAD probe of `https://github.com` |

Python API for the same information:

```python
from obscuralens.desktop import collect_diagnostics, diagnostics_report

report = collect_diagnostics()            # plain dict, JSON-safe
text = diagnostics_report()               # the ASCII rendering
js = diagnostics_report(as_json=True)     # JSON, for tooling
```

Everything in the diagnostics module never raises and never touches the
network unless asked.

## What is inside the executable

The desktop builds are **PyInstaller one-file** executables produced from
`scripts/obscuralens.spec`:

- `collect_submodules('obscuralens')` keeps every tracker, source and
  module reachable even where hidden imports are not statically
  detectable.
- `collect_data_files('obscuralens')` bundles **all package data**: the
  offline data packs (`obscuralens/data/*.txt`), the risk rule packs
  (`obscuralens/rules/packs/*.yaml`), the report templates
  (`obscuralens/reporting/templates/*.j2`) and the web UI's static assets.
  Earlier builds shipped without the offline packs; the spec now bundles
  them so the exe behaves exactly like a full install (this was fixed
  during the beta program -- see [docs/v5.1.md](v5.1.md)).
- The build entry point (`scripts/pyinstaller_entry.py`) calls
  `multiprocessing.freeze_support()` before handing over to the CLI, which
  Windows one-file builds require.

Consequences worth knowing:

- **First-launch unpack delay.** One-file mode unpacks the bundled Python
  runtime and data into a temporary directory on *every* start; the first
  launch is the slowest because antivirus software typically scans the
  freshly unpacked DLLs. Subsequent launches are faster but still pay the
  unpack. If you start the app many times a day and the delay annoys you,
  the pip install route starts instantly.
- **The console window stays open.** The build is a console application
  (`console=True`): the terminal is where the banner, splash lines and
  Ctrl+C handling live. Closing the terminal window stops the app.
- **Everything is bundled.** The exe needs no network access to *start*;
  network egress only happens for the OSINT lookups you run (and for
  `--check-update` / the optional network diagnostics probe).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `No free port found for 127.0.0.1 in the range starting at 8000` | 21 ports (8000-8020) all busy | free one of them, or pass `--port 8300` (a port outside the window is honoured exactly, with no probing) |
| Browser did not open | default browser misconfigured, headless session, or `OBSCURALENS_NO_BROWSER` set | open `http://127.0.0.1:8000` manually (check the `Listening on` line for the real port); try `--browser firefox`; unset `OBSCURALENS_NO_BROWSER` |
| `The desktop edition needs the optional web stack ... pip install "obscuralens[web]"` | you are running the launcher from a *pip install* without the web extra -- this cannot happen in the exe, which bundles it | `pip install "obscuralens[web]"`, or download the desktop executable from the releases page (the message includes the link) |
| SmartScreen / Gatekeeper blocks the binary | unsigned executable (expected) | verify the SHA-256 against `checksums.sha256`, then bypass: Windows *More info > Run anyway*; macOS `xattr -d com.apple.quarantine <file>` |
| Antivirus flags the exe | false positives on PyInstaller one-file builds are common: the bootloader self-unpacks an executable payload, which heuristics dislike | verify the checksum; if you want certainty, build your own from source with `pyinstaller scripts/obscuralens.spec --noconfirm` and compare; report the detection to your vendor |
| First start is slow (tens of seconds) | one-file unpack + antivirus scanning the unpacked files | wait it out; subsequent starts are faster; or use the pip install |
| Firewall prompt on launch | the process opens a listening socket (loopback) and makes outbound HTTPS to the data sources you query | the local server binds `127.0.0.1` only -- allowing it on private networks changes nothing externally; outbound HTTPS to the OSINT sources is required for lookups |
| `another instance is already running` but no window | a previous run crashed after reclaiming its lock, or is genuinely still alive | check the URL in the message; if stale, delete `desktop.lock` in the config dir (path shown by `--diagnostics`) |
| Garbled / empty banner output | legacy console code page or closed pipe | the banner is pure ASCII and survives `cmd.exe`; set `NO_COLOR=1` if colour sequences confuse your terminal |
| Update check says the service is unreachable | offline, DNS failure or a proxy refusing `api.github.com` | the check is informational; retry later, nothing else is affected |

Anything else: run `--diagnostics`, capture the output, and [open an
issue](#feedback).

## Security and privacy

- **The web UI is loopback-only.** uvicorn binds `127.0.0.1` by default;
  your browser talks to a server on your own machine. `--host` exists for
  unusual setups -- exposing the UI to a network is your decision and your
  responsibility (the server has no authentication of its own).
- **No telemetry.** The desktop app does not phone home. The only GitHub
  requests it ever makes are the explicit `--check-update` /
  `obscuralens update check` calls and the opt-in network probe inside
  `collect_diagnostics(check_network=True)`.
- **Lookups go only to the public sources you query.** When you
  investigate a target, the bundled engine fans out to the same public
  OSINT endpoints the pip CLI uses -- and to nothing else. See
  [docs/sources.md](sources.md) for the full catalog.
- **API keys stay local.** Keys you configure (Shodan, VirusTotal, ...)
  are stored in your config directory and sent only to the service they
  belong to.
- **History, cases and cache are local files** (SQLite + on-disk cache in
  the config directory). Uninstalling is deleting the executable plus,
  if you want, that directory.
- The rule text baked into the bundled risk rule packs describes technical
  indicators, never people -- see [docs/rules.md](rules.md) for that
  framing and its limits.

## FAQ

### Are the binaries signed?

No. Windows binaries trigger SmartScreen ("unknown publisher") and macOS
binaries are Gatekeeper-quarantined; both are expected for an unsigned
beta. Signing requires a paid organizational certificate the project does
not hold. Verify downloads against `checksums.sha256`, or build from
source with the bundled PyInstaller spec.

### Does the desktop edition auto-update?

No, and deliberately so. The updater *checks* GitHub and prints a notice
with download links; it never downloads or replaces anything on its own.
To move to a new build, download it yourself and delete the old exe. Both
channels read the same local config and database, so switching loses
nothing.

### Can I use the exe in CI/CD?

You can, but it is the wrong tool. The exe is aimed at analysts; for
automation prefer the pip package (same CLI, starts instantly), the Docker
image, or the [Python SDK](sdk.md) talking to a `obscuralens serve`
instance. The desktop launcher is interactive by design (it blocks until
Ctrl+C and opens a browser).

### Desktop or Docker -- which should I run?

Desktop: one analyst, one workstation, browser UI, zero setup. Docker
(`docker compose up`, web UI on :8000): servers, shared deployments,
headless boxes. Both run the same engine; the desktop exe simply bundles
what the Docker image installs.

### Is there a build for macOS Intel or Windows 32-bit?

Not in this beta. The release matrix is win-x64, linux-x64 and macos-arm64.
On Intel Macs or 32-bit Windows, use the pip install (Python 3.9+ runs
everywhere the CLI does). Apple Silicon support is native -- Rosetta is
not involved.

### Does it work offline?

Starts, yes: the launcher, the web UI, the toolbox, the offline data packs
and the bundled rule packs need no network. Lookups do -- they query
public OSINT sources by design. `--diagnostics` is offline by default;
`--check-update` needs `api.github.com`.

### How do I switch between beta and stable?

Download the other channel's executable and use it; they are independent
files sharing the same local data. The channel a build *reports* comes
from the build itself (`--channel` overrides it for update checks and
`--version` output). Version comparison understands that
`5.1.0-beta.1 < 5.1.0`, so a beta build will correctly point you at the
newer stable release when one exists.

### Where is my data stored?

In the config directory: `%APPDATA%\ObscuraLens` on Windows,
`~/Library/Caches/obscuralens` on macOS, `~/.cache/obscuralens` (or
`$XDG_CACHE_HOME/obscuralens`) on Linux -- override with
`OBSCURALENS_CONFIG_DIR`. `desktop.lock` lives there too. Run
`--diagnostics` to see the resolved paths.

### Is the web UI exposed to my network?

No. The server binds `127.0.0.1` only; only your own machine can reach it.
Outbound traffic goes to the public data sources of the lookups you run.
A firewall prompt about a listening socket refers to the loopback server.

### The exe is huge and slow to start -- why?

One-file PyInstaller builds carry the whole Python runtime, the web stack
and every data pack, and unpack them to a temp directory on each launch.
Convenience has a cost. The pip install starts faster; the exe needs no
Python at all.

## Feedback

Desktop beta feedback goes to the GitHub issue tracker:

<https://github.com/AceGuru-mjh/obscuralens/issues>

Please tag desktop-beta issues with the `desktop-beta` label and include:

1. the exact asset name you downloaded (it encodes version and platform),
2. the `--diagnostics` output,
3. what you expected and what happened.

For general platform bugs (a source lying, a rule mis-firing, an SDK
error), the ordinary issue templates apply -- see
[docs/sources.md](sources.md), [docs/rules.md](rules.md) and
[docs/sdk.md](sdk.md) for the component-specific context that helps.
