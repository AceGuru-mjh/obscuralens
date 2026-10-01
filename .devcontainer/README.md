# Dev container

A ready-to-use ObscuraLens development environment based on
`mcr.microsoft.com/devcontainers/python:1-3.12-bookworm`.

## Usage

1. Install the **Dev Containers** VS Code extension.
2. Open this repository in VS Code.
3. Run **Dev Containers: Reopen in Container**.

On first create the container installs the package in editable mode with its
dev extras (`pip install -e ".[dev]"`). The taskbar then offers the shared
tasks (install, test, lint, run, serve, tui) and the launch configurations in
`.vscode/`.

Port `8000` is forwarded for the web UI (`python -m obscuralens serve`).
