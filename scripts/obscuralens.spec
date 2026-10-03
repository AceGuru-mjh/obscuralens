# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: build a single-file `obscuralens` executable.

Build with:  pyinstaller scripts/obscuralens.spec --noconfirm
Output:      dist/obscuralens(.exe)
"""

import contextlib
import os

from PyInstaller.utils.hooks import collect_submodules

# SPECPATH points at the directory containing this spec file; the repository
# root is its parent. Adding it to pathex lets Analysis locate the package even
# when it is not importable through the active interpreter's editable install.
repo_root = os.path.dirname(SPECPATH)
entry_script = os.path.join(SPECPATH, 'pyinstaller_entry.py')

# Our own modules (some are only imported lazily, e.g. web/tui/plugins).
hiddenimports = collect_submodules('obscuralens')

# Third-party packages that are only ever imported lazily (inside functions),
# so they must be collected explicitly: a frozen executable cannot pip-install
# the "[web]"/"[tui]" extras at runtime, and modulegraph cannot always see
# through their own lazy/optional imports (uvicorn drivers, pydantic
# plugins, textual's rich/pygments/markdown stack).
for _package in (
    'fastapi',
    'starlette',
    'uvicorn',
    'pydantic',
    'annotated_types',
    'anyio',
    'textual',
    'rich',
    'pygments',
    'markdown_it',
    'platformdirs',
):
    # Package absent from the build environment: the corresponding
    # feature (serve/tui) will report its install hint at runtime.
    with contextlib.suppress(Exception):
        hiddenimports += collect_submodules(_package)

a = Analysis(
    [entry_script],
    pathex=[repo_root],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=['pytest', 'tkinter', 'PyQt5', 'PySide6'],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='obscuralens',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
