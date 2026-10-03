# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: build a single-file `obscuralens` executable.

Build with:  pyinstaller scripts/obscuralens.spec --noconfirm
Output:      dist/obscuralens(.exe)

Desktop beta notes:
  * ``collect_data_files`` bundles every shipped package-data file
    (offline data packs, risk rule packs, report templates, locale
    catalogues) so the standalone exe behaves exactly like an install.
  * ``collect_submodules`` keeps every tracker/source/module reachable
    even when hidden imports are not statically detectable.
  * The workflow that publishes the exe renames the artifact to
    ``ObscuraLens-<version>-<platform>.exe`` at staging time, so the
    spec itself keeps a stable output name.
"""

import contextlib
import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

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

# Non-Python resources shipped inside the package:
#   obscuralens/data/*.txt          offline data packs
#   obscuralens/rules/packs/*.yaml  explainable risk rule packs
#   obscuralens/reporting/templates/*.j2  report templates
package_datas = collect_data_files('obscuralens',
                                   include_py_files=False,
                                   excludes=['**/__pycache__/*'])

a = Analysis(
    [entry_script],
    pathex=[repo_root],
    binaries=[],
    datas=package_datas,
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
