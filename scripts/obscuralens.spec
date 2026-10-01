# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: build a single-file `obscuralens` executable.

Build with:  pyinstaller scripts/obscuralens.spec --noconfirm
Output:      dist/obscuralens(.exe)
"""

import os

from PyInstaller.utils.hooks import collect_submodules

# SPECPATH points at the directory containing this spec file, so the entry
# script resolves correctly no matter the current working directory.
entry_script = os.path.join(SPECPATH, 'pyinstaller_entry.py')
hiddenimports = collect_submodules('obscuralens')

a = Analysis(
    [entry_script],
    pathex=[],
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
