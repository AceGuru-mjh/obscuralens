# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: build a single-file `obscuralens` executable.

Build with:  pyinstaller scripts/obscuralens.spec --noconfirm
Output:      dist/obscuralens(.exe)
"""

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules('obscuralens')

a = Analysis(
    ['scripts/pyinstaller_entry.py'],
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
