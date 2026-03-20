# -*- mode: python ; coding: utf-8 -*-
"""
ShieldOS Engine — PyInstaller Build Specification
Run: pyinstaller build.spec
"""

import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('rules',   'rules'),          # YARA rule files
        ('assets',  'assets'),          # Icons
    ],
    hiddenimports=[
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'fastapi',
        'pydantic',
        'watchdog.observers',
        'watchdog.observers.polling',
        'watchdog.events',
        'pystray._win32',
        'pystray._darwin',
        'pystray._xorg',
        'PIL._tkinter_finder',
        'plyer.platforms.win.notification',
        'plyer.platforms.macosx.notification',
        'plyer.platforms.linux.notification',
        'yara',
        'psutil',
        'schedule',
        'cryptography',
        'sqlite3',
        'email',
        'email.mime',
        'email.mime.text',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='shieldos-engine',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # No console window on Windows
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='../ui/assets/icon.ico' if sys.platform == 'win32' else (
         '../ui/assets/icon.icns' if sys.platform == 'darwin' else None
    ),
)
