@echo off
setlocal EnableDelayedExpansion
echo.
echo ████████████████████████████████████████████████
echo    ShieldOS Build Script — Windows
echo ████████████████████████████████████████████████
echo.

:: ── Check prerequisites ──────────────────────────────────────────────
where python >nul 2>&1 || (echo ERROR: Python not found in PATH & exit /b 1)
where npm    >nul 2>&1 || (echo ERROR: Node.js/npm not found in PATH & exit /b 1)

echo [1/5] Installing Python dependencies...
cd /d "%~dp0..\engine"
pip install -r requirements.txt
if errorlevel 1 (echo ERROR: pip install failed & exit /b 1)

echo.
echo [2/5] Creating assets directory...
if not exist "assets" mkdir assets
copy /y "..\ui\assets\icon.ico" "assets\icon.ico" >nul 2>&1

echo.
echo [3/5] Building Python engine with PyInstaller...
pyinstaller --clean --onefile --noconsole ^
    --name shieldos-engine ^
    --icon "..\ui\assets\icon.ico" ^
    --add-data "rules;rules" ^
    --add-data "assets;assets" ^
    --hidden-import uvicorn.logging ^
    --hidden-import uvicorn.loops ^
    --hidden-import uvicorn.loops.auto ^
    --hidden-import uvicorn.protocols ^
    --hidden-import uvicorn.protocols.http ^
    --hidden-import uvicorn.protocols.http.auto ^
    --hidden-import uvicorn.lifespan ^
    --hidden-import uvicorn.lifespan.on ^
    --hidden-import fastapi ^
    --hidden-import pydantic ^
    --hidden-import watchdog.observers ^
    --hidden-import watchdog.events ^
    main.py

if errorlevel 1 (echo ERROR: PyInstaller failed & exit /b 1)
echo Engine built: dist\shieldos-engine.exe

echo.
echo [4/5] Installing Electron dependencies...
cd /d "%~dp0..\ui"
npm install
if errorlevel 1 (echo ERROR: npm install failed & exit /b 1)

echo.
echo [5/5] Building Electron installer...
npm run build:win
if errorlevel 1 (echo ERROR: electron-builder failed & exit /b 1)

echo.
echo ████████████████████████████████████████████████
echo    BUILD COMPLETE
echo    Installer: ui\dist\ShieldOS-Setup.exe
echo ████████████████████████████████████████████████
echo.
