#!/bin/bash
set -euo pipefail

echo ""
echo "████████████████████████████████████████████████"
echo "   ShieldOS Build Script — Linux"
echo "████████████████████████████████████████████████"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# ── Check prerequisites ──────────────────────────────────────────────────
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found"; exit 1; }
command -v pip3    >/dev/null 2>&1 || { echo "ERROR: pip3 not found";    exit 1; }
command -v npm     >/dev/null 2>&1 || { echo "ERROR: npm not found";     exit 1; }

echo "[1/5] Installing Python dependencies..."
cd "$ROOT_DIR/engine"
pip3 install --user -r requirements.txt

echo ""
echo "[2/5] Creating assets directory..."
mkdir -p assets
cp -n "$ROOT_DIR/ui/assets/icon.png" assets/ 2>/dev/null || true

echo ""
echo "[3/5] Building Python engine with PyInstaller..."
pyinstaller --clean --onefile \
    --name shieldos-engine \
    --add-data "rules:rules" \
    --add-data "assets:assets" \
    --hidden-import uvicorn.logging \
    --hidden-import uvicorn.loops \
    --hidden-import uvicorn.loops.auto \
    --hidden-import uvicorn.protocols \
    --hidden-import uvicorn.protocols.http \
    --hidden-import uvicorn.protocols.http.auto \
    --hidden-import uvicorn.lifespan \
    --hidden-import uvicorn.lifespan.on \
    --hidden-import fastapi \
    --hidden-import pydantic \
    --hidden-import watchdog.observers \
    --hidden-import watchdog.events \
    main.py

echo "Engine built: dist/shieldos-engine"

echo ""
echo "[4/5] Installing Electron dependencies..."
cd "$ROOT_DIR/ui"
npm install

echo ""
echo "[5/5] Building Linux AppImage..."
npm run build:linux

echo ""
echo "████████████████████████████████████████████████"
echo "   BUILD COMPLETE"
echo "   AppImage: ui/dist/ShieldOS.AppImage"
echo "████████████████████████████████████████████████"
echo ""
