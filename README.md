# ShieldOS — Antivirus & Endpoint Protection

**Version 4.2.1** | Cross-platform (Windows, macOS, Linux)

ShieldOS is a real-time antivirus and endpoint protection suite with a Python backend engine and Electron frontend UI.

---

## Architecture

```
shieldos/
├── engine/          Python FastAPI backend (port 7734)
│   ├── main.py      Entry point + REST API
│   ├── scanner.py   Parallel scan engine (4 workers)
│   ├── realtime.py  File system watcher (watchdog)
│   ├── yara_engine  YARA rule matching
│   ├── heuristics   Entropy/PE/string analysis
│   ├── signatures   Local hash + byte pattern DB
│   ├── virustotal   VirusTotal API v3 integration
│   ├── quarantine   XOR-encrypted vault
│   └── rules/       YARA rule files
└── ui/              Electron frontend
    ├── main.js      Electron main process
    ├── preload.js   IPC bridge (contextBridge)
    └── renderer/    Single-page HTML/CSS/JS app
```

---

## Prerequisites

### Engine (Python)
- Python 3.10 or later
- pip

### UI (Node.js)
- Node.js 18 or later
- npm 9 or later

---

## Development Setup

### 1. Install engine dependencies

```bash
cd engine
pip install -r requirements.txt
```

> **Windows note:** Replace `python-magic` with `python-magic-bin` for Windows:
> ```
> pip install python-magic-bin
> ```

> **YARA note:** `yara-python` requires the YARA library. On Linux:
> ```bash
> sudo apt install yara
> ```
> On macOS:
> ```bash
> brew install yara
> ```
> On Windows, install with: `pip install yara-python` (pre-built wheel included)

### 2. Start the engine

```bash
cd engine
python main.py
```

Engine starts on `http://127.0.0.1:7734`. Verify with:
```bash
curl http://127.0.0.1:7734/status
```

### 3. Install UI dependencies

```bash
cd ui
npm install
```

### 4. Start the UI

```bash
cd ui
npm start
```

---

## Building for Distribution

### Windows

```bat
cd build
build-windows.bat
```
Output: `ui/dist/ShieldOS-Setup.exe`

Requires:
- Python + PyInstaller (`pip install pyinstaller`)
- Node.js + electron-builder (`npm install` in `ui/`)
- Visual Studio Build Tools (for native Node modules)

### macOS

```bash
chmod +x build/build-macos.sh
./build/build-macos.sh
```
Output: `ui/dist/ShieldOS.dmg`

Requires:
- Xcode Command Line Tools (`xcode-select --install`)
- For notarisation: Apple Developer account

### Linux

```bash
chmod +x build/build-linux.sh
./build/build-linux.sh
```
Output: `ui/dist/ShieldOS.AppImage`

Make executable and run:
```bash
chmod +x ui/dist/ShieldOS-*.AppImage
./ui/dist/ShieldOS-*.AppImage
```

---

## Configuration

On first run, a config database is created at:

| Platform | Path |
|----------|------|
| Windows  | `%APPDATA%\ShieldOS\shieldos.db` |
| macOS    | `~/Library/Application Support/ShieldOS/shieldos.db` |
| Linux    | `~/.config/shieldos/shieldos.db` |

### Key settings (configurable in UI Settings page)

| Setting | Default | Description |
|---------|---------|-------------|
| `realtime_enabled` | `true` | File system monitoring |
| `virustotal_api_key` | `""` | Optional — enables cloud scanning |
| `heuristics_level` | `medium` | `low / medium / high / paranoid` |
| `max_file_size_mb` | `512` | Skip files larger than this |
| `quarantine_auto` | `true` | Auto-quarantine detected threats |
| `scheduled_scan_time` | `02:00` | Daily home-dir scan time |
| `parallel_scan_workers` | `4` | Thread pool size |

---

## VirusTotal Integration

1. Create a free account at [virustotal.com](https://www.virustotal.com/gui/join-us)
2. Copy your API key from your profile
3. Enter it in ShieldOS Settings → Cloud Scanning
4. Click Save Settings

Free tier: 4 requests/minute. ShieldOS respects this limit automatically using hash lookup (no file upload unless the file is unknown).

---

## REST API Reference

Engine API runs on `http://127.0.0.1:7734`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/status` | GET | Engine status, uptime, protection layers |
| `/stats` | GET | Scan statistics |
| `/scan/file` | POST | Scan a single file |
| `/scan/directory` | POST | Start directory scan |
| `/scan/progress/{id}` | GET | Scan progress |
| `/scan/cancel/{id}` | POST | Cancel running scan |
| `/threats` | GET | Recent threats |
| `/quarantine` | GET | Quarantined files |
| `/quarantine/restore/{id}` | POST | Restore quarantined file |
| `/quarantine/{id}` | DELETE | Permanently delete |
| `/history` | GET | Full scan history |
| `/config` | GET/POST | Read/write configuration |
| `/realtime/start` | POST | Enable real-time protection |
| `/realtime/stop` | POST | Disable real-time protection |
| `/processes` | GET | Scan running processes |
| `/events` | GET | SSE event stream |
| `/rules` | GET | Loaded YARA rule names |
| `/rules/reload` | POST | Hot-reload YARA rules |
| `/whitelist/add` | POST | Add hash to whitelist |
| `/network` | GET | Active network connections |

---

## Detection Engines

1. **Signature DB** — SHA256 hash matching + byte/string pattern scan
2. **YARA Rules** — Custom rule matching across 5 rule files:
   - `malware.yar` — Packers, PowerShell abuse, generic malware (16 rules)
   - `ransomware.yar` — WannaCry, Ryuk, Conti, LockBit, BlackCat (9 rules)
   - `trojans.yar` — RATs, stealers, backdoors, loaders (11 rules)
   - `exploits.yar` — Shellcode, heap spray, CVE patterns (12 rules)
   - `pup.yar` — Adware, miners, hijackers (10 rules)
3. **Heuristics** — Entropy analysis, PE header inspection, string analysis
4. **VirusTotal** — Cloud hash lookup (opt-in, requires API key)

---

## Quarantine

Detected threats are XOR-encrypted (key: `0xAB`) and moved to:

| Platform | Quarantine path |
|----------|----------------|
| Windows  | `%APPDATA%\ShieldOS\quarantine\` |
| macOS    | `~/Library/Application Support/ShieldOS/quarantine/` |
| Linux    | `~/.config/shieldos/quarantine/` |

Files are stored as `<sha256_prefix>.quar` and cannot be accidentally executed. Restore or permanently delete via the Quarantine page in the UI.

---

## YARA Rule Development

Add custom `.yar` files to the rules directory, then click **Reload Rules** in Settings or call `POST /rules/reload`. Rules are validated before loading — compile errors are logged and the previous ruleset remains active.

---

## Permissions

- **Windows:** Installer requests administrator elevation for system directory access
- **macOS:** Requires Full Disk Access — grant in System Preferences → Privacy & Security
- **Linux:** Runs as current user; use `sudo` for scanning system directories

---

## License

ShieldOS is provided for defensive security use. Detection signatures are derived from publicly documented malware indicators.
