'use strict'

const {
  app, BrowserWindow, ipcMain, dialog,
  shell, nativeImage, Menu
} = require('electron')
const { spawn } = require('child_process')
const path = require('path')
const http = require('http')

const ENGINE_URL  = 'http://127.0.0.1:7734'
const ENGINE_PORT = 7734

let mainWindow   = null
let engineProcess = null
let engineReady   = false

// ── Helpers ────────────────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms))
}

async function fetchJSON(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { timeout: 5000, ...opts }, res => {
      let data = ''
      res.on('data', c => { data += c })
      res.on('end', () => {
        try { resolve(JSON.parse(data)) }
        catch (e) { resolve({ error: 'parse error', raw: data }) }
      })
    })
    req.on('error', reject)
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')) })
    if (opts.body) req.write(opts.body)
    req.end()
  })
}

// ── Engine management ──────────────────────────────────────────────────────

function getEnginePath() {
  if (app.isPackaged) {
    const base = process.resourcesPath
    if (process.platform === 'win32')
      return path.join(base, 'engine', 'shieldos-engine.exe')
    return path.join(base, 'engine', 'shieldos-engine')
  }
  // Development: run Python directly
  return null
}

function startEngine() {
  const enginePath = getEnginePath()

  if (enginePath) {
    // Packaged: run compiled binary
    engineProcess = spawn(enginePath, [], {
      detached:  false,
      stdio:     ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    })
  } else {
    // Development: run Python
    const pyArgs = [path.join(__dirname, '..', 'engine', 'main.py')]
    const py     = process.platform === 'win32' ? 'python' : 'python3'
    engineProcess = spawn(py, pyArgs, {
      stdio: ['ignore', 'pipe', 'pipe'],
    })
  }

  engineProcess.stdout.on('data', d =>
    console.log('[Engine]', d.toString().trim()))
  engineProcess.stderr.on('data', d =>
    console.error('[Engine]', d.toString().trim()))
  engineProcess.on('exit', (code) => {
    console.log('[Engine] exited with code', code)
    engineReady = false
    // Auto-restart if unexpected exit and window is open
    if (mainWindow && !mainWindow.isDestroyed() && code !== 0) {
      setTimeout(() => {
        console.log('[Engine] Restarting...')
        startEngine()
        waitForEngine().then(() => {
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('engine-restarted')
          }
        })
      }, 2000)
    }
  })

  console.log('[Engine] Process started, PID:', engineProcess.pid)
}

async function waitForEngine(maxWait = 20000) {
  const start = Date.now()
  while (Date.now() - start < maxWait) {
    try {
      await fetchJSON(`${ENGINE_URL}/status`)
      engineReady = true
      console.log('[Engine] API ready')
      return true
    } catch {
      await sleep(500)
    }
  }
  console.error('[Engine] Timed out waiting for API')
  return false
}

function stopEngine() {
  if (engineProcess) {
    try {
      engineProcess.kill('SIGTERM')
    } catch (e) {
      try { engineProcess.kill() } catch {}
    }
    engineProcess = null
  }
}

// ── Window creation ────────────────────────────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width:           1280,
    height:          800,
    minWidth:        960,
    minHeight:       600,
    frame:           false,
    transparent:     false,
    backgroundColor: '#050d0f',
    webPreferences: {
      preload:          path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration:  false,
      sandbox:          true,
    },
    icon: path.join(__dirname, 'assets', 'icon.png'),
    show: false,
    titleBarStyle: 'hidden',
  })

  // Remove default menu bar
  Menu.setApplicationMenu(null)

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'))

  mainWindow.once('ready-to-show', () => {
    mainWindow.show()
    if (process.env.NODE_ENV === 'development') {
      mainWindow.webContents.openDevTools({ mode: 'detach' })
    }
  })

  mainWindow.on('closed', () => {
    mainWindow = null
  })

  // Open external links in system browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url)
    return { action: 'deny' }
  })
}

// ── IPC Handlers ───────────────────────────────────────────────────────────

// Proxy API GET
ipcMain.handle('api-get', async (_, endpoint) => {
  try {
    return await fetchJSON(`${ENGINE_URL}${endpoint}`)
  } catch (e) {
    return { error: e.message }
  }
})

// Proxy API POST
ipcMain.handle('api-post', async (_, endpoint, body) => {
  try {
    const bodyStr = JSON.stringify(body || {})
    return await fetchJSON(`${ENGINE_URL}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(bodyStr),
      },
      body: bodyStr,
    })
  } catch (e) {
    return { error: e.message }
  }
})

// Proxy API DELETE
ipcMain.handle('api-delete', async (_, endpoint) => {
  try {
    return await fetchJSON(`${ENGINE_URL}${endpoint}`, { method: 'DELETE' })
  } catch (e) {
    return { error: e.message }
  }
})

// File picker
ipcMain.handle('open-file-dialog', async () => {
  return dialog.showOpenDialog(mainWindow, {
    properties: ['openFile', 'multiSelections'],
    title: 'Select files to scan',
  })
})

// Folder picker
ipcMain.handle('open-folder-dialog', async () => {
  return dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Select folder to scan',
  })
})

// Open URL in browser
ipcMain.handle('open-external', (_, url) => {
  shell.openExternal(url)
})

// Window controls (frameless)
ipcMain.handle('window-minimize', () => mainWindow?.minimize())
ipcMain.handle('window-maximize', () => {
  if (!mainWindow) return
  mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize()
})
ipcMain.handle('window-close', () => mainWindow?.close())

// Engine status
ipcMain.handle('engine-ready', () => engineReady)

// ── App lifecycle ──────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  console.log('[App] Starting ShieldOS...')
  startEngine()

  const ready = await waitForEngine()
  if (!ready) {
    console.error('[App] Engine failed to start — showing error window')
  }

  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    stopEngine()
    app.quit()
  }
})

app.on('before-quit', () => {
  stopEngine()
})

// macOS: quit engine when app quits
app.on('will-quit', () => {
  stopEngine()
})
