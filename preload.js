'use strict'

const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('shieldos', {
  // ── REST API proxy ───────────────────────────────────────────────────────
  api: {
    get:    (endpoint)        => ipcRenderer.invoke('api-get',    endpoint),
    post:   (endpoint, body)  => ipcRenderer.invoke('api-post',   endpoint, body),
    delete: (endpoint)        => ipcRenderer.invoke('api-delete', endpoint),
  },

  // ── Native dialogs ───────────────────────────────────────────────────────
  dialog: {
    openFile:   () => ipcRenderer.invoke('open-file-dialog'),
    openFolder: () => ipcRenderer.invoke('open-folder-dialog'),
  },

  // ── Frameless window controls ────────────────────────────────────────────
  window: {
    minimize: () => ipcRenderer.invoke('window-minimize'),
    maximize: () => ipcRenderer.invoke('window-maximize'),
    close:    () => ipcRenderer.invoke('window-close'),
  },

  // ── Shell ────────────────────────────────────────────────────────────────
  shell: {
    openExternal: (url) => ipcRenderer.invoke('open-external', url),
  },

  // ── Engine status ────────────────────────────────────────────────────────
  engineReady: () => ipcRenderer.invoke('engine-ready'),

  // ── SSE live event stream ────────────────────────────────────────────────
  // Returns a cleanup function to close the EventSource
  connectEvents: (onMessage, onError) => {
    const es = new EventSource('http://127.0.0.1:7734/events')

    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        onMessage(data)
      } catch {}
    }

    es.onerror = () => {
      if (onError) onError()
      // Auto-reconnect after 3 seconds
      setTimeout(() => {
        try { es.close() } catch {}
        window.shieldos.connectEvents(onMessage, onError)
      }, 3000)
    }

    // Listen for engine restart signal from main process
    ipcRenderer.on('engine-restarted', () => {
      try { es.close() } catch {}
      setTimeout(() => window.shieldos.connectEvents(onMessage, onError), 1500)
    })

    return () => es.close()
  },
})
