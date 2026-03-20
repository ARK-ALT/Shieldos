'use strict'

/* ═══════════════════════════════════════════════════════════════════════
   ShieldOS — Renderer App Logic
   Communicates with Python engine via window.shieldos (preload bridge)
═══════════════════════════════════════════════════════════════════════ */

const HEUR_LABELS  = ['Low', 'Medium', 'High', 'Paranoid']
const HEUR_VALUES  = ['low', 'medium', 'high', 'paranoid']
const LAYER_NAMES  = {
  signatures: 'Signatures', yara: 'YARA Rules', heuristics: 'Heuristics',
  virustotal: 'VirusTotal', realtime: 'Real-Time', quarantine: 'Quarantine',
  scheduler: 'Scheduler', network: 'Network',
}

// ── State ──────────────────────────────────────────────────────────────────
const State = {
  currentPage:    'dashboard',
  currentScanId:  null,
  realtimeEnabled: true,
  config:          {},
  scanResults:     [],
  scanResultCount: 0,
  scanStartTime:   null,
  workerLastFile:  { 'SC-01': '', 'SC-02': '', 'SC-03': '', 'SC-04': '' },
  workerProgress:  { 'SC-01': 0,  'SC-02': 0,  'SC-03': 0,  'SC-04': 0  },
  fpsInterval:     null,
  pollInterval:    null,
  disconnectSSE:   null,
}

// ── App entry point ────────────────────────────────────────────────────────
const App = {

  async init() {
    // Navigation
    document.querySelectorAll('.nav-item[data-page]').forEach(el => {
      el.addEventListener('click', () => App.navigate(el.dataset.page))
    })

    // Connect SSE
    State.disconnectSSE = shieldos.connectEvents(
      App.handleSSEEvent,
      () => App.showToast('Engine disconnected — reconnecting…', 'info')
    )

    // Initial data load
    await App.loadStatus()
    await App.loadStats()
    await App.loadThreats()
    await App.loadConfig()
    await App.loadYARARules()

    // Poll stats every 10s
    State.pollInterval = setInterval(async () => {
      await App.loadStats()
      if (State.currentPage === 'quarantine') await App.loadQuarantine()
      if (State.currentPage === 'realtime')   await App.loadRealtimeStatus()
    }, 10000)
  },

  navigate(page) {
    State.currentPage = page

    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.page === page)
    })
    document.querySelectorAll('.page').forEach(el => {
      el.classList.toggle('active', el.id === `page-${page}`)
    })

    // Load page data on first visit
    switch (page) {
      case 'quarantine': App.loadQuarantine();  break
      case 'processes':  App.loadProcesses();   break
      case 'history':    App.loadHistory();     break
      case 'realtime':   App.loadRealtimeStatus(); break
    }
  },

  // ── SSE event handler ──────────────────────────────────────────────────

  handleSSEEvent(event) {
    switch (event.type) {
      case 'connected':
        App.updateEngineStatus(true)
        break

      case 'scan_result':
        App.addEventFeedItem(event)
        App.updateWorker(event.client_id, event.path, event.result)
        if (event.result !== 'clean' && State.currentPage === 'scan') {
          App.addScanResultRow(event)
        }
        // Update FPS counter display periodically
        break

      case 'threat_detected':
        App.showToast(
          `⚠ Threat: ${event.threat_name || 'Unknown'}\n${App.basename(event.path)}`,
          'threat'
        )
        App.flashThreatCount()
        // Refresh threats table
        App.loadThreats()
        // Refresh quarantine badge
        App.refreshQuarantineBadge()
        break

      case 'scan_progress':
        App.updateScanProgress(event)
        break

      case 'stats_update':
        App.applyStats(event)
        break

      case 'engine_status':
        App.updateEngineStatus(event.status === 'ready')
        break
    }
  },

  // ── Status / Stats ─────────────────────────────────────────────────────

  async loadStatus() {
    const data = await shieldos.api.get('/status')
    if (data.error) return

    State.realtimeEnabled = data.realtime_enabled

    const badge = document.getElementById('sidebar-status-badge')
    const text  = document.getElementById('sidebar-status-text')

    if (data.realtime_enabled) {
      badge.className = 'protection-badge protected'
      text.textContent = 'Protected'
    } else {
      badge.className = 'protection-badge paused'
      text.textContent = 'Paused'
    }

    const sub = document.getElementById('dash-subtitle')
    if (sub) sub.textContent = `ShieldOS v${data.version} — uptime ${App.formatUptime(data.uptime_seconds)}`

    // Protection layers
    if (data.protection_layers) App.renderLayers(data.protection_layers)
  },

  async loadStats() {
    const data = await shieldos.api.get('/stats')
    if (data.error) return
    App.applyStats(data)
  },

  applyStats(data) {
    App.setText('stat-scanned',     App.formatNum(data.total_scanned    ?? data.total ?? 0))
    App.setText('stat-threats',     App.formatNum(data.threats_found    ?? data.threats ?? 0))
    App.setText('stat-quarantined', App.formatNum(data.quarantined       ?? 0))
    App.setText('stat-fps',         data.files_per_second ?? 0)
    if (data.last_scan) {
      App.setText('stat-last-scan', 'Last: ' + App.formatDate(data.last_scan))
    }
  },

  // ── Threats ────────────────────────────────────────────────────────────

  async loadThreats() {
    const data = await shieldos.api.get('/threats?limit=20')
    if (!Array.isArray(data)) return
    const tbody = document.getElementById('threats-table')
    if (!tbody) return
    tbody.innerHTML = data.length === 0
      ? '<tr><td colspan="6" class="empty-state">No threats detected</td></tr>'
      : data.map(t => `
        <tr>
          <td class="truncate mono" title="${App.esc(t.path)}">${App.esc(App.basename(t.path))}</td>
          <td class="text-red">${App.esc(t.threat_name || '—')}</td>
          <td><span class="badge badge-clean">${App.esc(t.engine || '—')}</span></td>
          <td>${App.severityBadge(t.severity)}</td>
          <td>${App.esc(t.action || 'allowed')}</td>
          <td class="text-dim mono">${App.formatDate(t.timestamp)}</td>
        </tr>`).join('')
  },

  flashThreatCount() {
    const el = document.getElementById('stat-threats')
    if (el) {
      el.style.animation = 'none'
      requestAnimationFrame(() => {
        el.style.animation = 'pulse-red 0.5s 3'
      })
    }
  },

  // ── Scan ───────────────────────────────────────────────────────────────

  async browseScanFolder() {
    const result = await shieldos.dialog.openFolder()
    if (!result.canceled && result.filePaths.length > 0) {
      document.getElementById('scan-path-input').value = result.filePaths[0]
    }
  },

  async startScan() {
    const path = document.getElementById('scan-path-input').value.trim()
    if (!path) { App.showToast('Select a folder to scan', 'info'); return }

    const recursive = document.getElementById('scan-recursive').checked

    // Clear results
    State.scanResults    = []
    State.scanResultCount = 0
    State.scanStartTime  = Date.now()
    document.getElementById('scan-results-table').innerHTML = ''
    App.setText('scan-result-count', '0 entries')

    // Show progress card
    document.getElementById('scan-progress-card').style.display = 'block'
    document.getElementById('scan-start-btn').style.display  = 'none'
    document.getElementById('scan-cancel-btn').style.display = ''
    document.getElementById('scan-main-bar').style.width = '0%'

    const res = await shieldos.api.post('/scan/directory', { path, recursive })
    if (res.error) {
      App.showToast('Scan failed: ' + res.error, 'threat')
      return
    }

    State.currentScanId = res.scan_id
    App.setText('dash-scan-id', `SCAN-${res.scan_id}`)
  },

  async cancelScan() {
    if (State.currentScanId) {
      await shieldos.api.post(`/scan/cancel/${State.currentScanId}`)
      State.currentScanId = null
      App.endScan()
    }
  },

  updateScanProgress(event) {
    const { scanned, total, threats, percent, done } = event

    const bar  = document.getElementById('scan-main-bar')
    if (bar) bar.style.width = (percent || 0) + '%'

    App.setText('scan-progress-label', `${App.formatNum(scanned)} / ${App.formatNum(total)}`)
    App.setText('sc-scanned', App.formatNum(scanned))
    App.setText('sc-threats', threats || 0)

    // FPS
    if (State.scanStartTime) {
      const elapsed = (Date.now() - State.scanStartTime) / 1000
      App.setText('sc-fps', elapsed > 0 ? Math.round(scanned / elapsed) : 0)
    }

    if (done) {
      App.endScan()
      App.showToast(`Scan complete: ${App.formatNum(scanned)} files, ${threats} threats`, 'success')
      App.loadStats()
      App.loadThreats()
    }
  },

  endScan() {
    document.getElementById('scan-start-btn').style.display  = ''
    document.getElementById('scan-cancel-btn').style.display = 'none'
    State.currentScanId = null
    // Reset workers
    ;['SC-01','SC-02','SC-03','SC-04'].forEach(w => App.updateWorker(w, 'Idle', null))
  },

  addScanResultRow(event) {
    State.scanResultCount++
    App.setText('scan-result-count', `${State.scanResultCount} entries`)
    const tbody = document.getElementById('scan-results-table')
    if (!tbody) return
    const name   = App.basename(event.path || '')
    const result = event.result || 'clean'
    const row    = document.createElement('tr')
    row.innerHTML = `
      <td class="truncate mono" title="${App.esc(event.path)}">${App.esc(name)}</td>
      <td><span class="event-result ${result}">${result}</span></td>
      <td class="text-red">${App.esc(event.threat_name || '—')}</td>
      <td>${App.esc(event.engine || '—')}</td>
      <td>${App.esc(event.action || '—')}</td>
      <td class="mono text-dim">${App.esc(event.client_id || '')}</td>
    `
    tbody.prepend(row)
    if (tbody.children.length > 500) tbody.lastChild.remove()
  },

  // ── Quick / Full scan ──────────────────────────────────────────────────

  async quickScan() {
    App.navigate('scan')
    const home = await shieldos.api.get('/config')
    document.getElementById('scan-path-input').value = '~'
    // Trigger immediately if we have a path
    const res = await shieldos.api.post('/scan/directory', {
      path: home.watch_paths?.[0] || '~', recursive: true,
    })
    if (res.scan_id) {
      State.currentScanId = res.scan_id
      document.getElementById('scan-progress-card').style.display = 'block'
      document.getElementById('scan-start-btn').style.display  = 'none'
      document.getElementById('scan-cancel-btn').style.display = ''
    }
  },

  async fullScan() {
    App.navigate('scan')
    App.showToast('Select a root folder to begin full scan', 'info')
  },

  // ── Workers ────────────────────────────────────────────────────────────

  updateWorker(clientId, filePath, result) {
    const row = document.getElementById(`worker-${clientId}`)
    if (!row) return
    const label  = row.querySelector('.worker-file')
    const fill   = row.querySelector('.progress-fill')
    const name   = filePath ? App.basename(filePath) : 'Idle'
    if (label) label.textContent = name
    if (fill) {
      if (!filePath || filePath === 'Idle') {
        fill.style.width = '0%'
        fill.className   = 'progress-fill'
      } else {
        // Animate a cycling progress indicator
        const w = State.workerProgress[clientId] || 0
        State.workerProgress[clientId] = (w + 15) % 100
        fill.style.width = State.workerProgress[clientId] + '%'
        fill.className   = 'progress-fill ' + (result === 'threat' ? 'red' : result === 'suspicious' ? 'yellow' : '')
      }
    }
    // Also update sc-current-file
    if (State.currentPage === 'scan') {
      App.setText('sc-current-file', filePath || '—')
    }
  },

  // ── Event feed ─────────────────────────────────────────────────────────

  addEventFeedItem(event) {
    const now  = new Date()
    const time = now.toTimeString().slice(0, 8)
    const name = App.basename(event.path || '')
    const result = event.result || 'clean'

    const item = document.createElement('div')
    item.className = 'event-item'
    item.innerHTML = `
      <span class="event-time">${time}</span>
      <span class="event-client">${App.esc(event.client_id || 'RT')}</span>
      <span class="event-path" title="${App.esc(event.path)}">${App.esc(name)}</span>
      <span class="event-result ${result}">${result}</span>
    `

    // Dashboard feed
    const df = document.getElementById('event-feed')
    if (df) {
      df.prepend(item.cloneNode(true))
      if (df.children.length > 200) df.lastChild.remove()
    }

    // Realtime feed
    const rf = document.getElementById('rt-event-feed')
    if (rf && event.scan_type === 'realtime') {
      rf.prepend(item)
      if (rf.children.length > 500) rf.lastChild.remove()
    }
  },

  // ── Protection layers ──────────────────────────────────────────────────

  renderLayers(layers) {
    const grid = document.getElementById('layers-grid')
    if (!grid) return
    grid.innerHTML = Object.entries(layers).map(([key, active]) => `
      <div class="layer-card ${active ? 'active' : 'inactive'}">
        <span class="layer-dot"></span>
        <span class="layer-name">${LAYER_NAMES[key] || key}</span>
      </div>
    `).join('')
  },

  updateEngineStatus(connected) {
    const badge = document.getElementById('sidebar-status-badge')
    const text  = document.getElementById('sidebar-status-text')
    if (!connected) {
      if (badge) badge.className = 'protection-badge paused'
      if (text)  text.textContent = 'Connecting…'
    }
  },

  // ── Real-Time ──────────────────────────────────────────────────────────

  async loadRealtimeStatus() {
    const data = await shieldos.api.get('/status')
    if (data.error) return
    const toggle = document.getElementById('rt-enabled-toggle')
    if (toggle) toggle.checked = data.realtime_enabled
    const btn = document.getElementById('rt-toggle-btn')
    if (btn) btn.textContent = data.realtime_enabled ? 'Pause Protection' : 'Enable Protection'

    const cfg = await shieldos.api.get('/config')
    if (!cfg.error) App.renderWatchPaths(cfg.watch_paths || [])
  },

  renderWatchPaths(paths) {
    const el = document.getElementById('watch-paths-list')
    if (!el) return
    if (paths.length === 0) {
      el.innerHTML = '<div class="text-dim" style="padding:12px;">No custom watch paths configured (using defaults)</div>'
      return
    }
    el.innerHTML = paths.map(p => `
      <div class="toggle-row">
        <span class="mono" style="font-size:11px;">${App.esc(p)}</span>
        <button class="btn-sm btn-danger" onclick="App.removeWatchPath('${App.esc(p)}')">Remove</button>
      </div>
    `).join('')
  },

  async setRealtime(enabled) {
    const endpoint = enabled ? '/realtime/start' : '/realtime/stop'
    await shieldos.api.post(endpoint)
    State.realtimeEnabled = enabled
    await App.loadStatus()
  },

  async toggleRealtime() {
    await App.setRealtime(!State.realtimeEnabled)
    await App.loadRealtimeStatus()
  },

  async addWatchPath() {
    const result = await shieldos.dialog.openFolder()
    if (!result.canceled && result.filePaths.length > 0) {
      const path = result.filePaths[0]
      await shieldos.api.post('/realtime/add-path', { path })
      await App.loadRealtimeStatus()
    }
  },

  async removeWatchPath(path) {
    await shieldos.api.post('/realtime/remove-path', { path })
    await App.loadRealtimeStatus()
  },

  // ── Quarantine ─────────────────────────────────────────────────────────

  async loadQuarantine() {
    const data = await shieldos.api.get('/quarantine')
    const tbody = document.getElementById('quarantine-table')
    const sub   = document.getElementById('q-subtitle')
    if (!tbody) return

    if (!Array.isArray(data) || data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Quarantine vault is empty</td></tr>'
      if (sub) sub.textContent = 'Vault is empty'
      App.setText('nav-q-count', '')
      return
    }

    if (sub) sub.textContent = `${data.length} file${data.length !== 1 ? 's' : ''} in vault`
    App.setText('nav-q-count', `(${data.length})`)

    tbody.innerHTML = data.map(q => `
      <tr>
        <td class="truncate mono" title="${App.esc(q.original_path)}">${App.esc(q.filename)}</td>
        <td class="text-red">${App.esc(q.threat_name || '—')}</td>
        <td>${App.severityBadge(q.severity)}</td>
        <td><span class="badge badge-clean">${App.esc(q.threat_type || 'unknown')}</span></td>
        <td class="text-dim mono">${App.formatDate(q.timestamp)}</td>
        <td class="flex gap-8">
          <button class="btn-sm" onclick="App.restoreQuarantine(${q.id})">Restore</button>
          <button class="btn-sm btn-danger" onclick="App.deleteQuarantine(${q.id})">Delete</button>
        </td>
      </tr>`).join('')
  },

  async restoreQuarantine(id) {
    if (!confirm('Restore this file to its original location? The threat will no longer be quarantined.')) return
    const res = await shieldos.api.post(`/quarantine/restore/${id}`)
    if (res.restored) {
      App.showToast('File restored', 'success')
      await App.loadQuarantine()
    } else {
      App.showToast('Restore failed: ' + (res.detail || 'unknown error'), 'threat')
    }
  },

  async deleteQuarantine(id) {
    if (!confirm('Permanently delete this quarantined file? This cannot be undone.')) return
    const res = await shieldos.api.delete(`/quarantine/${id}`)
    if (res.deleted) {
      App.showToast('File permanently deleted', 'success')
      await App.loadQuarantine()
    }
  },

  async deleteAllQuarantine() {
    const data = await shieldos.api.get('/quarantine')
    if (!Array.isArray(data) || data.length === 0) { App.showToast('Quarantine is empty', 'info'); return }
    if (!confirm(`Permanently delete all ${data.length} quarantined files?`)) return
    for (const q of data) await shieldos.api.delete(`/quarantine/${q.id}`)
    App.showToast('All quarantined files deleted', 'success')
    await App.loadQuarantine()
  },

  async refreshQuarantineBadge() {
    const data = await shieldos.api.get('/quarantine')
    if (Array.isArray(data)) {
      App.setText('nav-q-count', data.length > 0 ? `(${data.length})` : '')
    }
  },

  // ── Processes ──────────────────────────────────────────────────────────

  async loadProcesses() {
    const tbody = document.getElementById('processes-table')
    if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="text-dim" style="padding:16px;">Loading…</td></tr>'
    const data = await shieldos.api.get('/processes')
    if (!Array.isArray(data) || !tbody) return

    tbody.innerHTML = data.length === 0
      ? '<tr><td colspan="6" class="empty-state">No process data available</td></tr>'
      : data.map(p => {
          const sr     = p.scan_result || {}
          const result = sr.result || 'clean'
          return `<tr>
            <td class="mono text-dim">${p.pid}</td>
            <td>${App.esc(p.name)}</td>
            <td class="truncate mono" title="${App.esc(p.exe)}" style="max-width:260px;">${App.esc(p.exe)}</td>
            <td class="mono">${p.cpu}%</td>
            <td class="mono">${p.memory_mb}</td>
            <td><span class="event-result ${result}">${result}</span>${sr.threat_name ? ' — <span class="text-red">' + App.esc(sr.threat_name) + '</span>' : ''}</td>
          </tr>`
        }).join('')
  },

  async scanProcesses() {
    const tbody = document.getElementById('processes-table')
    if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="text-dim" style="padding:16px;">Scanning processes…</td></tr>'
    await App.loadProcesses()
  },

  // ── History ────────────────────────────────────────────────────────────

  async loadHistory() {
    const data = await shieldos.api.get('/history?limit=200')
    const tbody = document.getElementById('history-table')
    const sub   = document.getElementById('hist-subtitle')
    if (!tbody) return

    if (!Array.isArray(data) || data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No scan history</td></tr>'
      return
    }

    if (sub) sub.textContent = `${App.formatNum(data.length)} entries`

    tbody.innerHTML = data.map(h => `
      <tr>
        <td class="text-dim mono">${App.formatDate(h.timestamp)}</td>
        <td class="truncate mono" title="${App.esc(h.path)}">${App.esc(h.filename)}</td>
        <td><span class="event-result ${h.result}">${h.result}</span></td>
        <td class="text-red">${App.esc(h.threat_name || '—')}</td>
        <td>${App.esc(h.engine || '—')}</td>
        <td>${App.esc(h.scan_type || 'manual')}</td>
      </tr>`).join('')
  },

  async clearHistory() {
    if (!confirm('Clear all scan history? This cannot be undone.')) return
    await shieldos.api.delete('/history')
    App.showToast('Scan history cleared', 'success')
    if (State.currentPage === 'history') App.loadHistory()
  },

  // ── Settings ───────────────────────────────────────────────────────────

  async loadConfig() {
    const cfg = await shieldos.api.get('/config')
    if (cfg.error) return
    State.config = cfg

    App.setCheckbox('cfg-realtime',       cfg.realtime_enabled)
    App.setCheckbox('cfg-archives',       cfg.scan_archives)
    App.setCheckbox('cfg-hidden',         cfg.scan_hidden)
    App.setCheckbox('cfg-auto-quarantine',cfg.quarantine_auto)
    App.setCheckbox('cfg-notifications',  cfg.notifications_enabled)
    App.setCheckbox('cfg-sched-enabled',  cfg.scheduled_scan_enabled)

    const heurIdx = HEUR_VALUES.indexOf(cfg.heuristics_level || 'medium')
    const heurEl  = document.getElementById('cfg-heuristics')
    if (heurEl) { heurEl.value = heurIdx >= 0 ? heurIdx : 1 }
    App.updateHeurLabel(heurEl?.value || 1)

    const sizeEl = document.getElementById('cfg-maxsize')
    if (sizeEl) { sizeEl.value = cfg.max_file_size_mb || 512 }
    App.updateMaxSizeLabel(sizeEl?.value || 512)

    const timeEl = document.getElementById('cfg-sched-time')
    if (timeEl) timeEl.value = cfg.scheduled_scan_time || '02:00'

    const vtEl = document.getElementById('cfg-vt-key')
    if (vtEl) vtEl.value = cfg.virustotal_api_key || ''

    // Also sync realtime toggle on realtime page
    const rtToggle = document.getElementById('rt-enabled-toggle')
    if (rtToggle) rtToggle.checked = cfg.realtime_enabled
  },

  async saveSettings() {
    const heurIdx = parseInt(document.getElementById('cfg-heuristics')?.value || 1)
    const cfg = {
      realtime_enabled:       App.getCheckbox('cfg-realtime'),
      scan_archives:          App.getCheckbox('cfg-archives'),
      scan_hidden:            App.getCheckbox('cfg-hidden'),
      quarantine_auto:        App.getCheckbox('cfg-auto-quarantine'),
      notifications_enabled:  App.getCheckbox('cfg-notifications'),
      scheduled_scan_enabled: App.getCheckbox('cfg-sched-enabled'),
      scheduled_scan_time:    document.getElementById('cfg-sched-time')?.value || '02:00',
      heuristics_level:       HEUR_VALUES[heurIdx] || 'medium',
      max_file_size_mb:       parseInt(document.getElementById('cfg-maxsize')?.value || 512),
      virustotal_api_key:     document.getElementById('cfg-vt-key')?.value || '',
    }

    const res = await shieldos.api.post('/config', { config: cfg })
    if (res.error) {
      App.showToast('Save failed: ' + res.error, 'threat')
    } else {
      State.config = res
      App.showToast('Settings saved', 'success')
      await App.loadStatus()
    }
  },

  updateHeurLabel(val) {
    App.setText('heur-level-label', HEUR_LABELS[parseInt(val)] || 'Medium')
  },

  updateMaxSizeLabel(val) {
    App.setText('maxsize-label', `${val} MB`)
  },

  toggleVTKeyVisibility() {
    const el = document.getElementById('cfg-vt-key')
    if (el) el.type = el.type === 'password' ? 'text' : 'password'
  },

  async loadYARARules() {
    const data = await shieldos.api.get('/rules')
    const el   = document.getElementById('yara-rule-list')
    if (!el) return
    if (Array.isArray(data)) {
      el.textContent = data.length > 0
        ? `${data.length} rule set${data.length !== 1 ? 's' : ''} loaded: ${data.join(', ')}`
        : 'No rules loaded'
    }
  },

  async reloadYARA() {
    const res = await shieldos.api.post('/rules/reload')
    if (res.error) {
      App.showToast('YARA reload failed: ' + res.error, 'threat')
    } else {
      App.showToast('YARA rules reloaded', 'success')
      await App.loadYARARules()
    }
  },

  // ── Toast notifications ────────────────────────────────────────────────

  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container')
    if (!container) return
    const el = document.createElement('div')
    el.className = `toast ${type}`
    el.textContent = message
    container.appendChild(el)
    setTimeout(() => {
      el.style.transition = 'opacity 0.3s'
      el.style.opacity = '0'
      setTimeout(() => el.remove(), 300)
    }, type === 'threat' ? 6000 : 3500)
  },

  // ── Utilities ──────────────────────────────────────────────────────────

  basename(path) {
    if (!path) return ''
    return path.split(/[\\/]/).pop() || path
  },

  esc(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
  },

  setText(id, text) {
    const el = document.getElementById(id)
    if (el) el.textContent = String(text)
  },

  setCheckbox(id, val) {
    const el = document.getElementById(id)
    if (el) el.checked = Boolean(val)
  },

  getCheckbox(id) {
    return document.getElementById(id)?.checked ?? false
  },

  formatNum(n) {
    return Number(n || 0).toLocaleString()
  },

  formatDate(iso) {
    if (!iso) return '—'
    try {
      const d = new Date(iso)
      return d.toLocaleDateString() + ' ' + d.toTimeString().slice(0, 8)
    } catch { return iso }
  },

  formatUptime(secs) {
    const h = Math.floor(secs / 3600)
    const m = Math.floor((secs % 3600) / 60)
    return h > 0 ? `${h}h ${m}m` : `${m}m`
  },

  severityBadge(severity) {
    const map = {
      critical: 'badge-crit',  crit: 'badge-crit',
      high: 'badge-high',      med: 'badge-med',
      medium: 'badge-med',     low: 'badge-low',
    }
    const cls = map[severity?.toLowerCase()] || 'badge-clean'
    return `<span class="badge ${cls}">${severity || '—'}</span>`
  },
}

// ── Bootstrap ──────────────────────────────────────────────────────────────
window.App = App
document.addEventListener('DOMContentLoaded', () => App.init())
