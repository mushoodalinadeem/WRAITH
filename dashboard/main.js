/**
 * main.js — WRAITH Dashboard Controller v3
 *
 * Features:
 *   - Chart.js real-time attack timeline (30-second buckets)
 *   - SSE live feed with auto-reconnect
 *   - Three threat states: Normal / Warning / Alert
 *   - Color-coded attack type chips
 *   - Forensic detail panel via /logs/<id>
 *   - Stats polling every 5 seconds
 */

// ────────────────────────────────────────────────
// Constants — mirror config.py values
// ────────────────────────────────────────────────
const THRESHOLD_WARNING  = 40;
const THRESHOLD_ALERT    = 70;
const TERMINAL_MAX_ROWS  = 60;
const TABLE_MAX_ROWS     = 100;
const STATS_POLL_MS      = 5000;
const CHART_BUCKET_MS    = 30000;   // 30-second chart buckets
const CHART_MAX_BUCKETS  = 20;      // keep last 20 buckets visible

// ────────────────────────────────────────────────
// Attack type → styling metadata
// ────────────────────────────────────────────────
const ATTACK_META = {
  'SQL Injection':          { chip:'chip-sql',   bkBar:'bk-sql',   bkCnt:'cnt-sql',   chartColor:'rgba(245,158,11,0.85)',  label:'SQL' },
  'XSS':                    { chip:'chip-xss',   bkBar:'bk-xss',   bkCnt:'cnt-xss',   chartColor:'rgba(96,165,250,0.85)',  label:'XSS' },
  'HTTP Flood':             { chip:'chip-flood', bkBar:'bk-flood', bkCnt:'cnt-flood', chartColor:'rgba(239,68,68,0.85)',   label:'Flood' },
  'Web Brute Force':        { chip:'chip-brute', bkBar:'bk-brute', bkCnt:'cnt-brute', chartColor:'rgba(167,139,250,0.85)', label:'Brute' },
  'Directory Enumeration':  { chip:'chip-enum',  bkBar:'bk-enum',  bkCnt:'cnt-enum',  chartColor:'rgba(52,211,153,0.85)',  label:'Enum' },
  'File Disclosure':        { chip:'chip-file',  bkBar:'bk-file',  bkCnt:'cnt-file',  chartColor:'rgba(251,146,60,0.85)',  label:'File' },
  'CRLF Injection':         { chip:'chip-crlf',  bkBar:'bk-crlf',  bkCnt:'cnt-crlf',  chartColor:'rgba(244,114,182,0.85)', label:'CRLF' },
  'Buffer Overflow':        { chip:'chip-buf',   bkBar:'bk-buf',   bkCnt:'cnt-buf',   chartColor:'rgba(250,204,21,0.85)',  label:'BufOvf' },
};

// ────────────────────────────────────────────────
// State
// ────────────────────────────────────────────────
let _eventSource    = null;
let _terminalPaused = false;
let _currentState   = 'normal';
let _activeRowId    = null;
let _pausedBuffer   = [];
let _sseStartId     = 0;

// ────────────────────────────────────────────────
// Utilities
// ────────────────────────────────────────────────
function _esc(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#x27;')
    .replace(/\//g,'&#x2F;');
}

function _fmtTime(ts) {
  if (!ts) return '--:--:--';
  try {
    const d = new Date(ts.includes('T') ? ts : ts.replace(' ','T')+'Z');
    return d.toLocaleTimeString('en-GB',{hour12:false});
  } catch { return (ts+'').substring(0,8)||'--:--:--'; }
}

function _scoreState(s) {
  if (s >= THRESHOLD_ALERT)   return 'alert';
  if (s >= THRESHOLD_WARNING) return 'warning';
  return 'normal';
}

function _scoreClass(s) {
  if (s >= THRESHOLD_ALERT)   return 'score-alert';
  if (s >= THRESHOLD_WARNING) return 'score-warning';
  return 'score-normal';
}

function _attackChipHTML(type) {
  const m = ATTACK_META[type];
  const cls = m ? m.chip : 'chip-normal';
  return `<span class="attack-chip ${cls}">${_esc(type||'Normal')}</span>`;
}

function _layerClass(layer) {
  if (layer === 'ml')       return 'layer-ml';
  if (layer === 'rule')     return 'layer-rule';
  if (layer === 'fallback') return 'layer-fallback';
  return '';
}

function _termLineClass(log) {
  const s = log.threat_score || 0;
  if (s >= THRESHOLD_ALERT)   return 't-line--alert';
  if (s >= THRESHOLD_WARNING) return 't-line--warn';
  if (log.attack_type && log.attack_type !== 'Normal') return 't-line--attack';
  return 't-line--normal';
}

// ────────────────────────────────────────────────
// Clock
// ────────────────────────────────────────────────
function _startClock() {
  const el = document.getElementById('sys-time');
  const tick = () => { el.textContent = new Date().toLocaleTimeString('en-GB',{hour12:false}); };
  tick(); setInterval(tick, 1000);
}

// ────────────────────────────────────────────────
// Threat State
// ────────────────────────────────────────────────
function updateThreatMeter(score) {
  const newState = _scoreState(score);
  const pct      = Math.min(score, 100);
  const circumference = 2 * Math.PI * 52; // r=52

  document.getElementById('threat-score').textContent = String(score).padStart(3,'0');
  document.getElementById('threat-bar').style.width = pct + '%';

  // SVG ring offset: full circle = 326.7, empty = 326.7, filled = 0
  const offset = circumference - (pct / 100) * circumference;
  const ring = document.getElementById('ring-fg');
  if (ring) ring.style.strokeDashoffset = offset.toFixed(1);

  const labelEl = document.getElementById('threat-label');
  if      (newState === 'alert')   labelEl.textContent = '!! ALERT !!';
  else if (newState === 'warning') labelEl.textContent = '⚠ WARNING';
  else                              labelEl.textContent = 'NORMAL';

  if (newState !== _currentState) {
    document.body.classList.remove('state-normal','state-warning','state-alert');
    document.body.classList.add('state-' + newState);

    // Glitch animation on escalation
    const el = document.getElementById('threat-score');
    el.classList.remove('glitch');
    void el.offsetWidth;
    el.classList.add('glitch');
    setTimeout(() => el.classList.remove('glitch'), 350);

    _currentState = newState;
  }
}

function _setLastAttackTime(ts) {
  document.getElementById('last-attack-ts').textContent = _fmtTime(ts) || '—';
}

// ────────────────────────────────────────────────
// Chart.js — Real-time Attack Timeline
// ────────────────────────────────────────────────
const _Chart = (() => {
  let chart    = null;
  let buckets  = [];  // [{timeMs, label, counts:{type:n}}]
  let _ticker  = null;

  // Chart.js color config per attack type
  const DATASETS_CFG = Object.entries(ATTACK_META).map(([type, meta]) => ({
    label:           meta.label,
    attackType:      type,
    borderColor:     meta.chartColor,
    backgroundColor: meta.chartColor.replace('0.85','0.12'),
    data:            [],
    borderWidth:     1.5,
    pointRadius:     3,
    pointHoverRadius:5,
    tension:         0.3,
    fill:            false,
  }));

  function _updateChartData() {
    if (!chart) return;
    chart.data.labels = buckets.map(b => b.label);
    chart.data.datasets.forEach(ds => {
      ds.data = buckets.map(b => b.counts[ds.attackType] || 0);
    });
    chart.update('none');
  }

  function init() {
    const ctx = document.getElementById('attack-chart');
    if (!ctx || !window.Chart) return;

    Chart.defaults.color = '#38bdf8';
    Chart.defaults.borderColor = 'rgba(14,165,233,0.18)';

    // Pre-populate buckets for the last 10 minutes
    const nowMs = Date.now();
    buckets = [];
    for (let i = CHART_MAX_BUCKETS - 1; i >= 0; i--) {
      const bTime = new Date(nowMs - i * CHART_BUCKET_MS);
      buckets.push({
        timeMs: bTime.getTime(),
        label: bTime.toLocaleTimeString('en-GB', { hour12: false }),
        counts: Object.fromEntries(Object.keys(ATTACK_META).map(t => [t, 0]))
      });
    }

    chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: DATASETS_CFG,
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 400 },
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: {
            display: true,
            position: 'top',
            labels: {
              color: '#bae6fd',
              font:  { family: "'Share Tech Mono', monospace", size: 10 },
              boxWidth: 12,
              padding: 14,
              filter: (item) => {
                const ds = chart.data.datasets[item.datasetIndex];
                return ds && ds.data.some(v => v > 0);
              }
            }
          },
          tooltip: {
            backgroundColor: 'rgba(4,6,8,0.95)',
            borderColor: 'rgba(14,165,233,0.3)',
            borderWidth: 1,
            titleColor: '#0ea5e9',
            bodyColor: '#f0f9ff',
            titleFont: { family: "'Share Tech Mono', monospace", size: 11 },
            bodyFont:  { family: "'Share Tech Mono', monospace", size: 10 },
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(14,165,233,0.06)' },
            ticks: {
              color: 'rgba(14,165,233,0.35)',
              font: { family: "'Share Tech Mono', monospace", size: 9 },
              maxTicksLimit: 8,
            }
          },
          y: {
            grid: { color: 'rgba(14,165,233,0.06)' },
            ticks: {
              color: 'rgba(14,165,233,0.35)',
              font: { family: "'Share Tech Mono', monospace", size: 9 },
              stepSize: 1,
            },
            beginAtZero: true,
          }
        }
      }
    });

    _updateChartData();

    // Auto-tick every CHART_BUCKET_MS
    _ticker = setInterval(_commitBucket, CHART_BUCKET_MS);
  }

  function addEvent(log) {
    const type = log.attack_type;
    if (!type || type === 'Normal') return;

    // Parse log timestamp
    let logMs = Date.now();
    if (log.timestamp) {
      try {
        const tsStr = log.timestamp.includes('T') ? log.timestamp : log.timestamp.replace(' ', 'T') + 'Z';
        logMs = new Date(tsStr).getTime();
      } catch {
        logMs = Date.now();
      }
    }

    // Find chronological bucket
    for (let i = buckets.length - 1; i >= 0; i--) {
      const b = buckets[i];
      if (logMs >= b.timeMs) {
        if (i === buckets.length - 1 || logMs < buckets[i+1].timeMs) {
          if (b.counts[type] !== undefined) {
            b.counts[type]++;
            _updateChartData();
          }
          break;
        }
      }
    }
  }

  function _commitBucket() {
    if (!chart) return;

    const now = new Date();
    buckets.push({
      timeMs: now.getTime(),
      label: now.toLocaleTimeString('en-GB', { hour12: false }),
      counts: Object.fromEntries(Object.keys(ATTACK_META).map(t => [t, 0]))
    });

    if (buckets.length > CHART_MAX_BUCKETS) {
      buckets.shift();
    }

    _updateChartData();
  }

  function flush() { _updateChartData(); }

  return { init, addEvent, flush };
})();

// ────────────────────────────────────────────────
// Terminal
// ────────────────────────────────────────────────
function addTerminalLine(log) {
  if (_terminalPaused) {
    _pausedBuffer.push({ type: 'log', data: log });
    if (_pausedBuffer.length > TERMINAL_MAX_ROWS) _pausedBuffer.shift();
    return;
  }
  const el = document.getElementById('terminal');

  const line = document.createElement('div');
  line.className = 't-line ' + _termLineClass(log);

  const score    = log.threat_score || 0;
  const prefix   = (log.attack_type && log.attack_type !== 'Normal') ? '▶' : '·';
  const typeDisp = (log.attack_type || 'Normal').toUpperCase().substring(0, 14);

  line.innerHTML =
    `<span class="t-ts">${_esc(_fmtTime(log.timestamp))}</span>` +
    `<span class="t-ip">${_esc((log.ip_address||'?.?.?.?').padEnd(15))}</span>` +
    `<span class="t-met">${_esc((log.method||'GET').padEnd(5))}</span>` +
    `<span class="t-pth">${_esc((log.path||'/').substring(0,28))}</span>` +
    `<span class="t-atk">${prefix} ${_esc(typeDisp)}</span>` +
    `<span class="t-scr">[${score}]</span>`;

  el.appendChild(line);
  while (el.children.length > TERMINAL_MAX_ROWS) el.removeChild(el.firstChild);
  
  // Defer scrolling to prevent layout thrashing (synchronous reflow)
  requestAnimationFrame(() => {
    el.scrollTop = el.scrollHeight;
  });
}

function _addTermSysLine(msg) {
  if (_terminalPaused) {
    _pausedBuffer.push({ type: 'sys', data: msg });
    if (_pausedBuffer.length > TERMINAL_MAX_ROWS) _pausedBuffer.shift();
    return;
  }
  const el = document.getElementById('terminal');
  const line = document.createElement('div');
  line.className = 't-line t-line--sys';
  line.innerHTML = `<span class="t-ts">SYSTEM</span><span>${_esc(msg)}</span>`;
  el.appendChild(line);
  
  // Defer scrolling to prevent layout thrashing
  requestAnimationFrame(() => {
    el.scrollTop = el.scrollHeight;
  });
}

function pauseTerminal() {
  _terminalPaused = !_terminalPaused;
  const btn = document.querySelector('.btn-sm[onclick="pauseTerminal()"]');
  if (btn) btn.textContent = _terminalPaused ? 'RESUME' : 'PAUSE';

  if (!_terminalPaused && _pausedBuffer.length > 0) {
    _pausedBuffer.forEach(item => {
      if (item.type === 'log') {
        addTerminalLine(item.data);
      } else if (item.type === 'sys') {
        _addTermSysLine(item.data);
      }
    });
    _pausedBuffer = [];
  }
}

function clearTerminal() {
  document.getElementById('terminal').innerHTML = '';
  _addTermSysLine('Terminal cleared.');
}

// ────────────────────────────────────────────────
// Table
// ────────────────────────────────────────────────
function addTableRow(log) {
  const tbody = document.getElementById('log-tbody');
  const empty = tbody.querySelector('.empty-row');
  if (empty) empty.remove();

  while (tbody.children.length >= TABLE_MAX_ROWS) tbody.removeChild(tbody.lastChild);

  const score     = log.threat_score || 0;
  const state     = _scoreState(score);
  const type      = log.attack_type || 'Normal';

  const tr = document.createElement('tr');
  tr.dataset.id = log.id;
  tr.classList.add('row-new');
  if (state === 'alert')        tr.classList.add('row--alert');
  else if (state === 'warning') tr.classList.add('row--warn');
  else if (type !== 'Normal')   tr.classList.add('row--attack');

  tr.innerHTML =
    `<td>${_esc(String(log.id))}</td>` +
    `<td>${_esc(_fmtTime(log.timestamp))}</td>` +
    `<td>${_esc(log.ip_address||'?')}</td>` +
    `<td>${_esc(log.method||'GET')}</td>` +
    `<td title="${_esc(log.path||'/')}">${_esc((log.path||'/').substring(0,24))}</td>` +
    `<td>${_attackChipHTML(type)}</td>` +
    `<td><span class="score-badge ${_scoreClass(score)}">${score}</span></td>` +
    `<td><span class="layer-badge ${_layerClass(log.layer)}">${_esc((log.layer||'none').toUpperCase())}</span></td>`;

  tr.addEventListener('click', () => showForensicDetail(log.id, tr));
  tbody.insertBefore(tr, tbody.firstChild);
}

// ────────────────────────────────────────────────
// Forensic Detail
// ────────────────────────────────────────────────
async function showForensicDetail(logId, clickedRow) {
  if (_activeRowId) {
    const prev = document.querySelector(`tr[data-id="${_activeRowId}"]`);
    if (prev) prev.classList.remove('row--active');
  }
  if (clickedRow) clickedRow.classList.add('row--active');
  _activeRowId = logId;

  document.getElementById('forensic-id').textContent = `ENTRY #${logId}`;
  document.getElementById('forensic-content').innerHTML =
    '<div class="forensic-empty">[ LOADING... ]</div>';

  try {
    const res  = await fetch(`/logs/${logId}`);
    const data = await res.json();
    if (!res.ok || data.status !== 'ok') throw new Error(data.message || 'Request failed');
    _renderForensicDetail(data.log);
  } catch (err) {
    document.getElementById('forensic-content').innerHTML =
      `<div class="forensic-empty">[ ERROR: ${_esc(err.message)} ]</div>`;
  }
}

function _renderForensicDetail(log) {
  const score  = log.threat_score || 0;
  const sClass = _scoreClass(score);
  const lClass = _layerClass(log.layer);

  document.getElementById('forensic-content').innerHTML = `
    <div class="forensic-grid">
      <div class="f-field">
        <div class="f-key">ATTACK TYPE</div>
        <div class="f-val">${_attackChipHTML(log.attack_type)}</div>
      </div>
      <div class="f-field">
        <div class="f-key">THREAT SCORE</div>
        <div class="f-val"><span class="score-badge ${sClass}">${score} / 100</span></div>
      </div>
      <div class="f-field">
        <div class="f-key">DETECTION LAYER</div>
        <div class="f-val"><span class="layer-badge ${lClass}">${_esc((log.layer||'none').toUpperCase())}</span></div>
      </div>
      <div class="f-field">
        <div class="f-key">CONFIDENCE</div>
        <div class="f-val">${log.confidence ? (log.confidence*100).toFixed(1)+'%' : 'N/A'}</div>
      </div>
      <div class="f-field">
        <div class="f-key">SOURCE IP</div>
        <div class="f-val">${_esc(log.ip_address||'?')}</div>
      </div>
      <div class="f-field">
        <div class="f-key">METHOD + PATH</div>
        <div class="f-val">${_esc(log.method||'GET')} ${_esc(log.path||'/')}</div>
      </div>
      <div class="f-field">
        <div class="f-key">TIMESTAMP</div>
        <div class="f-val">${_esc(log.timestamp||'?')}</div>
      </div>
      <div class="f-field">
        <div class="f-key">USER AGENT</div>
        <div class="f-val" title="${_esc(log.user_agent||'')}">
          ${_esc((log.user_agent||'—').substring(0,40))}
        </div>
      </div>
    </div>
    <div class="forensic-report">${_esc(log.report||'No report generated.')}</div>
    ${log.payload ? `
      <div class="f-payload-label">PAYLOAD CAPTURE</div>
      <div class="f-payload">${_esc(log.payload)}</div>` : ''}
  `;
}

// ────────────────────────────────────────────────
// Breakdown bars
// ────────────────────────────────────────────────
function _updateBreakdown(attacksByType) {
  if (!attacksByType) return;

  const vals = Object.values(attacksByType);
  const maxVal = vals.length ? Math.max(1, ...vals) : 1;

  Object.entries(ATTACK_META).forEach(([type, meta]) => {
    const cnt  = attacksByType[type] || 0;
    const pct  = (cnt / maxVal) * 100;
    const bar  = document.getElementById(meta.bkBar);
    const text = document.getElementById(meta.bkCnt);

    if (bar)  bar.style.width = pct + '%';
    if (text) text.textContent = cnt;
  });
}

// ────────────────────────────────────────────────
// API Stats Polling
// ────────────────────────────────────────────────
async function fetchStats() {
  try {
    const res  = await fetch('/stats');
    const data = await res.json();
    if (!res.ok || data.status !== 'ok') return;
    const s = data.stats;

    const total   = s.total_requests || 0;
    const attacks = s.total_attacks  || 0;

    document.getElementById('h-total').textContent    = total;
    document.getElementById('h-attacks').textContent  = attacks;
    document.getElementById('h-ml').textContent       = s.ml_hits || 0;
    document.getElementById('h-rule').textContent     = s.rule_hits || 0;
    document.getElementById('h-fallback').textContent = s.fallback_hits || 0;

    _updateBreakdown(s.attacks_by_type);

    // Roll threat score from max_score in 5-minute rolling window
    const maxScore = s.max_score || 0;
    updateThreatMeter(maxScore);
  } catch { /* non-critical */ }
}

// ────────────────────────────────────────────────
// SSE Connection
// ────────────────────────────────────────────────
function _processLog(log) {
  // Update starting ID for SSE stream to avoid double-processing on reconnect
  if (log.id && log.id > _sseStartId) {
    _sseStartId = log.id;
  }

  // Real-time counter updates (prevents visual lag between stats polls)
  const totalEl = document.getElementById('h-total');
  if (totalEl) {
    totalEl.textContent = parseInt(totalEl.textContent, 10) + 1;
  }
  if (log.attack_type && log.attack_type !== 'Normal') {
    const attacksEl = document.getElementById('h-attacks');
    if (attacksEl) {
      attacksEl.textContent = parseInt(attacksEl.textContent, 10) + 1;
    }
  }
  if (log.layer) {
    const layerEl = document.getElementById('h-' + log.layer);
    if (layerEl) {
      layerEl.textContent = parseInt(layerEl.textContent, 10) + 1;
    }
  }

  // Update threat meter for attacks - spike immediately if score is higher than currently shown
  const score = log.threat_score || 0;
  if (score > 0) {
    const currentScore = parseInt(document.getElementById('threat-score').textContent, 10) || 0;
    if (score > currentScore) {
      updateThreatMeter(score);
    }
  }

  // Update last attack timestamp for attacks
  if (log.attack_type && log.attack_type !== 'Normal') {
    _setLastAttackTime(log.timestamp);
  }

  // Chart
  _Chart.addEvent(log);

  // Terminal + table
  addTerminalLine(log);
  addTableRow(log);
}

function connectSSE() {
  if (_eventSource) { _eventSource.close(); _eventSource = null; }

  const statusEl = document.getElementById('conn-status');
  statusEl.className = 'badge badge--warn';
  statusEl.textContent = '◌ CONNECTING';

  _eventSource = new EventSource(`/stream?since_id=${_sseStartId}`);

  _eventSource.onopen = () => {
    statusEl.className = 'badge badge--ok';
    statusEl.textContent = '● STREAM OK';
    _addTermSysLine('SSE stream connected. Live monitoring active.');
  };

  _eventSource.onmessage = (evt) => {
    try { _processLog(JSON.parse(evt.data)); }
    catch { /* skip malformed */ }
  };

  _eventSource.onerror = () => {
    statusEl.className = 'badge badge--err';
    statusEl.textContent = '✕ DISCONNECTED';
    _addTermSysLine('Stream disconnected. Reconnecting in 3s...');
    _eventSource.close();
    setTimeout(connectSSE, 3000);
  };
}

// ────────────────────────────────────────────────
// Simulate attack
// ────────────────────────────────────────────────
async function simulateAttack() {
  _addTermSysLine('Triggering attack simulation sequence...');
  try {
    const res  = await fetch('/demo/run', { method: 'POST' });
    const data = await res.json();
    _addTermSysLine(data.message || 'Simulation triggered.');
  } catch (err) {
    _addTermSysLine('Simulation error: ' + err.message);
  }
}

// ────────────────────────────────────────────────
// Initial log load
// ────────────────────────────────────────────────
async function _loadInitialLogs() {
  try {
    const res  = await fetch('/logs?limit=25');
    const data = await res.json();
    if (!res.ok || data.status !== 'ok') return;

    // API returns newest-first — reverse to add oldest first
    const logs = [...(data.logs || [])].reverse();
    logs.forEach(log => {
      _Chart.addEvent(log);
      addTerminalLine(log);
      addTableRow(log);
    });

    _Chart.flush();

    if (logs.length) {
      _sseStartId = Math.max(...logs.map(l => l.id));
      const lastAttack = logs.slice().reverse().find(l => l.attack_type && l.attack_type !== 'Normal');
      if (lastAttack) _setLastAttackTime(lastAttack.timestamp);
    }
  } catch { /* non-critical */ }
}

// ────────────────────────────────────────────────
// Init
// ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  _startClock();
  _Chart.init();
  await _loadInitialLogs();
  await fetchStats();
  connectSSE();
  setInterval(fetchStats, STATS_POLL_MS);
});