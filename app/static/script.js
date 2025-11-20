/* Suspicious Link Radar – Frontend
   Tasarım korunur; istek gönderme ve telemetri gösterimi güçlendirildi.
*/
(function () {
  // ==== CONFIG (dinamik base URL + health) ====
  const DEFAULT_PORT = 8081;
  const API_BASE = resolveApiBase();
  let apiHealthy = false;

  function resolveApiBase() {
    const loc = window.location;
    if (loc.protocol === 'http:' || loc.protocol === 'https:') {
      return loc.port ? `${loc.protocol}//${loc.hostname}:${loc.port}` : `${loc.protocol}//${loc.hostname}:${DEFAULT_PORT}`;
    }
    return `http://127.0.0.1:${DEFAULT_PORT}`;
  }

  async function initialHealthCheck() {
    const candidates = [`${API_BASE}/health`, `${API_BASE}/api/health`];
    for (const url of candidates) {
      try {
        const res = await fetch(url, { cache: 'no-store' });
        if (res.ok) {
          apiHealthy = true;
          setApiStatus('Hazır');
          return;
        }
      } catch (_) {}
    }
    apiHealthy = false;
    setApiStatus('Kapalı');
    addConsoleLog('error', 'Health check başarısız: ' + API_BASE);
    showToast('warn', 'Backend ulaşılamıyor. Önce sunucuyu başlatın.');
  }

  function setApiStatus(txt) {
    const el = document.getElementById('apiStatus');
    if (el) el.textContent = txt;
  }

  // ---- DOM ----
  const radarCanvas = id('radarCanvas');
  const radarContainer = id('radarContainer');
  const scanBtn = id('scanBtn');
  const urlInput = id('urlInput');
  const speedValue = id('speedValue');
  const telemetryPanel = id('telemetryPanel');
  const loadingState = id('loadingState');
  const gaugeNeedle = id('gaugeNeedle');
  const dialNeedle = id('dialNeedle');
  const telemetrySignal = id('telemetrySignal');
  const consoleStream = id('consoleStream');
  const toastStack = id('toastStack');
  const themeBtn = id('themeBtn');
  const debugBtn = id('debugBtn');
  const modalOverlay = id('modalOverlay');
  const modalTitle = id('modalTitle');
  const modalBody = id('modalBody');
  const modalCloseBtn = id('modalCloseBtn');

  // ---- Metrics ----
  const metricClassification = id('metricClassification');
  const metricConfidence = id('metricConfidence');
  const metricThreatLevel = id('metricThreatLevel');
  const metricPhishing = id('metricPhishing');
  const metricMalware = id('metricMalware');
  const metricDeface = id('metricDeface');

  // ---- Session ----
  const scanCountEl = id('scanCount');
  const errorCountEl = id('errorCount');
  const themeStateEl = id('themeState');
  const statusPings = id('statusPings');
  const apiStatus = id('apiStatus');
  const apiLatency = id('apiLatency');
  const lastResponse = id('lastResponse');

  // ---- State ----
  let scanCount = 0;
  let errorCount = 0;
  let radarCtx;
  let pingCounter = 0;
  let themeMode = 'dark';
  let scanning = false;
  let artificialSpeed = 0;

  // ---- Init ----
  function init() {
    prepareRadarCanvas();
    addConsoleLog('info', 'UI hazır (BASE=' + API_BASE + ')');
    bindEvents();
    randomPingBurst(3);
    setText('totalRecords', '640K+');
    showToast('safe', 'Arayüz Hazır');
    initialHealthCheck();
  }

  // ---- Radar ----
  function prepareRadarCanvas() {
    radarCanvas.width = radarCanvas.clientWidth;
    radarCanvas.height = radarCanvas.clientHeight;
    radarCtx = radarCanvas.getContext('2d');
    drawStaticGrid();
  }
  function drawStaticGrid() {
    const w = radarCanvas.width, h = radarCanvas.height;
    radarCtx.clearRect(0, 0, w, h);
    radarCtx.save();
    radarCtx.translate(w / 2, h / 2);
    const rings = 5;
    for (let i = 1; i <= rings; i++) {
      const r = (Math.min(w, h) / 2) * (i / rings);
      radarCtx.beginPath();
      radarCtx.arc(0, 0, r, 0, Math.PI * 2);
      radarCtx.strokeStyle = `rgba(255,69,0,${0.08 + i * 0.03})`;
      radarCtx.lineWidth = 1;
      radarCtx.stroke();
    }
    for (let a = 0; a < 360; a += 30) {
      radarCtx.beginPath();
      radarCtx.moveTo(0, 0);
      const rad = (a * Math.PI) / 180;
      radarCtx.lineTo(Math.cos(rad) * w / 2, Math.sin(rad) * h / 2);
      radarCtx.strokeStyle = 'rgba(255,69,0,0.15)';
      radarCtx.stroke();
    }
    radarCtx.restore();
  }

  // ---- Ping ----
  function placePing(xPercent, yPercent, threatScore) {
    const ping = document.createElement('div');
    ping.className = 'radar-ping';
    const size = 14 + Math.floor(threatScore * 10);
    ping.style.width = size + 'px';
    ping.style.height = size + 'px';
    ping.style.left = `calc(${xPercent}% - ${size / 2}px)`;
    ping.style.top = `calc(${yPercent}% - ${size / 2}px)`;
    ping.style.animationDuration = (2 + threatScore) + 's';
    radarContainer.appendChild(ping);
    pingCounter++;
    if (statusPings) statusPings.textContent = `PINGS: ${pingCounter}`;
    setTimeout(() => { if (ping.isConnected) ping.remove(); }, 3500);
  }
  function randomPingBurst(n = 1) { for (let i = 0; i < n; i++) placePing(10 + Math.random() * 80, 10 + Math.random() * 80, Math.random()); }

  // ---- Scan Flow ----
  async function startScan() {
    if (scanning) return;
    const targetUrl = urlInput.value.trim();
    if (!targetUrl) {
      showToast('warn', 'URL giriniz.');
      urlInput.focus();
      return;
    }
    if (!apiHealthy) {
      addConsoleLog('error', 'Backend kapalı veya ulaşılamıyor: ' + API_BASE);
      showToast('danger', 'Önce backend’i başlatın (uvicorn).');
      return;
    }
    scanning = true;
    scanBtn.disabled = true;
    urlInput.disabled = true;
    toggleLoading(true);
    addConsoleLog('info', 'Tarama başlatıldı');
    showToast('safe', 'Tarama başladı');
    artificialSpeed = 0;
    animateSpeedIncrease();

    const t0 = performance.now();
    let result;
    try {
      result = await fetchPrediction(targetUrl);
      const latency = Math.round(performance.now() - t0);
      if (apiLatency) apiLatency.textContent = latency + ' ms';
      if (lastResponse) lastResponse.textContent = new Date().toLocaleTimeString();
    } catch (e) {
      errorCount++;
      if (errorCountEl) errorCountEl.textContent = errorCount;
      if (apiStatus) apiStatus.textContent = 'Hata';
      addConsoleLog('error', 'API hata: ' + e.message);
      showToast('danger', 'API isteği başarısız, fallback');
      result = buildFallbackResult(targetUrl);
    }
    updateTelemetry(result);
    finalizeScan();
  }

  function animateSpeedIncrease() {
    if (!scanning) return;
    artificialSpeed += Math.random() * 14 + 4;
    if (artificialSpeed > 320) artificialSpeed = 320;
    speedValue.textContent = artificialSpeed.toFixed(0).padStart(3, '0');
    if (artificialSpeed < 320) requestAnimationFrame(animateSpeedIncrease);
  }

  // ---- API ----
  async function fetchPrediction(url) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const endpoints = [
      `${API_BASE}/predict`,
      `${API_BASE}/api/predict`,
    ];

    let lastErr;
    for (const ep of endpoints) {
      try {
        addConsoleLog('info', 'POST ' + ep);
        // 1) POST ile dene
        let res = await fetch(ep, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({ url }),
          signal: controller.signal,
          mode: 'cors',
          credentials: 'omit'
        });

        // 405 ise GET moduna düş
        if (res.status === 405) {
          addConsoleLog('warn', '405 -> GET moduna düşülüyor: ' + ep);
          res = await fetch(`${ep}?url=${encodeURIComponent(url)}`, {
            method: 'GET',
            headers: { 'Accept': 'application/json' },
            signal: controller.signal,
            mode: 'cors',
            credentials: 'omit'
          });
        }

        if (!res.ok) throw new Error('HTTP ' + res.status);
        const raw = await res.json();
        clearTimeout(timeout);
        addConsoleLog('info', 'API yanıt: ' + JSON.stringify(raw));
        if (apiStatus) apiStatus.textContent = 'OK';
        return normalizeApiResponse(raw);
      } catch (e) {
        lastErr = e;
        addConsoleLog('error', `Endpoint hatası (${ep}): ${e.message}`);
      }
    }

    clearTimeout(timeout);
    throw lastErr || new Error('API erişilemedi');
  }

  function normalizeApiResponse(data) {
    if (!data || typeof data !== 'object') {
      return buildFallbackResult('N/A');
    }
    const rawPred = (data.prediction || data.label || data.class || data.result || 'unknown').toString().toLowerCase();
    const probsRaw = data.probabilities || data.probs || data.scores || data.proba || {};
    const get = (...keys) => {
      for (const k of keys) {
        if (probsRaw[k] !== undefined && probsRaw[k] !== null) return parseFloat(probsRaw[k]);
      }
      return 0;
    };
    const benign = get('benign', 'safe', 'normal');
    const phishing = get('phishing', 'phish');
    const malware = get('malware', 'malicious');
    const defacement = get('defacement', 'deface', 'defacement_attack');
    const map = { benign, phishing, malware, defacement };
    let classification = rawPred;
    if (!Object.keys(map).includes(classification)) {
      classification = Object.entries(map).sort((a, b) => b[1] - a[1])[0][0];
    }
    return { url: data.url || data.target || 'N/A', classification, probabilities: map };
  }

  function buildFallbackResult(url) {
    return {
      url,
      classification: 'benign',
      probabilities: { benign: 0.82, phishing: 0.09, malware: 0.05, defacement: 0.04 }
    };
  }

  function finalizeScan() {
    scanning = false;
    scanCount++;
    scanCountEl.textContent = scanCount;
    scanBtn.disabled = false;
    urlInput.disabled = false;
    toggleLoading(false);
    speedValue.textContent = '000';
    artificialSpeed = 0;
    addConsoleLog('info', 'Tarama tamamlandı');
  }

  function toggleLoading(flag) {
    loadingState.classList.toggle('hidden', !flag);
  }

  // ---- Telemetry ----
  function updateTelemetry(result) {
    telemetryPanel.classList.remove('hidden');
    const { classification, probabilities } = result;
    metricClassification.textContent = classification.toUpperCase();
    const conf = computeConfidence(probabilities, classification);
    metricConfidence.textContent = (conf * 100).toFixed(1) + '%';
    metricPhishing.textContent = (probabilities.phishing * 100).toFixed(1) + '%';
    metricMalware.textContent = (probabilities.malware * 100).toFixed(1) + '%';
    metricDeface.textContent = (probabilities.defacement * 100).toFixed(1) + '%';
    const threatScore = Math.max(probabilities.phishing, probabilities.malware, probabilities.defacement);
    metricThreatLevel.textContent = (threatScore * 100).toFixed(1) + '%';
    moveLinearGauge(threatScore);
    moveCircularDial(threatScore);
    updateTelemetrySignal(threatScore, classification);
    addConsoleLog('info', `CLS=${classification} THREAT=${(threatScore * 100).toFixed(1)}%`);
    placePing(15 + Math.random() * 70, 15 + Math.random() * 70, threatScore);
    if (classification === 'benign') {
      showToast('safe', 'URL güvenli');
    } else if (threatScore > 0.6) {
      showToast('danger', 'Yüksek tehdit: ' + classification);
    } else {
      showToast('warn', 'Orta risk: ' + classification);
    }
  }

  function computeConfidence(probs, classification) {
    const k = classification.toLowerCase();
    return probs[k] !== undefined ? probs[k] : 0;
  }

  function moveLinearGauge(threatScore) {
    const track = id('linearGauge');
    if (!track) return;
    const trackWidth = track.offsetWidth;
    const offset = threatScore * (trackWidth - 8);
    gaugeNeedle.style.left = Math.max(4, offset) + 'px';
  }

  function moveCircularDial(threatScore) {
    const angle = -45 + 270 * threatScore;
    dialNeedle.style.transform = `translate(-50%,-100%) rotate(${angle}deg)`;
  }

  function updateTelemetrySignal(threatScore, classification) {
    telemetrySignal.className = 'telemetry-signal';
    if (classification === 'benign' && threatScore < 0.3) {
      telemetrySignal.style.background = 'var(--status-safe)';
    } else if (threatScore < 0.6) {
      telemetrySignal.style.background = 'var(--status-caution)';
      telemetrySignal.classList.add('idle');
    } else {
      telemetrySignal.style.background = 'var(--status-danger)';
      telemetrySignal.classList.add('offline');
    }
  }

  // ---- Console / Toast ----
  function addConsoleLog(type, msg) {
    const line = document.createElement('div');
    line.className = 'log-line';
    const ts = document.createElement('div');
    ts.className = 'log-timestamp';
    ts.textContent = new Date().toLocaleTimeString();
    const ev = document.createElement('div');
    ev.className = 'log-event ' + type;
    ev.textContent = msg;
    line.appendChild(ts); line.appendChild(ev);
    consoleStream.appendChild(line);
    consoleStream.scrollTop = consoleStream.scrollHeight;
  }

  function showToast(kind, text) {
    const toast = document.createElement('div');
    toast.className = 'toast ' + kind;
    toast.innerHTML = `<span style="font-weight:700;">${kind.toUpperCase()}</span>
      <span style="flex:1;">${text}</span>
      <button class="toast-close" aria-label="Kapat">×</button>`;
    toastStack.appendChild(toast);
    toast.querySelector('.toast-close').addEventListener('click', () => toast.remove());
    setTimeout(() => { if (toast.isConnected) toast.remove(); }, 6000);
  }

  // ---- Modal / Theme / Help ----
  function openModal(title, html) {
    modalTitle.textContent = title;
    modalBody.innerHTML = html;
    modalOverlay.classList.remove('hidden');
  }
  function closeModal() { modalOverlay.classList.add('hidden'); }

  function toggleTheme() {
    if (themeMode === 'dark') { document.body.classList.add('theme-pit'); themeMode = 'pit'; }
    else { document.body.classList.remove('theme-pit'); themeMode = 'dark'; }
    themeStateEl.textContent = themeMode;
    const st = id('statusTheme'); if (st) st.textContent = themeMode.toUpperCase();
    showToast('safe', 'Tema: ' + themeMode);
  }
  function toggleDebugOutline() { document.body.classList.toggle('outline-debug'); }

  function showHelpModal() {
    openModal('Yardım', `
      <p><strong>Tarama:</strong> Backend çalışıyor olmalı (uvicorn app.main:app --port ${DEFAULT_PORT}).</p>
      <p><strong>URL gir:</strong> https://...</p>
      <p><strong>Enter:</strong> Hızlı tarama.</p>
      <p><strong>Gauge/Dial:</strong> En yüksek tehdit alt sınıflardan.</p>
      <p><strong>Fallback:</strong> Ağ hatasında sahte değerler.</p>
    `);
  }

  // ---- Events ----
  function bindEvents() {
    scanBtn && scanBtn.addEventListener('click', startScan);
    urlInput && urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });
    themeBtn && themeBtn.addEventListener('click', toggleTheme);
    debugBtn && debugBtn.addEventListener('click', toggleDebugOutline);
    modalCloseBtn && modalCloseBtn.addEventListener('click', closeModal);
    const sec = id('statusSecurity'); sec && sec.addEventListener('dblclick', showHelpModal);
  }

  // ---- Utils ----
  function id(x) { return document.getElementById(x); }
  function setText(x, v) { const el = id(x); if (el) el.textContent = v; }

  // ---- Start ----
  init();
})();