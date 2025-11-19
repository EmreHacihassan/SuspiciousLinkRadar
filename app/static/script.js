/* Suspicious Link Radar – Cyber Racing Cockpit JS
   Uzun kapsamlı etkileşim mantığı
   - Radar çizim & ping
   - Tarama akışı & animasyon
   - API isteği (FastAPI /predict)
   - Metrik güncelleme (lineer + dairesel gauge)
   - Toast & konsol log sistemi
   - Tema / debug / modal
*/

(function() {
  // ---- DOM Seçimleri ----
  const radarCanvas = document.getElementById('radarCanvas');
  const radarContainer = document.getElementById('radarContainer');
  const scanBtn = document.getElementById('scanBtn');
  const urlInput = document.getElementById('urlInput');
  const speedValue = document.getElementById('speedValue');
  const telemetryPanel = document.getElementById('telemetryPanel');
  const loadingState = document.getElementById('loadingState');
  const gaugeNeedle = document.getElementById('gaugeNeedle');
  const dialNeedle = document.getElementById('dialNeedle');
  const telemetrySignal = document.getElementById('telemetrySignal');
  const consoleStream = document.getElementById('consoleStream');
  const toastStack = document.getElementById('toastStack');
  const themeBtn = document.getElementById('themeBtn');
  const debugBtn = document.getElementById('debugBtn');
  const modalOverlay = document.getElementById('modalOverlay');
  const modalTitle = document.getElementById('modalTitle');
  const modalBody = document.getElementById('modalBody');
  const modalCloseBtn = document.getElementById('modalCloseBtn');

  // Metrikler
  const metricClassification = document.getElementById('metricClassification');
  const metricConfidence = document.getElementById('metricConfidence');
  const metricThreatLevel = document.getElementById('metricThreatLevel');
  const metricPhishing = document.getElementById('metricPhishing');
  const metricMalware = document.getElementById('metricMalware');
  const metricDeface = document.getElementById('metricDeface');

  // Ek bilgiler
  const scanCountEl = document.getElementById('scanCount');
  const errorCountEl = document.getElementById('errorCount');
  const themeStateEl = document.getElementById('themeState');
  const statusPings = document.getElementById('statusPings');
  const apiStatus = document.getElementById('apiStatus');
  const apiLatency = document.getElementById('apiLatency');
  const lastResponse = document.getElementById('lastResponse');

  // Durum
  let scanCount = 0;
  let errorCount = 0;
  let radarCtx;
  let animationId;
  let pingCounter = 0;
  let themeMode = 'dark';
  let scanning = false;
  let artificialSpeed = 0;

  // ---- Başlatıcı ----
  function init() {
    prepareRadarCanvas();
    addConsoleLog('info', 'Arayüz yüklendi.');
    addConsoleLog('info', 'Hazır.');
    bindEvents();
    // Opsiyonel: başlangıç pingi
    randomPingBurst(3);
    // Fake totalRecords doldur (gerçek değer backend’den alınabiliyorsa AJAX eklenir)
    setText('totalRecords', '640K+');
    showToast('safe', 'Arayüz Hazır');
  }

  // ---- Radar Canvas ----
  function prepareRadarCanvas() {
    radarCanvas.width = radarCanvas.clientWidth;
    radarCanvas.height = radarCanvas.clientHeight;
    radarCtx = radarCanvas.getContext('2d');
    drawStaticGrid();
  }

  function drawStaticGrid() {
    const w = radarCanvas.width;
    const h = radarCanvas.height;
    radarCtx.clearRect(0, 0, w, h);
    radarCtx.save();
    radarCtx.translate(w / 2, h / 2);

    // Halkalar
    const rings = 5;
    for (let i = 1; i <= rings; i++) {
      const r = (Math.min(w, h) / 2) * (i / rings);
      radarCtx.beginPath();
      radarCtx.arc(0, 0, r, 0, Math.PI * 2);
      radarCtx.strokeStyle = `rgba(255,69,0,${0.08 + i * 0.03})`;
      radarCtx.lineWidth = 1;
      radarCtx.stroke();
    }

    // Çapraz çizgiler
    for (let a = 0; a < 360; a += 30) {
      radarCtx.beginPath();
      radarCtx.moveTo(0, 0);
      const rad = a * Math.PI / 180;
      radarCtx.lineTo(
        Math.cos(rad) * w / 2,
        Math.sin(rad) * h / 2
      );
      radarCtx.strokeStyle = 'rgba(255,69,0,0.15)';
      radarCtx.stroke();
    }

    radarCtx.restore();
  }

  // ---- Ping Yerleştirme ----
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
    statusPings.textContent = `PINGS: ${pingCounter}`;

    setTimeout(() => {
      ping.remove();
    }, 3500);
  }

  function randomPingBurst(n = 1) {
    for (let i = 0; i < n; i++) {
      const xp = 10 + Math.random() * 80;
      const yp = 10 + Math.random() * 80;
      const ts = Math.random();
      placePing(xp, yp, ts);
    }
  }

  // ---- Tarama Süreci ----
  async function startScan() {
    if (scanning) return;
    const targetUrl = urlInput.value.trim();
    if (!targetUrl) {
      showToast('warn', 'URL giriniz.');
      urlInput.focus();
      return;
    }

    scanning = true;
    scanBtn.disabled = true;
    urlInput.disabled = true;
    toggleLoading(true);
    addConsoleLog('info', 'Tarama başlatıldı...');
    showToast('safe', 'Tarama başladı');

    // Hız animasyonu
    artificialSpeed = 0;
    animateSpeedIncrease();

    const startTime = performance.now();
    let result;
    try {
      result = await fetchPrediction(targetUrl);
      const latency = Math.round(performance.now() - startTime);
      apiLatency.textContent = latency + ' ms';
      apiStatus.textContent = 'OK';
      lastResponse.textContent = new Date().toLocaleTimeString();
      addConsoleLog('info', 'API yanıt süresi: ' + latency + ' ms');
    } catch (err) {
      errorCount++;
      errorCountEl.textContent = errorCount;
      apiStatus.textContent = 'Hata';
      addConsoleLog('error', 'API isteği başarısız: ' + err.message);
      showToast('danger', 'API isteği başarısız; sahte sonuç kullanıldı');
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
    if (artificialSpeed < 320) {
      requestAnimationFrame(animateSpeedIncrease);
    }
  }

  async function fetchPrediction(url) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const payload = { url };
    addConsoleLog('info', 'API istek: ' + url);

    const res = await fetch('/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    clearTimeout(timeout);

    if (!res.ok) {
      throw new Error('HTTP ' + res.status);
    }

    const data = await res.json();
    addConsoleLog('info', 'API yanıt alındı.');
    return normalizeApiResponse(data);
  }

  function normalizeApiResponse(data) {
    // Beklenen alanları esnek şekilde yakala
    // Olası format: { prediction: 'phishing', probabilities: { benign:0.1, phishing:0.8, malware:0.05, defacement:0.05 } }
    const pred = data.prediction || data.label || data.class || 'unknown';
    const probs = data.probabilities || data.probs || {};
    return {
      url: data.url || 'N/A',
      classification: pred,
      probabilities: {
        benign: parseFloat(probs.benign ?? probs.benign ?? 0),
        phishing: parseFloat(probs.phishing ?? probs.phishing ?? 0),
        malware: parseFloat(probs.malware ?? probs.malware ?? 0),
        defacement: parseFloat(probs.defacement ?? probs.defacement ?? probs.deface ?? 0)
      }
    };
  }

  function buildFallbackResult(url) {
    return {
      url,
      classification: 'benign',
      probabilities: {
        benign: 0.82,
        phishing: 0.09,
        malware: 0.05,
        defacement: 0.04
      }
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
    addConsoleLog('info', 'Tarama tamamlandı.');
  }

  function toggleLoading(flag) {
    loadingState.classList.toggle('hidden', !flag);
  }

  // ---- Telemetri Güncelleme ----
  function updateTelemetry(result) {
    telemetryPanel.classList.remove('hidden');
    const { classification, probabilities } = result;

    metricClassification.textContent = classification.toUpperCase();
    const conf = computeConfidence(probabilities, classification);
    metricConfidence.textContent = (conf * 100).toFixed(1) + '%';

    metricPhishing.textContent = (probabilities.phishing * 100).toFixed(1) + '%';
    metricMalware.textContent = (probabilities.malware * 100).toFixed(1) + '%';
    metricDeface.textContent = (probabilities.defacement * 100).toFixed(1) + '%';

    // Tehdit seviyesi: benign hariç en yüksek risk
    const threatScore = Math.max(probabilities.phishing, probabilities.malware, probabilities.defacement);
    metricThreatLevel.textContent = (threatScore * 100).toFixed(1) + '%';

    moveLinearGauge(threatScore);
    moveCircularDial(threatScore);
    updateTelemetrySignal(threatScore, classification);

    addConsoleLog('info', `Sınıflandırma: ${classification}, Tehdit Skor: ${(threatScore * 100).toFixed(1)}%`);

    // Radar pingi ekle (risk arttıkça daha büyük)
    const xp = 15 + Math.random() * 70;
    const yp = 15 + Math.random() * 70;
    placePing(xp, yp, threatScore);

    // Toast
    if (classification === 'benign') {
      showToast('safe', 'URL güvenli görünüyor.');
    } else if (threatScore > 0.6) {
      showToast('danger', 'Yüksek tehdit algılandı: ' + classification);
    } else {
      showToast('warn', 'Orta risk: ' + classification);
    }
  }

  function computeConfidence(probs, classification) {
    const key = classification.toLowerCase();
    return probs[key] !== undefined ? probs[key] : 0;
  }

  function moveLinearGauge(threatScore) {
    const percent = threatScore * 100;
    const trackWidth = document.getElementById('linearGauge').offsetWidth;
    const offset = (percent / 100) * (trackWidth - 8);
    gaugeNeedle.style.left = Math.max(4, offset) + 'px';
  }

  function moveCircularDial(threatScore) {
    // 0 -> -45deg (safe), 1 -> 225deg (danger) aralığı
    const minDeg = -45;
    const maxDeg = 225;
    const angle = minDeg + (maxDeg - minDeg) * threatScore;
    dialNeedle.style.transform = `translate(-50%,-100%) rotate(${angle}deg)`;
  }

  function updateTelemetrySignal(threatScore, classification) {
    telemetrySignal.classList.remove('offline', 'idle');
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

  // ---- Konsol Log ----
  function addConsoleLog(type, message) {
    const line = document.createElement('div');
    line.className = 'log-line';
    const ts = document.createElement('div');
    ts.className = 'log-timestamp';
    ts.textContent = new Date().toLocaleTimeString();
    const ev = document.createElement('div');
    ev.className = 'log-event ' + type;
    ev.textContent = message;
    line.appendChild(ts);
    line.appendChild(ev);
    consoleStream.appendChild(line);
    consoleStream.scrollTop = consoleStream.scrollHeight;
  }

  // ---- Toast ----
  function showToast(kind, text) {
    const toast = document.createElement('div');
    toast.className = 'toast ' + kind;
    toast.innerHTML = `
      <span style="font-weight:700;">${kind.toUpperCase()}</span>
      <span style="flex:1;">${text}</span>
      <button class="toast-close" aria-label="Kapat">×</button>
    `;
    toastStack.appendChild(toast);
    const closer = toast.querySelector('.toast-close');
    closer.addEventListener('click', () => toast.remove());
    setTimeout(() => {
      if (toast.isConnected) toast.remove();
    }, 6000);
  }

  // ---- Modal ----
  function openModal(title, htmlContent) {
    modalTitle.textContent = title;
    modalBody.innerHTML = htmlContent;
    modalOverlay.classList.remove('hidden');
  }

  function closeModal() {
    modalOverlay.classList.add('hidden');
  }

  // ---- Tema / Debug ----
  function toggleTheme() {
    if (themeMode === 'dark') {
      document.body.classList.add('theme-pit');
      themeMode = 'pit';
    } else {
      document.body.classList.remove('theme-pit');
      themeMode = 'dark';
    }
    themeStateEl.textContent = themeMode;
    document.getElementById('statusTheme').textContent = themeMode.toUpperCase();
    showToast('safe', 'Tema: ' + themeMode);
  }

  function toggleDebugOutline() {
    document.body.classList.toggle('outline-debug');
  }

  // ---- Yardım Modal İçeriği ----
  function showHelpModal() {
    openModal(
      'Yardım / Kılavuz',
      `
      <p><strong>Tarama:</strong> URL girip "Tarama Başlat" butonuna basın veya Enter tuşu.</p>
      <p><strong>Tema Değiştir:</strong> Koyu / pit modu arası geçiş.</p>
      <p><strong>Debug Çerçeve:</strong> Öğelerin kenarlarını incelemek için.</p>
      <p><strong>Gauge & Dial:</strong> Tehdit olasılığı lineer ve dairesel göstergelerde yansır.</p>
      <p><strong>Radar Ping:</strong> Tehdit seviyesi arttıkça ping boyutu artar.</p>
      <p><strong>Performans:</strong> Ağ hatasında sahte (fallback) sonuç kullanılır.</p>
      `
    );
  }

  // ---- Event Binding ----
  function bindEvents() {
    scanBtn.addEventListener('click', startScan);
    urlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') startScan();
    });
    themeBtn.addEventListener('click', toggleTheme);
    debugBtn.addEventListener('click', toggleDebugOutline);
    modalCloseBtn.addEventListener('click', closeModal);
    // Yardım için çift tıklama statusSecurity
    document.getElementById('statusSecurity').addEventListener('dblclick', showHelpModal);
  }

  // ---- Yardımcı ----
  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  // Başlat
  init();

})();