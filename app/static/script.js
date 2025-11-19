const byId = (id) => document.getElementById(id);
const el = {
  url: byId("url"),
  check: byId("check"),
  status: byId("status"),
  label: byId("label"),
  prob: byId("prob"),
  risk: byId("risk"),
  raw: byId("raw"),
  th: byId("threshold"),
  thVal: byId("th-val"),
};

const RISK_MAP = {
  safe:   { text: "Güvenli",   cls: "status--safe" },
  caution:{ text: "Dikkat",    cls: "status--caution" },
  danger: { text: "Tehlikeli", cls: "status--danger" },
};

function setStatus(kind, title, desc){
  el.status.className = "status";
  const map = RISK_MAP[kind] || { cls: "status--idle" };
  el.status.classList.add(map.cls || "status--idle");
  el.status.innerHTML = `<div class="status__title">${title}</div><div class="status__desc">${desc || ""}</div>`;
}

function fmtPct(p){
  if (typeof p !== "number") return "";
  return (p * 100).toFixed(1) + "%";
}

async function checkUrl(){
  const url = el.url.value.trim();
  const threshold = parseFloat(el.th.value);
  if (!url) {
    setStatus("caution","Dikkat","Lütfen bir URL girin.");
    return;
  }
  el.check.disabled = true;
  const prev = el.check.textContent;
  el.check.textContent = "Kontrol ediliyor…";
  setStatus("idle","Kontrol ediliyor","Sunucuya istek gönderiliyor. <span class='spinner'></span>");

  try{
    const res = await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, threshold }),
    });
    const data = await res.json();

    if (!res.ok){
      const msg = (data && (data.detail || data.message)) || `Hata kodu: ${res.status}`;
      setStatus("caution","İstek başarısız", msg);
      el.label.textContent = "—";
      el.prob.textContent = "—";
      el.risk.textContent = "—";
      el.raw.textContent = JSON.stringify(data, null, 2);
      return;
    }

    const risk = String(data.risk_level || "").toLowerCase();
    const map = RISK_MAP[risk] || RISK_MAP.caution;

    setStatus(risk, `Durum: ${map.text}`, `Etiket: ${data.label || "—"} • Olasılık: ${fmtPct(data.probability)}`);

    el.label.textContent = data.label || "—";
    el.prob.textContent = fmtPct(data.probability);
    el.risk.textContent = map.text;
    el.raw.textContent = JSON.stringify(data, null, 2);

  }catch(err){
    setStatus("danger","Bağlantı hatası","API'ye ulaşılamadı. Sunucu çalışıyor mu?");
    el.raw.textContent = String(err);
  }finally{
    el.check.disabled = false;
    el.check.textContent = prev;
  }
}

el.check.addEventListener("click", checkUrl);
el.url.addEventListener("keydown", (e)=>{ if(e.key === "Enter") checkUrl(); });
el.th.addEventListener("input", ()=>{ el.thVal.textContent = Number(el.th.value).toFixed(2); });

// İlk durum
setStatus("idle","Hazır","Bir URL girin ve Kontrol Et'e basın.");
