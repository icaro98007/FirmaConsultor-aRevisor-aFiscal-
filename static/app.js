// Lógica Frontend para el Agente RAG Privado de Revisoría Fiscal + Pipeline de Trazabilidad Inmutable

const chatMessages = document.getElementById("chat-messages");
const chatForm = document.getElementById("chat-form");
const queryInput = document.getElementById("query-input");
const sendBtn = document.getElementById("send-btn");

const guardrailBanner = document.getElementById("guardrail-status-banner");
const guardrailLayers = document.getElementById("guardrail-layers");
const sanitizedBox = document.getElementById("sanitized-preview-box");
const sanitizedQueryText = document.getElementById("sanitized-query-text");
const sourcesContainer = document.getElementById("sources-container");

const driveFilesList = document.getElementById("drive-files-list");
const statFiles = document.getElementById("stat-files");
const statChunks = document.getElementById("stat-chunks");
const geminiStatusPill = document.getElementById("gemini-status-pill");

const apiKeyInput = document.getElementById("api-key-input");
const modelSelect = document.getElementById("model-select");
const thresholdInput = document.getElementById("threshold-input");
const thresholdVal = document.getElementById("threshold-val");
const saveConfigBtn = document.getElementById("save-config-btn");
const configFeedback = document.getElementById("config-feedback");

const fileUpload = document.getElementById("file-upload");
const uploadStatus = document.getElementById("upload-status");
const auditCount = document.getElementById("audit-count");
const auditTableBody = document.getElementById("audit-table-body");
const integrityBanner = document.getElementById("integrity-banner");
const verifyLedgerBtn = document.getElementById("verify-ledger-btn");
const openLatestTraceBtn = document.getElementById("open-latest-trace-btn");

// Modal de Trazabilidad y Evaluación de Cumplimiento
const traceModal = document.getElementById("trace-modal");
const modalTraceTitle = document.getElementById("modal-trace-title");
const modalTraceContent = document.getElementById("modal-trace-content");
const closeModalBtn = document.getElementById("close-modal-btn");
const copyTraceJsonBtn = document.getElementById("copy-trace-json-btn");
const downloadTraceJsonBtn = document.getElementById("download-trace-json-btn");

let TRACE_CACHE = {};
let LATEST_TRACE_RECORD = null;
let CURRENT_MODAL_RECORD = null;

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function formatMarkdownSimple(text) {
  let raw = String(text || "");
  // Asegurar saltos de línea antes de puntos numerados (1. , 2. , 1) , 2) ) y viñetas (- )
  raw = raw.replace(/(?:(?<=[:.;])\s+|\s{1,2})(?=(?:\d{1,2}[\.\)]\s+[A-ZÁÉÍÓÚÑ*]))/g, "\n");
  raw = raw.replace(/(?:(?<=[:.;])\s+|\s{1,2})(?=(?:-\s+[A-ZÁÉÍÓÚÑ*]))/g, "\n");

  let html = escapeHtml(raw);
  html = html.replace(/^### (.*)$/gm, "<h3>$1</h3>");
  html = html.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*(.*?)\*/g, "<em>$1</em>");
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  html = html.replace(
    /\[Fuente:\s*([^\]]+)\]/g,
    '<span class="tag tag-ok">[Fuente: $1]</span>'
  );
  return html
    .split("\n\n")
    .map((para) => `<p>${para.replace(/\n/g, "<br/>")}</p>`)
    .join("");
}

function openTraceabilityModal(record) {
  if (!record) return;
  CURRENT_MODAL_RECORD = record;
  modalTraceTitle.textContent = `Certificado Inmutable ${record.trace_id} (Secuencia #${record.sequence_number})`;

  const ts = record.timestamp || {};
  const grScore = record.grounding_score || {};
  const comp = record.compliance_evaluation || {};
  const proof = record.immutability_proof || {};
  const sources = record.consulted_sources || [];

  const controlsHtml = (comp.controls || [])
    .map(
      (c) => `
      <div class="control-card">
        <strong>✓ ${escapeHtml(c.control_id)} · ${escapeHtml(c.control_name)}</strong>
        <div>Estado: <code>${escapeHtml(c.result)}</code></div>
        <div style="color:#94a3b8;margin-top:2px;">${escapeHtml(c.evidence)}</div>
      </div>
    `
    )
    .join("");

  const sourcesHtml =
    sources.length > 0
      ? sources
          .map(
            (s) => `
          <div class="source-item">
            <div class="source-item-top">
              <strong>📄 ${escapeHtml(s.doc_name)} (${escapeHtml(s.chunk_id)})</strong>
              <span class="score-badge">Relevancia: ${Number(s.relevance_score).toFixed(3)}</span>
            </div>
            <div class="source-section">${escapeHtml(s.category)} — ${escapeHtml(s.section)}</div>
          </div>
        `
          )
          .join("")
      : `<p class="empty-state">0 fuentes expuestas: El guardarraíl detuvo la solicitud antes de exponer documentos internos.</p>`;

  modalTraceContent.innerHTML = `
    <div class="trace-kpi-grid">
      <div class="trace-kpi">
        <span>Timestamp (ISO-8601)</span>
        <strong>${escapeHtml(ts.local_iso8601 || ts.display || "")}</strong>
      </div>
      <div class="trace-kpi">
        <span>Score de Fundamentación</span>
        <strong>${Number(grScore.score || 0).toFixed(3)} (${escapeHtml(grScore.label || "N/A")})</strong>
      </div>
      <div class="trace-kpi">
        <span>Evaluación de Cumplimiento</span>
        <strong style="color:#34d399;">${escapeHtml(comp.compliance_score || "100%")} · ${escapeHtml(comp.overall_status || "")}</strong>
      </div>
      <div class="trace-kpi">
        <span>Fuentes Consultadas</span>
        <strong>${sources.length} documento(s) Drive</strong>
      </div>
    </div>

    <div class="trace-section-box">
      <h4>1. Dictamen de Evaluación de Cumplimiento Normativo</h4>
      <p style="font-size:0.77rem;color:#cbd5e1;margin-bottom:0.55rem;">
        ${escapeHtml(comp.verdict_summary || "")}
      </p>
      <div class="compliance-controls-grid">
        ${controlsHtml}
      </div>
    </div>

    <div class="trace-section-box">
      <h4>2. Fuentes Consultadas y Score de Fundamentación</h4>
      <div class="sources-container">
        ${sourcesHtml}
      </div>
    </div>

    <div class="trace-section-box">
      <h4>3. Prueba de Inmutabilidad Criptográfica (SHA-256 Hash Chain)</h4>
      <div class="hash-chain-box">
        <div><strong>Algoritmo:</strong> ${escapeHtml(proof.algorithm || "SHA-256-HASH-CHAIN")}</div>
        <div><strong>Prev Hash (Bloque #${record.sequence_number - 1}):</strong> ${escapeHtml(proof.prev_hash || "")}</div>
        <div><strong>Record Hash (Bloque #${record.sequence_number}):</strong> ${escapeHtml(record.record_hash || "")}</div>
        <div><strong>Query SHA-256 (Sin PII):</strong> ${escapeHtml((record.request || {}).query_sha256 || "")}</div>
      </div>
    </div>

    <div class="trace-section-box">
      <h4>4. Registro Estructurado Inmutable (JSON Canónico)</h4>
      <pre class="json-pre">${escapeHtml(JSON.stringify(record, null, 2))}</pre>
    </div>
  `;

  traceModal.classList.remove("hidden");
}

window.openTraceById = function (traceId) {
  const rec = TRACE_CACHE[traceId];
  if (rec) {
    openTraceabilityModal(rec);
  }
};

closeModalBtn.addEventListener("click", () => {
  traceModal.classList.add("hidden");
});

traceModal.addEventListener("click", (e) => {
  if (e.target === traceModal) {
    traceModal.classList.add("hidden");
  }
});

copyTraceJsonBtn.addEventListener("click", () => {
  if (!CURRENT_MODAL_RECORD) return;
  navigator.clipboard.writeText(JSON.stringify(CURRENT_MODAL_RECORD, null, 2));
  copyTraceJsonBtn.textContent = "✓ JSON Copiado al Portapapeles";
  setTimeout(() => {
    copyTraceJsonBtn.textContent = "📋 Copiar JSON Estructurado";
  }, 1800);
});

downloadTraceJsonBtn.addEventListener("click", () => {
  if (!CURRENT_MODAL_RECORD) return;
  const blob = new Blob([JSON.stringify(CURRENT_MODAL_RECORD, null, 2)], {
    type: "application/json;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${CURRENT_MODAL_RECORD.trace_id}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

openLatestTraceBtn.addEventListener("click", async () => {
  if (LATEST_TRACE_RECORD) {
    openTraceabilityModal(LATEST_TRACE_RECORD);
  } else {
    await refreshAuditLog();
    if (LATEST_TRACE_RECORD) {
      openTraceabilityModal(LATEST_TRACE_RECORD);
    } else {
      alert("Realiza primero una consulta en el chat para generar su Certificado Inmutable de Trazabilidad y Evaluación de Cumplimiento.");
    }
  }
});

async function loadStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();

    statFiles.textContent = (data.manifest_files || []).length;
    statChunks.textContent = data.indexed_chunks_count || 0;
    auditCount.textContent = data.audit_events_count || 0;

    if (data.gemini_configured) {
      geminiStatusPill.textContent = "Gemini Cloud Conectado";
      geminiStatusPill.className = "status-pill pill-cloud";
    } else {
      geminiStatusPill.textContent = "RAG Extractivo Local";
      geminiStatusPill.className = "status-pill pill-ready";
    }

    driveFilesList.innerHTML = "";
    (data.manifest_files || []).forEach((file) => {
      const ext = (file.name.split(".").pop() || "").toUpperCase();
      const div = document.createElement("div");
      div.className = "drive-file-item";
      const fileUrl = `https://drive.google.com/file/d/${file.id}/view`;
      div.innerHTML = `
        <a href="${fileUrl}" target="_blank" rel="noopener noreferrer" title="${escapeHtml(file.name)}">
          📄 ${escapeHtml(file.name)}
        </a>
        <span class="file-ext">${escapeHtml(ext)}</span>
      `;
      driveFilesList.appendChild(div);
    });
  } catch (err) {
    console.error("Error cargando estado:", err);
  }
}

async function refreshAuditLog() {
  try {
    const res = await fetch("/api/traceability");
    const data = await res.json();
    const records = data.records || [];
    const integrity = data.integrity || {};

    auditCount.textContent = records.length;

    if (integrity.valid) {
      integrityBanner.className = "guardrail-banner banner-allowed";
      integrityBanner.textContent = `✓ ${integrity.message} · Head SHA-256: ${(integrity.head_hash || "").slice(0, 20)}...`;
    } else {
      integrityBanner.className = "guardrail-banner banner-jailbreak";
      integrityBanner.textContent = `⛔ Alerta de Integridad: ${integrity.reason || "Error en cadena"}`;
    }

    records.forEach((r) => {
      TRACE_CACHE[r.trace_id] = r;
    });
    if (records.length > 0 && !LATEST_TRACE_RECORD) {
      LATEST_TRACE_RECORD = records[0];
    }

    if (records.length === 0) {
      auditTableBody.innerHTML = `<tr><td colspan="8" class="empty-state">Aún no se han generado registros inmutables en esta sesión.</td></tr>`;
      return;
    }

    auditTableBody.innerHTML = records
      .map((rec) => {
        const st = (rec.response || {}).status_code || "";
        let badgeClass = "tag-ok";
        if (st === "BLOCKED_JAILBREAK") badgeClass = "tag-danger";
        else if (st === "BLOCKED_OUT_OF_SCOPE") badgeClass = "tag-warn";

        const sourcesList = (rec.consulted_sources || []).map((s) => s.doc_name).join(", ") || "—";
        const gScore = Number((rec.grounding_score || {}).score || 0).toFixed(3);
        const compStatus = (rec.compliance_evaluation || {}).overall_status || "CUMPLIDO";
        const shortHash = (rec.record_hash || "").slice(0, 14) + "...";

        return `
          <tr>
            <td><strong>#${rec.sequence_number}</strong><br/><code>${escapeHtml(rec.trace_id)}</code></td>
            <td>${escapeHtml((rec.timestamp || {}).local_iso8601 || "")}</td>
            <td>${escapeHtml((rec.request || {}).sanitized_query || "")}</td>
            <td><strong>${gScore}</strong></td>
            <td><span class="tag ${badgeClass}">${escapeHtml(compStatus)}</span></td>
            <td>${escapeHtml(sourcesList)}</td>
            <td><code>${escapeHtml(shortHash)}</code></td>
            <td>
              <button class="btn-trace" onclick="openTraceById('${escapeHtml(rec.trace_id)}')">
                🛡️ Ver Evaluación
              </button>
            </td>
          </tr>
        `;
      })
      .join("");
  } catch (e) {
    console.error("Error cargando trazabilidad:", e);
  }
}

verifyLedgerBtn.addEventListener("click", async () => {
  const res = await fetch("/api/traceability/verify");
  const info = await res.json();
  if (info.valid) {
    integrityBanner.className = "guardrail-banner banner-allowed";
    integrityBanner.textContent = `✓ Verificación Criptográfica Exitosa (${info.verified_at}): ${info.total_records} bloques íntegros · SHA-256 Head: ${(info.head_hash || "").slice(0, 24)}...`;
  } else {
    integrityBanner.className = "guardrail-banner banner-jailbreak";
    integrityBanner.textContent = `⛔ Fallo de Integridad en bloque #${info.broken_at_sequence}: ${info.reason}`;
  }
});

function appendMessage(role, content, meta = {}) {
  const wrapper = document.createElement("div");
  if (role === "user") {
    wrapper.className = "message user-message";
    wrapper.innerHTML = `
      <div class="msg-header">
        <span class="msg-author">Consulta del Usuario</span>
      </div>
      <div class="msg-body"><p>${escapeHtml(content)}</p></div>
    `;
  } else {
    let extraClass = "";
    let badgeText = "Grounding Verificado";
    let badgeClass = "badge-grounded";

    if (meta.status_code === "BLOCKED_OUT_OF_SCOPE") {
      extraClass = "blocked-oos";
      badgeText = "Rechazado · Fuera de Alcance";
      badgeClass = "badge-oos";
    } else if (meta.status_code === "BLOCKED_JAILBREAK") {
      extraClass = "blocked-jailbreak";
      badgeText = "Bloqueado · Escudo Anti-Jailbreak";
      badgeClass = "badge-jailbreak";
    }

    const traceRec = meta.trace_record || null;
    let traceButtonHtml = "";
    if (traceRec && traceRec.trace_id) {
      TRACE_CACHE[traceRec.trace_id] = traceRec;
      LATEST_TRACE_RECORD = traceRec;
      const gScore = Number((traceRec.grounding_score || {}).score || 0).toFixed(3);
      const shortHash = (traceRec.record_hash || "").slice(0, 12);
      traceButtonHtml = `
        <div class="trace-action-bar">
          <button type="button" class="btn-trace" onclick="openTraceById('${escapeHtml(traceRec.trace_id)}')">
            🛡️ Trazabilidad Inmutable y Evaluación de Cumplimiento (${escapeHtml(traceRec.trace_id)})
          </button>
          <span class="trace-hash-pill" title="Hash SHA-256 encadenado e inmutable">
            ⛓️ Score Fundamentación: ${gScore} · SHA-256: ${escapeHtml(shortHash)}...
          </span>
        </div>
      `;
    }

    wrapper.className = `message assistant-message ${extraClass}`;
    wrapper.innerHTML = `
      <div class="msg-header">
        <span class="msg-author">Agente de Revisoría Fiscal</span>
        <span class="msg-badge ${badgeClass}">${badgeText}</span>
      </div>
      <div class="msg-body">${formatMarkdownSimple(content)}</div>
      <div class="msg-footer">
        <span>Motor: ${escapeHtml(meta.engine || "RAG Privado")}</span>
        <span>Timestamp: ${escapeHtml(((traceRec || {}).timestamp || {}).local_iso8601 || new Date().toISOString())}</span>
      </div>
      ${traceButtonHtml}
    `;
  }

  chatMessages.appendChild(wrapper);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

function updateTelemetry(result) {
  const gr = result.guardrails || {};
  const layers = gr.layers_summary || [];

  if (result.status_code === "ALLOWED") {
    guardrailBanner.className = "guardrail-banner banner-allowed";
    guardrailBanner.textContent =
      "✓ Solicitud Autorizada: Cumple políticas de privacidad, alcance y evidencia en Drive.";
  } else if (result.status_code === "BLOCKED_JAILBREAK") {
    guardrailBanner.className = "guardrail-banner banner-jailbreak";
    guardrailBanner.textContent =
      "⛔ Solicitud Bloqueada: Intento de Jailbreak / Prompt Injection / Exfiltración detectado.";
  } else {
    guardrailBanner.className = "guardrail-banner banner-oos";
    guardrailBanner.textContent =
      "⚠️ Solicitud Rechazada: Tema fuera de la base de conocimiento de Revisoría Fiscal.";
  }

  if (layers.length > 0) {
    guardrailLayers.innerHTML = layers
      .map((l) => {
        let dotClass = "dot-pass";
        if (!l.passed) {
          dotClass = l.status === "BLOCKED" ? "dot-fail" : "dot-warn";
        } else if (l.status === "REDACTED") {
          dotClass = "dot-warn";
        }
        return `
          <div class="layer-item">
            <span class="layer-dot ${dotClass}"></span>
            <div>
              <strong>${escapeHtml(l.layer)} (${escapeHtml(l.status)})</strong>
              <p>${escapeHtml(l.detail)}</p>
            </div>
          </div>
        `;
      })
      .join("");
  }

  if (gr.sanitized_query) {
    sanitizedBox.classList.remove("hidden");
    sanitizedQueryText.textContent = gr.sanitized_query;
  }

  const sources = result.sources || [];
  if (sources.length === 0) {
    sourcesContainer.innerHTML = `
      <p class="empty-state">
        Sin fragmentos citados (la solicitud fue detenida por los guardarraíles antes de exponer o inventar información).
      </p>
    `;
  } else {
    sourcesContainer.innerHTML = sources
      .map(
        (s) => `
        <div class="source-item">
          <div class="source-item-top">
            <strong>📄 ${escapeHtml(s.doc_name)}</strong>
            <span class="score-badge">Score: ${Number(s.score).toFixed(2)}</span>
          </div>
          <div class="source-section">${escapeHtml(s.section)}</div>
          <div class="source-excerpt">${escapeHtml(s.excerpt)}</div>
        </div>
      `
      )
      .join("");
  }
}

async function submitQuery(queryText) {
  const trimmed = (queryText || "").trim();
  if (!trimmed) return;

  appendMessage("user", trimmed);
  queryInput.value = "";
  sendBtn.disabled = true;
  sendBtn.textContent = "Verificando Guardarraíles...";

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: trimmed }),
    });
    const data = await res.json();
    appendMessage("assistant", data.answer, data);
    updateTelemetry(data);
    await refreshAuditLog();
  } catch (err) {
    appendMessage(
      "assistant",
      "Error de comunicación con el servidor local de Revisoría Fiscal.",
      { status_code: "ERROR" }
    );
  } finally {
    sendBtn.disabled = false;
    sendBtn.textContent = "Consultar Base Privada";
  }
}

chatForm.addEventListener("submit", (e) => {
  e.preventDefault();
  submitQuery(queryInput.value);
});

queryInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    submitQuery(queryInput.value);
  }
});

// Botones de Escenarios de Prueba 1-Click
document.querySelectorAll(".scenario-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const clone = btn.cloneNode(true);
    const tagEl = clone.querySelector(".tag");
    if (tagEl) tagEl.remove();
    const text = clone.textContent.trim();
    submitQuery(text);
  });
});

// Configuración de Gemini Cloud y Umbral
thresholdInput.addEventListener("input", () => {
  thresholdVal.textContent = Number(thresholdInput.value).toFixed(2);
});

saveConfigBtn.addEventListener("click", async () => {
  const payload = {
    gemini_model: modelSelect.value,
    min_retrieval_score: parseFloat(thresholdInput.value),
  };
  if (apiKeyInput.value.trim()) {
    payload.gemini_api_key = apiKeyInput.value.trim();
  }

  const res = await fetch("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  apiKeyInput.value = "";
  configFeedback.textContent = data.gemini_configured
    ? `✓ Conectado a Google Gemini (${data.gemini_model}) · Umbral ${data.min_retrieval_score}`
    : `✓ Umbral actualizado (${data.min_retrieval_score}) · Modo RAG Extractivo Local`;
  await loadStatus();
});

// Carga de archivos locales adicionales (.docx, .csv, .txt)
fileUpload.addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  uploadStatus.textContent = `Indexando ${file.name}...`;

  const reader = new FileReader();
  reader.onload = async () => {
    const base64 = reader.result.split(",")[1];
    const res = await fetch("/api/upload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: file.name, content_base64: base64 }),
    });
    const data = await res.json();
    if (data.ok) {
      uploadStatus.textContent = `✓ ${data.filename} indexado (${data.indexed_chunks_count} fragmentos activos).`;
      await loadStatus();
    } else {
      uploadStatus.textContent = `⚠️ ${data.error || "Error al indexar archivo"}`;
    }
  };
  reader.readAsDataURL(file);
});

// Navegación de pestañas (Chat vs Ledger Inmutable)
document.querySelectorAll(".tab-btn[data-tab]").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn[data-tab]").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const target = btn.getAttribute("data-tab");
    if (target === "chat-view") {
      document.getElementById("chat-view").classList.remove("hidden");
      document.getElementById("audit-view").classList.add("hidden");
    } else {
      document.getElementById("chat-view").classList.add("hidden");
      document.getElementById("audit-view").classList.remove("hidden");
      refreshAuditLog();
    }
  });
});

loadStatus();
refreshAuditLog();
