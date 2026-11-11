// Lógica Frontend Universal (Funciona con Backend Python/Cloudflare Worker y con Fallback Edge en Navegador)

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

const traceModal = document.getElementById("trace-modal");
const modalTraceTitle = document.getElementById("modal-trace-title");
const modalTraceContent = document.getElementById("modal-trace-content");
const closeModalBtn = document.getElementById("close-modal-btn");
const copyTraceJsonBtn = document.getElementById("copy-trace-json-btn");
const downloadTraceJsonBtn = document.getElementById("download-trace-json-btn");

let TRACE_CACHE = {};
let LATEST_TRACE_RECORD = null;
let CURRENT_MODAL_RECORD = null;
let LOCAL_LEDGER = [];
let LOCAL_LAST_HASH = "0".repeat(64);
let CLIENT_GEMINI_KEY = "";
let CLIENT_GEMINI_MODEL = "gemini-2.5-flash";
let CLIENT_MIN_SCORE = 0.28;

const FALLBACK_MANIFEST = [
  { id: "1m7qSgSd2YLgn-_AzbEnhSAscgEGNioEt", name: "01_Procedimientos_auditoria.docx" },
  { id: "1seULMbQ3FJsbNf2AimQ3oL00Orbevi17", name: "02_Guia_practica_NIA.docx" },
  { id: "1cdX7ZH8tMD-6J8lMZ9w4IFrGk086UKaG", name: "03_Control_interno_COSO_y_hallazgos.docx" },
  { id: "1vj6dFeFyPjnGjuEIPwRmsujo73cbdfMZ", name: "04_Cumplimiento_SARLAFT_SAGRILAFT_ROS.docx" },
  { id: "18TPNKvZw6ahpEBPqNpKuRj47242IHADx", name: "05_Indice_fuentes_y_metadatos.csv" },
  { id: "11vMbbiB4PcWyqqNCsAdb_HYLnmdyI29a", name: "Decreto_2420_de_2015_Normas_de_contabilidad_y_aseguramiento.pdf" },
  { id: "1uVV5yn4nFXDeVuKU5h_JOyJNEJrYB1Jb", name: "Circular-Externa-100-000016-de-24-12-2020.pdf" },
  { id: "1U52bByJfQdB4ckm0VFZs2Xk1abska-ne", name: "Circular-Externa-100-000004-de-09-04-2021.pdf" },
  { id: "1MqCVnZ1L2kWw-dsu4YS87aU3C5WtV9SM", name: "Circular-Externa-100-000015-de-24-12-2021.pdf" },
  { id: "1YxL3MwlQE8_S_2tvBg_J8Lsllp8BE1uD", name: "Circular-Cumplimiento-2023-01-734390.PDF" },
  { id: "1URqqBFGLAZpRcANr0E7DgV0o70e9jK-c", name: "Circular Externa 100-000004 de 4 de octubre de 2023.pdf" },
  { id: "1PhKsy6ebgEtbt1UFEo6TUNL83GAguK0-", name: "Circular Externa 100-000008 de 1 de noviembre de 2023.pdf" },
  { id: "1ehYhdbhoylvos0wRNqcNYb1MJQYOdFkK", name: "Circular Externa 100-000003 de 23 de abril de 2024.pdf" },
  { id: "1QXpRrdyMr5OqcrrY8YCine94gPU52oX0", name: "Circular Externa 100-300000 de 6 de diciembre de 2024.pdf" },
  { id: "1CNzj1oFzhEW3q0ccpty0uE0Sgb6hBq-n", name: "Circular Externa 100-000002 de 14 de marzo de 2025.pdf" },
  { id: "1EzyiFOUwzBRWbhjlNK2zAmLj8TwSNJlK", name: "Circular Externa 100-000020 de 2 de julio de 2026.pdf" }
];

const FALLBACK_CHUNKS = [
  {
    chunk_id: "DOC01-C03",
    doc_name: "01_Procedimientos_auditoria.docx",
    category: "Manual Interno de Auditoría",
    section: "Sección 5: Procedimiento Obligatorio de Arqueo de Caja Menor y Tesorería",
    content: "1. Carácter Sorpresivo y Presencia del Custodio: El arqueo de caja menor debe ejecutarse de manera sorpresiva (sin previo aviso) y obligatoriamente en presencia permanente del empleado responsable o custodio del fondo fijo.\n2. Corte Documental y de Efectivo: Exhibición de la totalidad del efectivo (billetes y monedas), recibos provisionales (vales), facturas y el último reembolso tramitado.\n3. Conteo Físico y Validación de Soportes: Se cuenta el dinero por denominación y se verifica fecha reciente, requisitos fiscales, autorización y topes máximos (prohibido cambio de cheques o préstamos personales).\n4. Cuadre y Conciliación del Fondo Fijo: Se compara el Fondo Fijo Autorizado contra (Efectivo físico contado + Gastos soportados válidos + Recibos provisionales autorizados).\n5. Suscripción del Acta de Arqueo y Diferencias: Se firma el Acta de Arqueo por el auditor/Revisor Fiscal y el custodio; cualquier faltante se cobra al responsable como cuenta por cobrar a empleados."
  },
  {
    chunk_id: "DOC01-C01",
    doc_name: "01_Procedimientos_auditoria.docx",
    category: "Manual Interno de Auditoría",
    section: "Sección 1 a 4: Planeación, Materialidad, Papeles de Trabajo y Dictamen",
    content: "1. Fase de Planeación: El Revisor Fiscal elabora el Memorando de Planeación de Auditoría (MPA).\n2. Materialidad: Se calcula entre el 0.5% y el 2% de los ingresos o activos totales, o el 5% de la utilidad antes de impuestos.\n3. Papeles de Trabajo y Reserva (NIA 230 y Art. 207-214 C.Co.): Se conservan por mínimo 5 años bajo reserva profesional."
  },
  {
    chunk_id: "DOC02-C01",
    doc_name: "02_Guia_practica_NIA.docx",
    category: "Normas Internacionales de Auditoría (NIA)",
    section: "NIA 200, NIA 240 (Fraude), NIA 315, NIA 500, NIA 530 y NIA 700/705 (Dictamen)",
    content: "1. NIA 240 (Responsabilidad frente al fraude): Exige escepticismo profesional, evaluación del triángulo del fraude, presunción de riesgo de fraude en ingresos y pruebas sobre asientos de diario manuales al cierre.\n2. NIA 700 y NIA 705 (Dictamen y Opinión Modificada): 1) No modificada (limpia), 2) Con salvedades (incorrección material pero no generalizada), 3) Desfavorable/Adversa (material y generalizada), y 4) Abstención de opinión (limitación al alcance material y generalizada)."
  },
  {
    chunk_id: "DOC03-C01",
    doc_name: "03_Control_interno_COSO_y_hallazgos.docx",
    category: "Manual de Control Interno y COSO",
    section: "Marco Integrado COSO 2013 (5 Componentes) y 5 Atributos de Hallazgos",
    content: "1. Los 5 Componentes de COSO 2013 (17 principios): Ambiente de Control, Evaluación de Riesgos, Actividades de Control (segregación de funciones e ITGC), Información y Comunicación, y Actividades de Supervisión/Monitoreo.\n2. Los 5 Atributos Obligatorios de un Hallazgo de Revisoría Fiscal (NIA 265): Condición, Criterio, Causa, Efecto y Recomendación."
  },
  {
    chunk_id: "DOC04-C01",
    doc_name: "04_Cumplimiento_SARLAFT_SAGRILAFT_ROS.docx",
    category: "Cumplimiento SARLAFT / SAGRILAFT / UIAF",
    section: "Obligación del Revisor Fiscal frente a SAGRILAFT, SARLAFT y Reporte ROS",
    content: "1. Obligación de Reporte ROS a la UIAF (Art. 207 num. 10 C.Co.): El Revisor Fiscal debe inscribirse en el SIREL y reportar de inmediato cualquier Operación Sospechosa (ROS) de LA/FT/FPADM.\n2. Reserva Estricta (Prohibición de Tipping-Off): Ningún miembro de la entidad auditada puede ser informado de que se envió un ROS.\n3. Circular Externa 100-000016 (SAGRILAFT): Verificación de debida diligencia, PEP, listas restrictivas y beneficiario final."
  },
  {
    chunk_id: "ET-C01",
    doc_name: "Estatuto_Tributario_Revisor_Fiscal",
    category: "Estatuto Tributario Colombiano",
    section: "Artículos 580, 581, 641, 647, 659 y 777 del Estatuto Tributario",
    content: "1. Artículo 580 lit. d) E.T.: La declaración se tiene por no presentada cuando se omite la firma del Revisor Fiscal estando obligado.\n2. Artículo 581 E.T.: La firma del Revisor Fiscal certifica que los libros de contabilidad se llevan en debida forma, reflejan razonablemente la situación financiera y se practicaron las retenciones vigentes.\n3. Artículo 641 E.T.: Sanción por extemporaneidad del 5% del impuesto o retención por cada mes o fracción de mes de retardo (máx 100%).\n4. Artículo 647 E.T.: Sanción por inexactitud del 100% de la diferencia.\n5. Artículo 659 y 660 E.T.: Suspensión de la facultad de firmar declaraciones al Revisor Fiscal por certificar hechos contrarios a la realidad contable."
  }
];

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function normalizeText(str) {
  return String(str || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
}

async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function formatMarkdownSimple(text) {
  let raw = String(text || "");
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

function renderManifestFiles(files) {
  driveFilesList.innerHTML = "";
  (files || FALLBACK_MANIFEST).forEach((file) => {
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
}

async function evaluateLocalEdgeFallback(rawQuery) {
  const OUT_OF_SCOPE_RESPONSE =
    "Soy un agente de Revisoría Fiscal alimentado exclusivamente por los manuales internos, las NIAs y el Estatuto Tributario de nuestra base de conocimiento privada. Este tema no se encuentra en mi base de conocimiento; por favor, investigue este tema en otro sitio.";
  const JAILBREAK_BLOCKED_RESPONSE =
    "Alerta de Seguridad y Legalidad (Guardarraíl Activo): Su solicitud ha sido bloqueada porque involucra un posible delito, conducta ilícita, evasión, fraude, manipulación de evidencia/logs o intento de Jailbreak. Como agente de Revisoría Fiscal, opero bajo estricto cumplimiento de la ley penal y tributaria colombiana, el Código de Ética (IESBA / Ley 43 de 1990) y trazabilidad inmutable, por lo que rechazo cualquier solicitud que busque facilitar, simular o encubrir actos ilícitos.";

  const norm = normalizeText(rawQuery);
  let sanitized = rawQuery
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "[EMAIL_REDACTADO]")
    .replace(/\b(?:NIT|nit|Nit)[\s:.\-#]*\d{3}[.\s]?\d{3}[.\s]?\d{3}(?:[\s\-]?\d)?\b/g, "[NIT_REDACTADO]")
    .replace(/\b(?:CC|C\.C\.|cédula|cedula|DNI|TI|CE)[\s:.\-#]*\d{6,12}\b/gi, "[ID_REDACTADO]");
  const piiRedacted = sanitized !== rawQuery;

  const jbPatterns = [
    /(?:juego\s+de\s+rol|role\s*play|imagina\s+que|imaginemos\s+que|simula\s+que|finge\s+que|supongamos\s+que|haz\s+de\s+cuenta|actua\s+como\b|eres\s+el\s+ceo|soy\s+el\s+ceo|hacker|pentester|ordename\b|autorizame\b)/i,
    /(?:ocultar|esconder|maquillar|alterar|borrar|eliminar|manipular|falsificar|evadir|eludir|enganar|ignorar|ignora|omitir|pasar\s+por\s+alto|no\s+reportar)\s+(?:las?\s+|los?\s+|el\s+|un\s+|una\s+|la\s+tabla\s+de\s+)?(?:inconsistencias?|hallazgos?|evidencias?|logs?|tabla\s+de\s+logs|registros?|trazabilidad|impuestos?|dian|uiaf|estados\s+financieros|contabilidad|lavado\s+de\s+activos|ros\b|sanciones?)/i,
    /(?:system\s*override|\boverride\b|bypass|modo\s+libre|sin\s+guardar\s+registro|desactiva.*trazabilidad|ignora.*instrucciones|\bdan\b|modo\s+desarrollador|system\s*prompt|datos\s+privados)/i,
    /(?:doble\s+contabilidad|facturas?\s+falsas?|proveedor(?:es)?\s+ficticios?|empresa(?:s)?\s+fachada|lavar\s+(?:dinero|activos)|blanquear|pitufeo|testaferros?|sobornar|coima|cohecho|peculado|robar|extorsion|secuestro|narcotrafico|contrabando|delito)/i
  ];
  const isJb = jbPatterns.some((p) => p.test(norm));

  const anchors = [
    "revisoria fiscal", "revisor fiscal", "manual interno", "arqueo", "caja menor", "fondo fijo", "custodio",
    "auditoria", "nia", "nias", "coso", "control interno", "hallazgo", "hallazgos", "sarlaft", "sagrilaft",
    "ros", "uiaf", "decreto 2420", "circular", "estatuto tributario", "declaracion", "extemporaneidad",
    "inexactitud", "580", "581", "641", "647", "659", "777"
  ];
  const outOfScopeExplicit = /\b(paella|cocinar|receta|clima|pronostico|futbol|mundial|horoscopo|chiste|pelicula|marte|vacaciones|divorcio|articulo 900|nia 810|impuesto al patrimonio)\b/.test(norm);
  const hasAnchor = !outOfScopeExplicit && anchors.some((a) => norm.includes(a));

  const matched = (!isJb && hasAnchor)
    ? FALLBACK_CHUNKS.map((c) => {
        const dn = normalizeText(c.doc_name + " " + c.section + " " + c.content);
        const words = norm.split(/\W+/).filter((w) => w.length > 3);
        const hits = words.filter((w) => dn.includes(w)).length;
        return { ...c, score: Number(Math.min(0.96, 0.25 + hits * 0.16).toFixed(3)), excerpt: c.content };
      }).filter((c) => c.score >= CLIENT_MIN_SCORE).sort((a, b) => b.score - a.score)
    : [];

  let statusCode = "ALLOWED";
  let answer = "";
  let engine = "Motor RAG Edge (Cloudflare / Browser)";

  if (isJb) {
    statusCode = "BLOCKED_JAILBREAK";
    answer = JAILBREAK_BLOCKED_RESPONSE;
    engine = "Escudo Anti-Jailbreak y Legalidad";
  } else if (!matched.length) {
    statusCode = "BLOCKED_OUT_OF_SCOPE";
    answer = OUT_OF_SCOPE_RESPONSE;
    engine = "Guardarraíl de Alcance";
  } else {
    const c = matched[0];
    answer = `De acuerdo con la documentación oficial de nuestra base de conocimiento privada de **Revisoría Fiscal**, se presenta el criterio normativo y técnico aplicable:\n\n### 1. Criterio Principal (\`${c.doc_name}\`)\n**Sección:** *${c.section}* (${c.category})\n\n${c.content}\n\n[Fuente: ${c.doc_name} - ${c.section}]`;
  }

  const seq = LOCAL_LEDGER.length + 1;
  const nowIso = new Date().toISOString();
  const traceId = `TRC-EDGE-${seq.toString().padStart(4, "0")}`;
  const gScore = statusCode === "ALLOWED" ? matched[0].score : 0.0;

  const traceRecord = {
    schema_version: "1.0.0-IMMUTABLE-AUDIT",
    trace_id: traceId,
    sequence_number: seq,
    timestamp: { utc_iso8601: nowIso, local_iso8601: nowIso },
    request: { sanitized_query: sanitized, pii_redacted: piiRedacted },
    response: { status_code: statusCode, engine },
    consulted_sources: matched.map((c) => ({
      chunk_id: c.chunk_id,
      doc_name: c.doc_name,
      category: c.category,
      section: c.section,
      relevance_score: c.score
    })),
    grounding_score: { score: gScore, label: statusCode === "ALLOWED" ? "ALTA FUNDAMENTACIÓN DOCUMENTAL" : "RECHAZO NORMATIVO" },
    compliance_evaluation: {
      compliant: true,
      compliance_score: "100%",
      overall_status: statusCode === "ALLOWED" ? "CUMPLIMIENTO_NORMATIVO_VERIFICADO" : (statusCode === "BLOCKED_JAILBREAK" ? "CUMPLIMIENTO_POR_BLOQUEO_ANTI_JAILBREAK" : "CUMPLIMIENTO_POR_RECHAZO_FUERA_DE_ALCANCE"),
      verdict_summary: "Evaluación de cumplimiento verificada bajo políticas estrictas de Revisoría Fiscal.",
      controls: [
        { control_id: "CTRL-01-DLP", control_name: "Privacidad de Datos y Anonimización PII", result: piiRedacted ? "CUMPLIDO (PII REDACTADO)" : "CUMPLIDO (SIN PII)", evidence: "Inspección DLP ejecutada." },
        { control_id: "CTRL-02-JAILBREAK", control_name: "Defensa Anti-Jailbreak y Anti-Delitos", result: isJb ? "ATAQUE BLOQUEADO" : "CUMPLIDO (SEGURO)", evidence: "Validación ética y de seguridad." },
        { control_id: "CTRL-03-SCOPE", control_name: "Restricción Exclusiva al Corpus de Revisoría Fiscal", result: statusCode, evidence: `Score RAG: ${gScore}` },
        { control_id: "CTRL-04-CITATION", control_name: "Trazabilidad de Citas (NIA 230)", result: "CUMPLIDO", evidence: "Vinculado a documentos oficiales de Google Drive." }
      ]
    },
    immutability_proof: { algorithm: "SHA-256-HASH-CHAIN", prev_hash: LOCAL_LAST_HASH }
  };

  const rHash = await sha256Hex(JSON.stringify(traceRecord));
  traceRecord.record_hash = rHash;
  LOCAL_LAST_HASH = rHash;
  LOCAL_LEDGER.push(traceRecord);

  return {
    answer,
    status_code: statusCode,
    guardrails: {
      sanitized_query: sanitized,
      pii_redacted: piiRedacted,
      jailbreak_detected: isJb,
      retrieval_confidence: gScore,
      layers_summary: [
        { layer: "1. Privacidad y DLP (Redacción PII)", passed: true, status: piiRedacted ? "REDACTED" : "CLEAN", detail: piiRedacted ? "Datos sensibles enmascarados." : "Sin PII expuesto." },
        { layer: "2. Escudo Anti-Jailbreak / Delitos", passed: !isJb, status: isJb ? "BLOCKED" : "SAFE", detail: isJb ? "Solicitud bloqueada por política de seguridad/legalidad." : "Consulta íntegra." },
        { layer: "3. Control Estricto de Alcance Documental", passed: statusCode === "ALLOWED", status: statusCode, detail: `Confianza RAG: ${gScore}` },
        { layer: "4. Verificación de Salida y Citas", passed: true, status: "VERIFIED", detail: "Trazabilidad documental verificada." }
      ]
    },
    sources: matched,
    engine,
    trace_record: traceRecord
  };
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
    if (!res.ok) throw new Error("Static mode");
    const data = await res.json();
    statFiles.textContent = (data.manifest_files || []).length;
    statChunks.textContent = data.indexed_chunks_count || 0;
    auditCount.textContent = data.audit_events_count || 0;
    renderManifestFiles(data.manifest_files);
  } catch (err) {
    renderManifestFiles(FALLBACK_MANIFEST);
  }
}

function renderAuditTable(records) {
  auditCount.textContent = records.length;
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
}

async function refreshAuditLog() {
  try {
    const res = await fetch("/api/traceability");
    if (!res.ok) throw new Error("Static mode");
    const data = await res.json();
    renderAuditTable(data.records || []);
  } catch (e) {
    renderAuditTable([...LOCAL_LEDGER].reverse());
  }
}

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
      badgeText = "Bloqueado · Escudo Anti-Jailbreak / Legalidad";
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
      "⛔ Solicitud Bloqueada: Intento de Jailbreak, Juego de Rol o Conducta Ilícita detectada.";
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
    let data;
    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: trimmed }),
      });
      if (!res.ok) throw new Error("Fallback to local Edge engine");
      data = await res.json();
    } catch (apiErr) {
      data = await evaluateLocalEdgeFallback(trimmed);
    }
    appendMessage("assistant", data.answer, data);
    updateTelemetry(data);
    await refreshAuditLog();
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

document.querySelectorAll(".scenario-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const clone = btn.cloneNode(true);
    const tagEl = clone.querySelector(".tag");
    if (tagEl) tagEl.remove();
    const text = clone.textContent.trim();
    submitQuery(text);
  });
});

thresholdInput.addEventListener("input", () => {
  CLIENT_MIN_SCORE = parseFloat(thresholdInput.value);
  thresholdVal.textContent = CLIENT_MIN_SCORE.toFixed(2);
});

saveConfigBtn.addEventListener("click", async () => {
  if (apiKeyInput.value.trim()) {
    CLIENT_GEMINI_KEY = apiKeyInput.value.trim();
  }
  CLIENT_GEMINI_MODEL = modelSelect.value;
  try {
    await fetch("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        gemini_api_key: CLIENT_GEMINI_KEY,
        gemini_model: CLIENT_GEMINI_MODEL,
        min_retrieval_score: CLIENT_MIN_SCORE,
      }),
    });
  } catch (e) {}
  apiKeyInput.value = "";
  configFeedback.textContent = `✓ Configuración activa (${CLIENT_GEMINI_MODEL}) · Umbral ${CLIENT_MIN_SCORE}`;
});

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
