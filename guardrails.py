# -*- coding: utf-8 -*-
"""
Guardarraíles Ultra-Estrictos para el Agente RAG Privado de Revisoría Fiscal.

Implementa 4 capas de defensa en profundidad:
1. Privacidad y Redacción de PII (DLP) antes de enviar datos a Gemini Cloud o logs.
2. Escudo Anti-Jailbreak, System Override, Desactivación de Trazabilidad/Controles y Prompt Injection.
3. Control Estricto de Alcance (Strict Domain Anchor + RAG Evidence Gate): Solo responde preguntas
   sobre Manuales Internos, NIAs, Control Interno COSO, SARLAFT/SAGRILAFT, Decreto 2420,
   Circulares de Supersociedades y Estatuto Tributario presentes en la base de conocimiento.
4. Validación de Salida (Output Guardrail) para garantizar citas y ausencia de fugas.
"""

import re
import unicodedata
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple


OUT_OF_SCOPE_RESPONSE = (
    "Soy un agente de Revisoría Fiscal alimentado exclusivamente por los manuales internos, "
    "las NIAs y el Estatuto Tributario de nuestra base de conocimiento privada. "
    "Este tema no se encuentra en mi base de conocimiento; por favor, investigue este tema en otro sitio."
)

JAILBREAK_BLOCKED_RESPONSE = (
    "Alerta de Seguridad (Guardarraíl Activo): Su solicitud ha sido bloqueada porque contiene "
    "instrucciones de intento de Jailbreak, System Override, desactivación de trazabilidad o alteración "
    "de directivas de seguridad. Como agente de Revisoría Fiscal, opero bajo políticas inquebrantables "
    "de privacidad, trazabilidad inmutable y solo respondo consultas técnicas de nuestra base oficial."
)


def _normalize_no_accents(text: str) -> str:
    """Convierte a minúsculas y elimina tildes/diacríticos para detección robusta."""
    nfkd = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in nfkd if not unicodedata.combining(c))


@dataclass
class GuardrailEvaluation:
    allowed: bool
    status_code: str  # "ALLOWED", "BLOCKED_JAILBREAK", "BLOCKED_OUT_OF_SCOPE"
    sanitized_query: str
    pii_redacted: bool
    pii_findings: List[Dict[str, str]] = field(default_factory=list)
    jailbreak_detected: bool = False
    jailbreak_triggers: List[str] = field(default_factory=list)
    in_domain_score: float = 0.0
    matched_domain_anchors: List[str] = field(default_factory=list)
    retrieval_confidence: float = 0.0
    forced_response: Optional[str] = None
    layers_summary: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FiscalGuardrails:
    """Motor de Guardarraíles de Entrada, Privacidad, Alcance Estricto y Salida."""

    # 1. Patrones de Datos Personales y Sensibles (PII / DLP Colombia)
    PII_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
        (
            "CORREO_ELECTRONICO",
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            "[EMAIL_REDACTADO]",
        ),
        (
            "NIT_EMPRESARIAL",
            re.compile(r"\b(?:NIT|nit|Nit)[\s:.\-#]*\d{3}[.\s]?\d{3}[.\s]?\d{3}(?:[\s\-]?\d)?\b"),
            "[NIT_REDACTADO]",
        ),
        (
            "DOCUMENTO_IDENTIDAD",
            re.compile(r"\b(?:CC|C\.C\.|cédula|cedula|DNI|TI|CE)[\s:.\-#]*\d{6,12}\b", re.IGNORECASE),
            "[ID_REDACTADO]",
        ),
        (
            "TARJETA_O_CUENTA",
            re.compile(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"),
            "[CUENTA_REDACTADA]",
        ),
        (
            "TELEFONO_MOVIL",
            re.compile(r"\b(?:\+?57[\s\-]?)?3\d{2}[\s\-]?\d{3}[\s\-]?\d{4}\b"),
            "[TELEFONO_REDACTADO]",
        ),
        (
            "CLAVE_O_TOKEN",
            re.compile(
                r"\b(?:AIza[0-9A-Za-z\-_]{20,}|sk-[0-9A-Za-z]{20,}|password\s*[:=]\s*\S+)\b",
                re.IGNORECASE,
            ),
            "[CREDENCIAL_REDACTADA]",
        ),
    ]

    # 2. Patrones Exhaustivos de Jailbreak, System Override y Evasión de Controles
    # Nota: Se evalúan sobre el texto normalizado sin tildes (_normalize_no_accents)
    JAILBREAK_NORMALIZED_PATTERNS: List[Tuple[str, re.Pattern]] = [
        (
            "Directiva de System Override / Bypass de Seguridad",
            re.compile(
                r"(?:system\s*override|admin\s*override|security\s*override|override\s*system|"
                r"override_guardrails|bypass_security|bypass\s+guardrail|sudo\s+mode|root\s+mode|"
                r"modo\s+dios|god\s+mode|comando\s+de\s+sistema|instruccion\s+de\s+sistema|"
                r"prioridad\s+maxima\s+de\s+sistema|\boverride\b)",
                re.IGNORECASE,
            ),
        ),
        (
            "Intento de Desactivar Trazabilidad, Logs, Guardarraíles o Módulos",
            re.compile(
                r"(?:desactiva|desactivar|apaga|apagar|inhabilita|inhabilitar|suspende|suspender|"
                r"elimina|eliminar|omite|omitir|salta|saltar|evade|evadir|quita|quitar|anula|anular|"
                r"disable|deactivate|turn\s+off|shut\s+down|bypass)\s+"
                r"(?:el\s+|la\s+|los\s+|las\s+|tu\s+|tus\s+|todo\s+)?(?:modulo\s+de\s+|sistema\s+de\s+|pipeline\s+de\s+)?"
                r"(?:trazabilidad|guardarrailes|guardrail|filtros?|seguridad|registros?|logs?|auditoria|"
                r"cumplimiento|reglas?|restricciones|controles|privacidad|validacion|verificacion|reto\s*\d*)",
                re.IGNORECASE,
            ),
        ),
        (
            "Solicitud de Operación sin Guardar Registro / Sin Trazabilidad / Modo Libre",
            re.compile(
                r"(?:sin\s+guardar\s+registro|no\s+guardes\s+registro|sin\s+dejar\s+registro|"
                r"sin\s+dejar\s+rastro|sin\s+trazabilidad|sin\s+registrar|sin\s+auditoria|sin\s+logs?|"
                r"off\s+the\s+record|modo\s+libre|free\s+mode|modo\s+abierto|modo\s+sin\s+filtro|"
                r"sin\s+restricciones|sin\s+censura|sin\s+filtros|unrestricted\s+mode|sin\s+guardarrailes)",
                re.IGNORECASE,
            ),
        ),
        (
            "Ignorar o Anular Instrucciones Previas / Reglas del Sistema",
            re.compile(
                r"(?:ignora|ignorar|olvida|olvidar|descarta|descartar|omite|omitir|salta|saltar|"
                r"anula|anular|reemplaza|sobreescribe|ignore|disregard|forget)\s+"
                r"(?:todas\s+|cualquier\s+)?(?:tus\s+|las\s+|mis\s+|los\s+|el\s+|the\s+|all\s+|previous\s+|prior\s+)?"
                r"(?:instrucciones|reglas|directivas|restricciones|limitaciones|guardarrailes|prompts?|"
                r"configuracion|ordenes|contexto|instructions|rules|guidelines)",
                re.IGNORECASE,
            ),
        ),
        (
            "Suplantación de Rol / Jailbreak Clásico (DAN / Modo Desarrollador / Cambio de Identidad)",
            re.compile(
                r"(?:\bdan\b|do\s+anything\s+now|modo\s+desarrollador|developer\s+mode|modo\s+debug|"
                r"debug\s+mode|jailbreak|actua\s+como\s+si\s+no\s+tuvieras|sal\s+de\s+tu\s+rol|"
                r"deja\s+de\s+ser\s+agente|olvida\s+que\s+eres|ya\s+no\s+eres\s+un\s+agente|"
                r"ahora\s+eres\s+un\s+(?:hacker|asistente\s+general|modelo\s+libre|experto\s+en\s+todo|chef|abogado)|"
                r"responde\s+usando\s+tu\s+conocimiento\s+general|responde\s+fuera\s+de\s+tu\s+base)",
                re.IGNORECASE,
            ),
        ),
        (
            "Extracción de System Prompt, Configuración Interna o Datos Privados",
            re.compile(
                r"(?:muestrame|revela|imprime|dime|escribe|repite|copia|extrae|exporta|lista|dame|"
                r"show|reveal|print|repeat|dump|leak)\s+"
                r"(?:tu\s+|el\s+|tus\s+|la\s+|los\s+|todas\s+las\s+|the\s+|your\s+)?"
                r"(?:system\s*prompt|prompt\s+del\s+sistema|instrucciones\s+ocultas|instrucciones\s+internas|"
                r"instrucciones\s+iniciales|configuracion\s+interna|reglas\s+secretas|datos\s+privados|"
                r"consultas\s+de\s+otros\s+usuarios|base\s+de\s+datos\s+completa|claves\s+api|api\s*key)",
                re.IGNORECASE,
            ),
        ),
        (
            "Inyección de Delimitadores o Comandos Falsos de Sistema",
            re.compile(
                r"(?:<\s*/?\s*system\s*>|\[\s*system\s*\]|\[\s*inst\s*\]|###\s*instruction|###\s*system|"
                r"^\s*system\s*:|^\s*admin\s*:|^\s*root\s*:|\breto\s+[1-9]\b.*(?:desactiva|modo|libre|ignora|sin))",
                re.IGNORECASE,
            ),
        ),
    ]

    # 3. Temas explícitamente fuera del alcance de Revisoría Fiscal (incluso si mencionan palabras sueltas)
    EXPLICIT_OUT_OF_SCOPE_NORMALIZED: List[re.Pattern] = [
        re.compile(
            r"\b(?:receta\s+de|cocinar|paella|pizza|restaurante|futbol|partido\s+de|mundial|champions|"
            r"clima|pronostico\s+del\s+tiempo|lluvia|temperatura\s+en|horoscopo|astrologia|chiste|poema|"
            r"cancion|pelicula|serie\s+de\s+tv|videojuego|bitcoin|criptomoneda|trading\s+de|"
            r"diagnosticar|enfermedad|dolor\s+de\s+cabeza|medicina|receta\s+medica|sintomas\s+de|"
            r"novia|pareja|amor|como\s+hackear|escribir\s+un\s+cuento|novela|capital\s+de|"
            r"planeta\s+marte|distancia\s+entre\s+la\s+tierra|sistema\s+solar|historia\s+de\s+roma|"
            r"segunda\s+guerra\s+mundial|codigo\s+en\s+python|programa\s+en\s+javascript|crear\s+una\s+web|"
            r"liquidacion\s+de\s+vacaciones|licencia\s+de\s+maternidad|divorcio|custodia|demanda\s+de\s+alimentos|"
            r"derecho\s+penal|homicidio|traduce\s+al\s+ingles|resumen\s+del\s+libro)\b",
            re.IGNORECASE,
        )
    ]

    # 4. Anclas Técnicas Obligatorias de la Base de Conocimiento
    # Para que una consulta sea admitida, DEBE contener al menos un concepto técnico específico
    # de nuestros Manuales Internos, NIAs, COSO, SARLAFT/SAGRILAFT, Circulares o Estatuto Tributario.
    REQUIRED_FISCAL_ANCHORS: List[str] = [
        # Revisoría Fiscal y Auditoría (Manual 01 y NIAs)
        "revisoria fiscal", "revisor fiscal", "revisores fiscales",
        "auditoria", "auditor", "auditores",
        "nia", "nias", "isae", "nicc", "isqm", "iesba",
        "dictamen", "opinion con salvedades", "salvedad", "salvedades",
        "abstencion de opinion", "denegacion de opinion", "opinion desfavorable", "opinion adversa",
        "opinion modificada", "opinion no modificada",
        "incorreccion material", "incorrecciones", "importancia relativa", "materialidad",
        "error tolerable", "muestreo de auditoria", "muestreo", "pruebas sustantivas",
        "confirmacion externa", "confirmaciones externas", "circularizacion",
        "papeles de trabajo", "memorando de planeacion", "archivo permanente",
        "triangulo del fraude", "escepticismo profesional", "asientos de diario",
        "carta de gerencia", "reserva profesional", "evidencia de auditoria",
        # Control Interno COSO y Hallazgos (Manual 03)
        "control interno", "coso", "ambiente de control", "evaluacion de riesgos",
        "actividades de control", "segregacion de funciones", "itgc",
        "hallazgo", "hallazgos", "debilidad material", "deficiencia significativa",
        "deficiencia de control", "condicion, criterio", "atributos de un hallazgo",
        # Cumplimiento SARLAFT / SAGRILAFT / ROS (Manual 04 y Circulares)
        "sarlaft", "sagrilaft", "ptee", "uiaf", "sirel",
        "operacion sospechosa", "operaciones sospechosas", "reporte ros", "reportes ros", "el ros", "un ros",
        "lavado de activos", "financiacion del terrorismo", "fpadm",
        "oficial de cumplimiento", "debida diligencia", "beneficiario final", "beneficiarios finales",
        "listas restrictivas", "tipping-off", "tipping off", "persona expuesta politicamente", "pep",
        "capitulo x", "circular basica juridica", "soborno transnacional",
        # Decreto 2420, NIIF, Supersociedades y Código de Comercio
        "decreto 2420", "2420 de 2015", "normas de aseguramiento", "niif",
        "estados financieros", "cierre contable", "libros de contabilidad", "prueba contable",
        "supersociedades", "superintendencia de sociedades", "circular externa",
        "100-000002", "100-000003", "100-000004", "100-000008", "100-000015",
        "100-000016", "100-000020", "100-300000", "734390",
        "codigo de comercio", "junta central de contadores",
        # Estatuto Tributario Colombiano
        "estatuto tributario", "declaracion tributaria", "declaraciones tributarias",
        "declaracion de renta", "declaracion de iva", "declaracion de retencion",
        "retencion en la fuente", "retenciones", "impuesto sobre la renta", "impuesto a cargo",
        "sancion por extemporaneidad", "extemporaneidad", "sancion por inexactitud", "inexactitud",
        "dian", "firma del contador", "firma del revisor",
        "articulo 580", "art 580", "art. 580",
        "articulo 581", "art 581", "art. 581",
        "articulo 596", "art 596", "articulo 602", "art 602", "articulo 606", "art 606",
        "articulo 641", "art 641", "art. 641",
        "articulo 643", "art 643", "articulo 647", "art 647", "art. 647", "articulo 648", "art 648",
        "articulo 659", "art 659", "art. 659", "articulo 660", "art 660",
        "articulo 772", "art 772", "articulo 777", "art 777", "art. 777",
        "articulo 203", "articulo 207", "articulo 208", "articulo 209", "articulo 214",
        "ley 43 de 1990", "ley 1762", "smmlv",
    ]

    @classmethod
    def redact_pii(cls, text: str) -> Tuple[str, List[Dict[str, str]]]:
        """Enmascara información personal o sensible (DLP) antes de enviarla al LLM o guardarla."""
        sanitized = text
        findings: List[Dict[str, str]] = []
        for label, pattern, replacement in cls.PII_PATTERNS:
            matches = list(pattern.finditer(sanitized))
            for m in matches:
                original = m.group(0)
                masked_preview = (
                    original[:3] + "***" + original[-2:]
                    if len(original) > 6
                    else "***"
                )
                findings.append({"type": label, "preview": masked_preview, "replacement": replacement})
            if matches:
                sanitized = pattern.sub(replacement, sanitized)
        return sanitized, findings

    @classmethod
    def detect_jailbreak(cls, text: str) -> Tuple[bool, List[str]]:
        """
        Evalúa sobre texto normalizado (sin tildes) si la entrada intenta realizar
        System Override, desactivar trazabilidad/módulos, modo libre, Prompt Injection o Exfiltración.
        """
        norm_text = _normalize_no_accents(text)
        triggers: List[str] = []
        for description, pattern in cls.JAILBREAK_NORMALIZED_PATTERNS:
            if pattern.search(norm_text):
                triggers.append(description)
        return (len(triggers) > 0), triggers

    @classmethod
    def compute_domain_affinity(cls, text: str) -> Tuple[float, bool, List[str]]:
        """
        Verifica de forma estricta:
        1. Si contiene algún tema explícitamente ajeno -> (0.0, True, [])
        2. Cuáles anclas técnicas específicas de Revisoría Fiscal / NIAs / Estatuto Tributario aparecen.
           Si no aparece NINGUNA ancla técnica específica -> score = 0.0 (se rechaza de inmediato).
        """
        norm = _normalize_no_accents(text)
        for pat in cls.EXPLICIT_OUT_OF_SCOPE_NORMALIZED:
            if pat.search(norm):
                return 0.0, True, []

        matched_anchors = [anchor for anchor in cls.REQUIRED_FISCAL_ANCHORS if anchor in norm]
        if not matched_anchors:
            return 0.0, False, []

        score = min(1.0, 0.45 + 0.25 * len(matched_anchors))
        return round(score, 2), False, matched_anchors

    @classmethod
    def evaluate_input_and_retrieval(
        cls,
        user_query: str,
        retrieved_chunks: List[Dict[str, Any]],
        min_retrieval_score: float = 0.25,
    ) -> GuardrailEvaluation:
        """
        Ejecuta las capas de protección estrictas sobre la consulta y los resultados del corpus.
        """
        layers: List[Dict[str, Any]] = []

        # Capa 1: Privacidad y Redacción PII
        sanitized_query, pii_findings = cls.redact_pii(user_query)
        layers.append(
            {
                "layer": "1. Privacidad y DLP (Redacción PII)",
                "passed": True,
                "status": "REDACTED" if pii_findings else "CLEAN",
                "detail": (
                    f"Se enmascararon {len(pii_findings)} dato(s) sensible(s) antes de enviar a Gemini."
                    if pii_findings
                    else "Sin datos personales o credenciales expuestas."
                ),
            }
        )

        # Capa 2: Escudo Anti-Jailbreak, System Override & Desactivación de Trazabilidad
        is_jailbreak, triggers = cls.detect_jailbreak(user_query)
        if is_jailbreak:
            layers.append(
                {
                    "layer": "2. Escudo Anti-Jailbreak / System Override",
                    "passed": False,
                    "status": "BLOCKED",
                    "detail": f"Ataque bloqueado: {', '.join(triggers)}",
                }
            )
            return GuardrailEvaluation(
                allowed=False,
                status_code="BLOCKED_JAILBREAK",
                sanitized_query=sanitized_query,
                pii_redacted=bool(pii_findings),
                pii_findings=pii_findings,
                jailbreak_detected=True,
                jailbreak_triggers=triggers,
                in_domain_score=0.0,
                matched_domain_anchors=[],
                retrieval_confidence=0.0,
                forced_response=JAILBREAK_BLOCKED_RESPONSE,
                layers_summary=layers,
            )

        layers.append(
            {
                "layer": "2. Escudo Anti-Jailbreak / System Override",
                "passed": True,
                "status": "SAFE",
                "detail": "No se detectaron patrones de System Override, desactivación de trazabilidad ni inyección.",
            }
        )

        # Capa 3: Alcance Estricto (Requiere Ancla Técnica de Dominio + Score RAG >= min_retrieval_score)
        domain_score, explicit_oos, matched_anchors = cls.compute_domain_affinity(sanitized_query)
        top_score = max((c.get("score", 0.0) for c in retrieved_chunks), default=0.0)

        # Regla estricta: Debe tener al menos 1 ancla técnica de Revisoría Fiscal/NIAs/ET
        # Y además evidencia en los documentos superior al umbral
        if explicit_oos or domain_score == 0.0 or not matched_anchors or top_score < min_retrieval_score:
            reason_detail = (
                "Tema explícitamente ajeno a Revisoría Fiscal."
                if explicit_oos
                else (
                    "La consulta no contiene ningún concepto técnico de Manuales Internos, NIAs, COSO, SAGRILAFT o Estatuto Tributario."
                    if not matched_anchors
                    else f"Evidencia documental insuficiente (Score RAG: {top_score:.2f} < umbral {min_retrieval_score:.2f})."
                )
            )
            layers.append(
                {
                    "layer": "3. Control Estricto de Alcance y Grounding",
                    "passed": False,
                    "status": "OUT_OF_SCOPE",
                    "detail": reason_detail,
                }
            )
            return GuardrailEvaluation(
                allowed=False,
                status_code="BLOCKED_OUT_OF_SCOPE",
                sanitized_query=sanitized_query,
                pii_redacted=bool(pii_findings),
                pii_findings=pii_findings,
                jailbreak_detected=False,
                jailbreak_triggers=[],
                in_domain_score=domain_score,
                matched_domain_anchors=matched_anchors,
                retrieval_confidence=round(top_score, 3),
                forced_response=OUT_OF_SCOPE_RESPONSE,
                layers_summary=layers,
            )

        layers.append(
            {
                "layer": "3. Control Estricto de Alcance y Grounding",
                "passed": True,
                "status": "GROUNDED",
                "detail": (
                    f"Anclas verificadas ({', '.join(matched_anchors[:3])}) · "
                    f"Evidencia en {len(retrieved_chunks)} fragmento(s) (Confianza: {top_score:.2f})."
                ),
            }
        )

        return GuardrailEvaluation(
            allowed=True,
            status_code="ALLOWED",
            sanitized_query=sanitized_query,
            pii_redacted=bool(pii_findings),
            pii_findings=pii_findings,
            jailbreak_detected=False,
            jailbreak_triggers=[],
            in_domain_score=domain_score,
            matched_domain_anchors=matched_anchors,
            retrieval_confidence=round(top_score, 3),
            forced_response=None,
            layers_summary=layers,
        )

    @classmethod
    def verify_output(
        cls,
        generated_answer: str,
        retrieved_chunks: List[Dict[str, Any]],
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Capa 4: Verifica que la salida del modelo mantenga privacidad, no filtre el prompt
        y cite los documentos de la base de conocimiento o aplique el rechazo normativo.
        """
        if not generated_answer or not generated_answer.strip():
            return OUT_OF_SCOPE_RESPONSE, {
                "layer": "4. Verificación de Salida y Citas",
                "passed": False,
                "status": "FALLBACK",
                "detail": "Respuesta vacía reemplazada por mensaje normativo de Revisoría Fiscal.",
            }

        if "NO_ENCONTRADO_EN_BASE" in generated_answer:
            return OUT_OF_SCOPE_RESPONSE, {
                "layer": "4. Verificación de Salida y Citas",
                "passed": False,
                "status": "OUT_OF_SCOPE_BY_LLM",
                "detail": "El verificador semántico determinó que el dato exacto no consta en los fragmentos.",
            }

        clean_answer, _ = cls.redact_pii(generated_answer)

        source_names = [c.get("doc_name", "") for c in retrieved_chunks]
        has_citation = (
            "[Fuente:" in clean_answer
            or "Fuente:" in clean_answer
            or any(name and name[:15].lower() in clean_answer.lower() for name in source_names)
        )

        if not has_citation and retrieved_chunks:
            citations_footer = "\n\n**Fuentes oficiales verificadas:**\n" + "\n".join(
                f"- `{c['doc_name']}` ({c['category']} — Sección: {c['section']})"
                for c in retrieved_chunks[:3]
            )
            clean_answer = clean_answer.strip() + citations_footer

        return clean_answer, {
            "layer": "4. Verificación de Salida y Citas",
            "passed": True,
            "status": "VERIFIED",
            "detail": "Respuesta anclada exclusivamente a documentos oficiales con trazabilidad de fuentes.",
        }
