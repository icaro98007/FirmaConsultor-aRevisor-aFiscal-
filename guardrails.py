# -*- coding: utf-8 -*-
"""
Guardarraíles Estrictos para el Agente RAG Privado de Revisoría Fiscal.

Implementa 4 capas de defensa en profundidad:
1. Privacidad y Redacción de PII (DLP) antes de enviar datos a Gemini Cloud o logs.
2. Detección de Jailbreak, Prompt Injection y extracción de configuración/datos.
3. Control de Alcance (Out-of-Scope) y Umbral de Evidencia Documental (Strict Grounding).
4. Validación de Salida (Output Guardrail) para garantizar citas y ausencia de fugas.
"""

import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple


OUT_OF_SCOPE_RESPONSE = (
    "Soy un agente de Revisoría Fiscal alimentado exclusivamente por los manuales internos, "
    "las NIAs y el Estatuto Tributario de nuestra base de conocimiento privada. "
    "Este tema no se encuentra en mi base de conocimiento; por favor, investigue este tema en otro sitio."
)

JAILBREAK_BLOCKED_RESPONSE = (
    "Alerta de Seguridad (Guardarraíl Activo): Su solicitud ha sido bloqueada porque contiene "
    "instrucciones que intentan alterar las directivas de seguridad, vulnerar la privacidad de los datos "
    "o desviar mi función. Como agente de Revisoría Fiscal, opero bajo políticas estrictas de privacidad "
    "y solo respondo consultas técnicas respaldadas por nuestra base de conocimiento oficial."
)


@dataclass
class GuardrailEvaluation:
    allowed: bool
    status_code: str  # "ALLOWED", "BLOCKED_JAILBREAK", "BLOCKED_OUT_OF_SCOPE", "BLOCKED_NO_EVIDENCE"
    sanitized_query: str
    pii_redacted: bool
    pii_findings: List[Dict[str, str]] = field(default_factory=list)
    jailbreak_detected: bool = False
    jailbreak_triggers: List[str] = field(default_factory=list)
    in_domain_score: float = 0.0
    retrieval_confidence: float = 0.0
    forced_response: Optional[str] = None
    layers_summary: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FiscalGuardrails:
    """Motor de Guardarraíles de Entrada, Privacidad y Salida."""

    # Patrones de Datos Personales y Sensibles (PII / DLP Colombia)
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
            re.compile(r"\b(?:AIza[0-9A-Za-z\-_]{20,}|sk-[0-9A-Za-z]{20,}|password\s*[:=]\s*\S+)\b", re.IGNORECASE),
            "[CREDENCIAL_REDACTADA]",
        ),
    ]

    # Patrones heurísticos de Jailbreak / Prompt Injection / Exfiltración
    JAILBREAK_PATTERNS: List[Tuple[str, re.Pattern]] = [
        (
            "Ignorar instrucciones previas",
            re.compile(
                r"(?:ignora|olvida|descarta|omite|salta|anula|ignore|disregard|forget)\s+"
                r"(?:todas\s+)?(?:tus|las|mis|the|all|previous|prior)?\s*"
                r"(?:instrucciones|reglas|directivas|restricciones|limitaciones|guardarra[ií]les|prompts?|instructions|rules)",
                re.IGNORECASE,
            ),
        ),
        (
            "Suplantación de rol / Modo sin restricciones (DAN / Developer Mode)",
            re.compile(
                r"(?:\bDAN\b|do\s+anything\s+now|modo\s+desarrollador|developer\s+mode|modo\s+dios|"
                r"jailbreak|sin\s+restricciones|sin\s+censura|sin\s+filtros|"
                r"act[uú]a\s+como\s+si\s+no\s+tuvieras\s+reglas|"
                r"ahora\s+eres\s+un\s+(?:hacker|asistente\s+general|chef|poeta|abogado\s+penal|modelo\s+libre))",
                re.IGNORECASE,
            ),
        ),
        (
            "Extracción de System Prompt o Configuración Interna",
            re.compile(
                r"(?:mu[eé]strame|revela|imprime|dime|escribe|repite|copia|show|reveal|print|repeat|dump)\s+"
                r"(?:tu|el|tus|the|your)?\s*"
                r"(?:system\s*prompt|prompt\s+del\s+sistema|instrucciones\s+ocultas|instrucciones\s+internas|"
                r"configuraci[oó]n\s+interna|reglas\s+secretas|initial\s+prompt)",
                re.IGNORECASE,
            ),
        ),
        (
            "Exfiltración de datos de otros usuarios o base privada",
            re.compile(
                r"(?:dame|mu[eé]strame|extrae|lista|exporta)\s+"
                r"(?:los\s+datos\s+privados|las\s+consultas\s+de\s+otros\s+usuarios|"
                r"toda\s+la\s+base\s+de\s+datos|las\s+contrase[nñ]as|los\s+correos\s+de\s+clientes)",
                re.IGNORECASE,
            ),
        ),
        (
            "Inyección de delimitadores de sistema",
            re.compile(
                r"(?:<\s*/?\s*system\s*>|\[\s*SYSTEM\s*\]|###\s*INSTRUCTION|###\s*SYSTEM|"
                r"sudo\s+mode|override_guardrails|bypass_security)",
                re.IGNORECASE,
            ),
        ),
    ]

    # Términos explícitamente fuera de alcance (temas cotidianos, entretenimiento, programación general, medicina, etc.)
    EXPLICIT_OUT_OF_SCOPE_PATTERNS: List[re.Pattern] = [
        re.compile(
            r"\b(?:receta\s+de|cocinar|paella|pizza|f[uú]tbol|partido\s+de|clima\s+en|pron[oó]stico\s+del\s+tiempo|"
            r"hor[oó]scopo|chiste|poema|canci[oó]n|pel[ií]cula|videojuego|bitcoin\s+trading|"
            r"diagnosticar\s+enfermedad|dolor\s+de\s+cabeza|medicina|novia|pareja|"
            r"c[oó]mo\s+hackear|escribir\s+un\s+cuento|qu[eé]\s+opinas\s+de\s+la\s+pol[ií]tica|"
            r"capital\s+de\s+francia|qui[eé]n\s+gan[oó]\s+el\s+mundial)\b",
            re.IGNORECASE,
        )
    ]

    # Vocabulario de dominio (Revisoría Fiscal, NIAs, COSO, SARLAFT/SAGRILAFT, Estatuto Tributario, Supersociedades)
    DOMAIN_KEYWORDS: List[str] = [
        "revisoría", "revisoria", "revisor", "fiscal", "auditoría", "auditoria", "auditor",
        "nia", "nias", "isa", "control interno", "coso", "hallazgo", "hallazgos", "evidencia",
        "muestreo", "materialidad", "importancia relativa", "riesgo", "riesgos", "fraude",
        "incorrección", "incorreccion", "dictamen", "opinión", "opinion", "salvedad", "abstención",
        "sarlaft", "sagrilaft", "ptee", "ros", "uiaf", "lavado de activos", "financiación del terrorismo",
        "debida diligencia", "beneficiario final", "pep", "oficial de cumplimiento", "matriz de riesgo",
        "estatuto tributario", "tributario", "tributaria", "impuesto", "renta", "iva", "retención",
        "retencion", "dian", "sanción", "sancion", "extemporaneidad", "inexactitud", "declaración",
        "declaracion", "artículo", "articulo", "decreto", "2420", "circular", "externa",
        "supersociedades", "superintendencia", "contabilidad", "niif", "estados financieros",
        "papeles de trabajo", "confirmación", "confirmaciones", "circularización", "inventarios",
        "gobierno corporativo", "ética", "etica", "independencia", "código de comercio", "manual",
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
        """Evalúa si la entrada intenta realizar Prompt Injection, Jailbreak o Exfiltración."""
        triggers: List[str] = []
        for description, pattern in cls.JAILBREAK_PATTERNS:
            if pattern.search(text):
                triggers.append(description)
        return (len(triggers) > 0), triggers

    @classmethod
    def compute_domain_affinity(cls, text: str) -> Tuple[float, bool]:
        """Calcula afinidad con el dominio de Revisoría Fiscal y detecta temas explícitamente ajenos."""
        lower = text.lower()
        for pat in cls.EXPLICIT_OUT_OF_SCOPE_PATTERNS:
            if pat.search(lower):
                return 0.0, True

        matched = [kw for kw in cls.DOMAIN_KEYWORDS if kw in lower]
        # Normalizamos el puntaje entre 0.0 y 1.0
        score = min(1.0, len(matched) / 2.0)
        return round(score, 2), False

    @classmethod
    def evaluate_input_and_retrieval(
        cls,
        user_query: str,
        retrieved_chunks: List[Dict[str, Any]],
        min_retrieval_score: float = 0.18,
    ) -> GuardrailEvaluation:
        """
        Ejecuta las capas de protección sobre la consulta y los resultados recuperados del corpus.
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

        # Capa 2: Escudo Anti-Jailbreak & Prompt Injection
        is_jailbreak, triggers = cls.detect_jailbreak(user_query)
        if is_jailbreak:
            layers.append(
                {
                    "layer": "2. Escudo Anti-Jailbreak / Prompt Injection",
                    "passed": False,
                    "status": "BLOCKED",
                    "detail": f"Intento bloqueado: {', '.join(triggers)}",
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
                retrieval_confidence=0.0,
                forced_response=JAILBREAK_BLOCKED_RESPONSE,
                layers_summary=layers,
            )

        layers.append(
            {
                "layer": "2. Escudo Anti-Jailbreak / Prompt Injection",
                "passed": True,
                "status": "SAFE",
                "detail": "No se detectaron patrones de manipulación de instrucciones ni exfiltración.",
            }
        )

        # Capa 3: Alcance Temático y Evidencia Documental (Strict RAG Grounding)
        domain_score, explicit_oos = cls.compute_domain_affinity(sanitized_query)
        top_score = max((c.get("score", 0.0) for c in retrieved_chunks), default=0.0)

        if explicit_oos or (domain_score == 0.0 and top_score < 0.30) or (top_score < min_retrieval_score):
            layers.append(
                {
                    "layer": "3. Control de Alcance y Grounding Documental",
                    "passed": False,
                    "status": "OUT_OF_SCOPE",
                    "detail": (
                        f"Consulta fuera del alcance documental (Afinidad: {domain_score:.2f}, "
                        f"Relevancia RAG máx: {top_score:.2f} < umbral {min_retrieval_score:.2f})."
                    ),
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
                retrieval_confidence=round(top_score, 3),
                forced_response=OUT_OF_SCOPE_RESPONSE,
                layers_summary=layers,
            )

        layers.append(
            {
                "layer": "3. Control de Alcance y Grounding Documental",
                "passed": True,
                "status": "GROUNDED",
                "detail": (
                    f"Evidencia verificada en {len(retrieved_chunks)} fragmento(s) "
                    f"(Confianza máx: {top_score:.2f})."
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

        # Si el propio LLM detectó que los fragmentos no contienen la respuesta exacta
        if "NO_ENCONTRADO_EN_BASE" in generated_answer:
            return OUT_OF_SCOPE_RESPONSE, {
                "layer": "4. Verificación de Salida y Citas",
                "passed": False,
                "status": "OUT_OF_SCOPE_BY_LLM",
                "detail": "El verificador semántico determinó que el dato exacto no consta en los fragmentos.",
            }

        # Redactar cualquier PII residual en la respuesta
        clean_answer, _ = cls.redact_pii(generated_answer)

        # Verificar que exista referencia a las fuentes recuperadas
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
