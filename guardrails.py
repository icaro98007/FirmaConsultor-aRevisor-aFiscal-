# -*- coding: utf-8 -*-
"""
Guardarraíles Ultra-Estrictos para el Agente RAG Privado de Revisoría Fiscal.

Implementa 4 capas de defensa en profundidad:
1. Privacidad y Redacción de PII (DLP) antes de enviar datos a Gemini Cloud o logs.
2. Escudo Anti-Jailbreak, Anti-Roleplay/Simulación, Anti-Fraude/Ocultamiento de Hallazgos,
   System Override, Desactivación de Trazabilidad/Logs y Prompt Injection.
3. Control Estricto de Alcance Documental (Strict Corpus Whitelist + Verificación de Artículos/NIAs):
   Solo responde lo que está explícitamente contenido en los documentos de la carpeta Google Drive.
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
    "Alerta de Seguridad y Legalidad (Guardarraíl Activo): Su solicitud ha sido bloqueada porque "
    "involucra un posible delito, conducta ilícita, evasión, fraude, manipulación de evidencia/logs "
    "o intento de Jailbreak. Como agente de Revisoría Fiscal, opero bajo estricto cumplimiento de la ley "
    "penal y tributaria colombiana, el Código de Ética (IESBA / Ley 43 de 1990) y trazabilidad inmutable, "
    "por lo que rechazo cualquier solicitud que busque facilitar, simular o encubrir actos ilícitos."
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
    """Motor de Guardarraíles de Entrada, Privacidad, Alcance Documental Estricto y Salida."""

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

    # 2. Patrones Exhaustivos de Jailbreak, Roleplay, Simulación, Ocultamiento/Fraude y System Override
    # Evaluados sobre texto normalizado sin tildes (_normalize_no_accents)
    JAILBREAK_NORMALIZED_PATTERNS: List[Tuple[str, re.Pattern]] = [
        (
            "Juego de Rol / Suplantación de Autoridad (CEO, Socio, Hacker) / Escenario Hipotético",
            re.compile(
                r"(?:juego\s+de\s+rol|role\s*play|imagina\s+que|imaginemos\s+que|simula\s+que|"
                r"simulando\s+que|finge\s+que|fingiendo\s+que|supongamos\s+que|supon\s+que|"
                r"haz\s+de\s+cuenta|ponte\s+en\s+el\s+papel|asume\s+el\s+rol|comportate\s+como|"
                r"en\s+un\s+escenario\s+ficticio|en\s+un\s+mundo\s+ficticio|hipoteticamente|"
                r"para\s+una\s+novela|para\s+un\s+guion|actua\s+como\b|eres\s+el\s+ceo|soy\s+el\s+ceo|"
                r"soy\s+el\s+socio|soy\s+tu\s+jefe|eres\s+un\s+hacker|hacker\s+etico|pentester|atacante|"
                r"ordename\b|autorizame\b|te\s+ordeno\s+que)",
                re.IGNORECASE,
            ),
        ),
        (
            "Solicitud de Ignorar/Ocultar Hallazgos, Lavado de Activos, Inconsistencias o Manipular Logs",
            re.compile(
                r"(?:ocultar|ocultarle|esconder|maquillar|disfrazar|encubrir|alterar|borrar|eliminar|"
                r"manipular|falsificar|adulterar|destruir|evadir|eludir|enganar|burlar|"
                r"ignorar|ignora|omitir|omite|pasar\s+por\s+alto|hacer\s+caso\s+omiso|"
                r"no\s+reportar|no\s+informar|callar|silenciar|tapar|desestimar)\s+"
                r"(?:las?\s+|los?\s+|el\s+|un\s+|una\s+|este\s+|ese\s+|cualquier\s+|la\s+tabla\s+de\s+|los\s+archivos\s+de\s+)?"
                r"(?:inconsistencias?|hallazgos?|evidencias?|logs?|tabla\s+de\s+logs|registros?|trazabilidad|"
                r"impuestos?|declaraciones|dian|uiaf|supersociedades|estados\s+financieros|contabilidad|"
                r"papeles\s+de\s+trabajo|controles|auditoria|fraude|lavado\s+de\s+activos|"
                r"operacion\s+sospechosa|ros\b|sanciones?|irregularidades?|alertas?)",
                re.IGNORECASE,
            ),
        ),
        (
            "Instrucción de Sabotaje de Base de Datos / Tabla de Logs / Borrado de Evidencia",
            re.compile(
                r"(?:alterar\s+la\s+tabla|borrar\s+un\s+hallazgo|borrar\s+el\s+historial|borrar\s+los\s+logs|"
                r"eliminar\s+evidencia|modificar\s+el\s+ledger|romper\s+la\s+cadena|como\s+lo\s+harias.*ocultar|"
                r"dime\s+como\s+(?:alterar|borrar|ocultar|evadir|hackear|vulnerar|falsificar))",
                re.IGNORECASE,
            ),
        ),
        (
            "Delito Financiero, Contable o Tributario (Doble Contabilidad, Facturas Falsas, Evasión, Fraude)",
            re.compile(
                r"(?:doble\s+contabilidad|llevar\s+dos\s+contabilidades|facturas?\s+falsas?|facturacion\s+falsa|"
                r"proveedor(?:es)?\s+ficticios?|empresa(?:s)?\s+fachada|empresa(?:s)?\s+de\s+papel|"
                r"costos?\s+inexistentes?|pasivos?\s+ficticios?|ingresos?\s+ficticios?|inflar\s+(?:ingresos|activos|utilidades)|"
                r"maquillar\s+(?:estados\s+financieros|balances|cifras|contabilidad)|"
                r"falsificar\s+(?:estados\s+financieros|certificaciones|firmas|documentos|soportes|facturas)|"
                r"certificar\s+hechos\s+falsos|falsedad\s+en\s+documento|defraudacion\s+tributaria|"
                r"como\s+(?:evadir|eludir|no\s+pagar)\s+impuestos|evadir\s+a\s+la\s+dian|"
                r"sin\s+que\s+la\s+dian\s+(?:se\s+de\s+cuenta|lo\s+detecte|lo\s+note)|"
                r"sin\s+que\s+(?:el\s+auditor|la\s+revisoria|supersociedades|la\s+uiaf)\s+(?:se\s+de\s+cuenta|lo\s+detecte))",
                re.IGNORECASE,
            ),
        ),
        (
            "Delito de Lavado de Activos, Testaferrato, Fraccionamiento (Pitufeo) o Violación de Reserva ROS",
            re.compile(
                r"(?:como\s+lavar\s+(?:dinero|activos)|blanquear\s+(?:capitales|dinero|activos)|"
                r"pitufeo|smurfing|fraccionar\s+(?:operaciones|transacciones|depositos)\s+para\s+no|"
                r"usar\s+testaferros?|ocultar\s+(?:el\s+)?beneficiario\s+final|burlar\s+(?:el\s+)?(?:sarlaft|sagrilaft|uiaf)|"
                r"avisar(?:le)?\s+al\s+cliente.*ros|alertar\s+al\s+reportado|cometer\s+lavado)",
                re.IGNORECASE,
            ),
        ),
        (
            "Delito de Corrupción, Soborno, Cohecho o Peculado",
            re.compile(
                r"(?:sobornar|pagar\s+(?:un\s+)?soborno|pagar\s+coima|dar\s+coima|dadiva\s+ilegal|"
                r"comprar\s+a\s+un\s+(?:funcionario|inspector|auditor|revisor|juez|fiscal)|"
                r"cohecho|peculado|concusion|colusion\s+en\s+licitacion|comision\s+ilegal\s+bajo\s+cuerda)",
                re.IGNORECASE,
            ),
        ),
        (
            "Delito Informático o General (Hackeo, Robo, Extorsión, Falsificación, Narcotráfico, Violencia)",
            re.compile(
                r"(?:hackear|vulnerar\s+un\s+sistema|acceso\s+abusivo|robar\s+(?:datos|contrasenas|dinero|identidad)|"
                r"clonar\s+tarjetas|phishing|ransomware|malware|extorsionar|extorsion|secuestrar|secuestro|"
                r"chantajear|amenazar\s+de\s+muerte|homicidio|asesinar|matar\s+a|narcotrafico|trafico\s+de\s+(?:drogas|armas|influencias)|"
                r"contrabando|estafar|como\s+cometer\s+un\s+(?:delito|fraude|robo|crimen|ilicito)|"
                r"sin\s+dejar\s+evidencia\s+del\s+delito|sin\s+ir\s+a\s+la\s+carcel)",
                re.IGNORECASE,
            ),
        ),
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

    # 3. Temas explícitamente NO incluidos en los 16 documentos (tanto generales como subtemas contables/legales no presentes)
    EXPLICIT_OUT_OF_SCOPE_NORMALIZED: List[re.Pattern] = [
        re.compile(
            r"\b(?:receta\s+de|cocinar|paella|pizza|restaurante|futbol|partido\s+de|mundial|champions|"
            r"clima|pronostico\s+del\s+tiempo|lluvia|temperatura\s+en|horoscopo|astrologia|chiste|poema|"
            r"cancion|pelicula|serie\s+de\s+tv|videojuego|bitcoin|criptomoneda|trading\s+de|"
            r"diagnosticar|enfermedad|dolor\s+de\s+cabeza|medicina|receta\s+medica|sintomas\s+de|"
            r"novia|pareja|amor|como\s+hackear|escribir\s+un\s+cuento|novela|capital\s+de|"
            r"planeta\s+marte|distancia\s+entre\s+la\s+tierra|sistema\s+solar|historia\s+de\s+roma|"
            r"segunda\s+guerra\s+mundial|codigo\s+en\s+python|programa\s+en\s+javascript|crear\s+una\s+web|"
            r"liquidacion\s+de\s+vacaciones|licencia\s+de\s+maternidad|cesantias|prima\s+de\s+servicios|"
            r"horas\s+extras|contrato\s+de\s+trabajo|despido\s+sin\s+justa\s+causa|divorcio|custodia|"
            r"demanda\s+de\s+alimentos|derecho\s+penal|homicidio|traduce\s+al\s+ingles|resumen\s+del\s+libro|"
            r"impuesto\s+al\s+patrimonio|impuesto\s+saludable|bolsas\s+plasticas|regimen\s+simple|rst|"
            r"precios\s+de\s+transferencia|factura\s+electronica|nomina\s+electronica|ica\s+bogota|"
            r"predial|vehiculos|arancel|aduanas)\b",
            re.IGNORECASE,
        )
    ]

    # Listas blancas de números de NIA y Artículos que SÍ existen en nuestros documentos
    SUPPORTED_NIA_NUMBERS = {"200", "230", "240", "265", "315", "320", "330", "500", "505", "530", "700", "701", "705"}
    SUPPORTED_ARTICLE_NUMBERS = {
        "13", "27", "203", "207", "208", "209", "214",
        "580", "581", "596", "602", "606",
        "641", "643", "647", "648",
        "659", "660",
        "772", "773", "774", "775", "776", "777",
    }

    # 4. Anclas Técnicas Obligatorias de los 16 Documentos en Drive
    REQUIRED_FISCAL_ANCHORS: List[str] = [
        # Manual 01 y NIAs (Manual 02)
        "revisoria fiscal", "revisor fiscal", "revisores fiscales",
        "procedimientos de auditoria", "memorando de planeacion", "mpa",
        "nia", "nias", "isae 3000", "isae", "nicc", "isqm", "iesba",
        "dictamen", "opinion con salvedades", "salvedad", "salvedades",
        "abstencion de opinion", "denegacion de opinion", "opinion desfavorable", "opinion adversa",
        "opinion modificada", "opinion no modificada",
        "incorreccion material", "incorrecciones", "importancia relativa", "materialidad",
        "error tolerable", "muestreo de auditoria", "muestreo", "pruebas sustantivas",
        "confirmacion externa", "confirmaciones externas", "circularizacion",
        "papeles de trabajo", "archivo permanente",
        "triangulo del fraude", "escepticismo profesional", "asientos de diario",
        "carta de gerencia", "reserva profesional", "evidencia de auditoria",
        # Control Interno COSO y Hallazgos (Manual 03)
        "control interno", "coso", "ambiente de control", "evaluacion de riesgos",
        "actividades de control", "segregacion de funciones", "itgc",
        "hallazgo", "hallazgos", "debilidad material", "deficiencia significativa",
        "deficiencia de control", "atributos de un hallazgo",
        # Cumplimiento SARLAFT / SAGRILAFT / ROS (Manual 04 y Circulares)
        "sarlaft", "sagrilaft", "ptee", "uiaf", "sirel",
        "operacion sospechosa", "operaciones sospechosas", "reporte ros", "reportes ros", "el ros", "un ros",
        "lavado de activos", "financiacion del terrorismo", "fpadm",
        "oficial de cumplimiento", "debida diligencia", "beneficiario final", "beneficiarios finales",
        "listas restrictivas", "tipping-off", "tipping off", "persona expuesta politicamente", "pep",
        "capitulo x", "circular basica juridica", "soborno transnacional",
        # Decreto 2420, NIIF, Supersociedades y Código de Comercio
        "decreto 2420", "2420 de 2015", "normas de aseguramiento", "niif",
        "estados financieros", "libros de contabilidad", "prueba contable",
        "supersociedades", "superintendencia de sociedades", "circular externa",
        "100-000002", "100-000003", "100-000004", "100-000008", "100-000015",
        "100-000016", "100-000020", "100-300000", "734390",
        "codigo de comercio", "junta central de contadores",
        # Estatuto Tributario Colombiano (Secciones presentes en el corpus)
        "estatuto tributario", "declaracion tributaria", "declaraciones tributarias",
        "sancion por extemporaneidad", "extemporaneidad", "sancion por inexactitud", "inexactitud",
        "firma del contador", "firma del revisor",
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
        Juego de Rol/Simulación, Ocultamiento de Hallazgos/Inconsistencias, Alteración de Logs,
        System Override, Desactivación de Trazabilidad, Prompt Injection o Exfiltración.
        """
        norm_text = _normalize_no_accents(text)
        triggers: List[str] = []
        for description, pattern in cls.JAILBREAK_NORMALIZED_PATTERNS:
            if pattern.search(norm_text):
                triggers.append(description)
        return (len(triggers) > 0), triggers

    @classmethod
    def check_unsupported_citations(cls, norm_text: str) -> Optional[str]:
        """
        Verifica si el usuario pregunta por un número específico de NIA o Artículo
        que NO existe dentro de nuestros documentos de Google Drive.
        """
        for m in re.finditer(r"\bnia\s*(\d{2,4})\b", norm_text):
            num = m.group(1)
            if num not in cls.SUPPORTED_NIA_NUMBERS:
                return f"La NIA {num} no forma parte de los documentos indexados en nuestra base privada."

        for m in re.finditer(r"\bart(?:iculo|\.)?\s*(\d{1,4})\b", norm_text):
            num = m.group(1)
            if num not in cls.SUPPORTED_ARTICLE_NUMBERS:
                return f"El Artículo {num} no se encuentra dentro de los fragmentos normativos de nuestra base."

        return None

    @classmethod
    def compute_domain_affinity(cls, text: str) -> Tuple[float, bool, List[str], Optional[str]]:
        """
        Verifica de forma estricta:
        1. Si contiene algún tema explícitamente ajeno o no soportado -> (0.0, True, [], reason)
        2. Si cita una NIA o Artículo que no está en los documentos -> (0.0, True, [], reason)
        3. Cuáles anclas técnicas específicas de los documentos aparecen.
        """
        norm = _normalize_no_accents(text)
        for pat in cls.EXPLICIT_OUT_OF_SCOPE_NORMALIZED:
            if pat.search(norm):
                return 0.0, True, [], "Tema fuera del alcance de los documentos de Revisoría Fiscal."

        unsupported_reason = cls.check_unsupported_citations(norm)
        if unsupported_reason:
            return 0.0, True, [], unsupported_reason

        matched_anchors = [anchor for anchor in cls.REQUIRED_FISCAL_ANCHORS if anchor in norm]
        if not matched_anchors:
            return 0.0, False, [], "La consulta no menciona ningún tema presente en los documentos de la base privada."

        score = min(1.0, 0.45 + 0.25 * len(matched_anchors))
        return round(score, 2), False, matched_anchors, None

    @classmethod
    def evaluate_input_and_retrieval(
        cls,
        user_query: str,
        retrieved_chunks: List[Dict[str, Any]],
        min_retrieval_score: float = 0.28,
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

        # Capa 2: Escudo Anti-Jailbreak, Anti-Roleplay, Anti-Fraude y System Override
        is_jailbreak, triggers = cls.detect_jailbreak(user_query)
        if is_jailbreak:
            layers.append(
                {
                    "layer": "2. Escudo Anti-Jailbreak / Roleplay / Sabotaje",
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
                "layer": "2. Escudo Anti-Jailbreak / Roleplay / Sabotaje",
                "passed": True,
                "status": "SAFE",
                "detail": "Sin patrones de juego de rol, ocultamiento ilícito, manipulación de logs ni System Override.",
            }
        )

        # Capa 3: Alcance Documental Estricto (Ancla + Cobertura en Documentos + Score RAG >= min_retrieval_score)
        domain_score, explicit_oos, matched_anchors, oos_reason = cls.compute_domain_affinity(sanitized_query)
        top_score = max((c.get("score", 0.0) for c in retrieved_chunks), default=0.0)
        top_matched_terms = max((c.get("matched_terms", 0) for c in retrieved_chunks), default=0)

        # Exigimos que:
        # 1) No sea un tema o artículo no soportado (explicit_oos == False)
        # 2) Contenga al menos 1 ancla específica de los documentos (matched_anchors)
        # 3) El fragmento recuperado tenga score >= min_retrieval_score y al menos 2 términos técnicos coincidentes
        if (
            explicit_oos
            or domain_score == 0.0
            or not matched_anchors
            or top_score < min_retrieval_score
            or (top_matched_terms < 2 and top_score < 0.45)
        ):
            reason_detail = (
                oos_reason
                if oos_reason
                else (
                    f"Evidencia insuficiente en los documentos de Google Drive "
                    f"(Score RAG: {top_score:.2f}, Términos verificados: {top_matched_terms})."
                )
            )
            layers.append(
                {
                    "layer": "3. Control Estricto de Alcance Documental",
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
                "layer": "3. Control Estricto de Alcance Documental",
                "passed": True,
                "status": "GROUNDED",
                "detail": (
                    f"Anclas documentales verificadas ({', '.join(matched_anchors[:3])}) · "
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
