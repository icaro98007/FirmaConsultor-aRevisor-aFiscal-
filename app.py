# -*- coding: utf-8 -*-
"""
Servidor Web y API REST para el Agente RAG Privado de Revisoría Fiscal.
Incluye el Pipeline de Trazabilidad Inmutable (SHA-256 Hash Chain + Append-Only JSONL).
Ejecución: python app.py (por defecto en http://127.0.0.1:8080)
"""

import base64
import json
import mimetypes
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Dict, Any, List
from urllib.parse import urlparse

from guardrails import FiscalGuardrails, OUT_OF_SCOPE_RESPONSE, JAILBREAK_BLOCKED_RESPONSE
from rag_engine import PrivateFiscalRAG, DRIVE_FOLDER_ID, DRIVE_FOLDER_URL
from traceability import ImmutableTraceabilityPipeline

BASE_DIR = Path(__file__).resolve().parent
DATA_RAW_DIR = BASE_DIR / "data" / "raw"
MANIFEST_PATH = BASE_DIR / "data" / "drive_manifest.json"
LEDGER_PATH = BASE_DIR / "data" / "audit_ledger.jsonl"
STATIC_DIR = BASE_DIR / "static"

DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

rag_engine = PrivateFiscalRAG(data_dir=DATA_RAW_DIR, manifest_path=MANIFEST_PATH)
trace_pipeline = ImmutableTraceabilityPipeline(ledger_path=LEDGER_PATH)

RUNTIME_CONFIG: Dict[str, Any] = {
    "gemini_api_key": os.environ.get("GEMINI_API_KEY", ""),
    "gemini_model": os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"),
    "min_retrieval_score": 0.25,
}


def process_fiscal_query(user_query: str) -> Dict[str, Any]:
    """Ejecuta el flujo completo de Guardarraíles + RAG Privado + Gemini API + Trazabilidad Inmutable."""
    query_str = (user_query or "").strip()
    if not query_str:
        return {
            "answer": "Por favor ingrese una consulta técnica relacionada con nuestros manuales internos, NIAs o el Estatuto Tributario.",
            "status_code": "EMPTY_QUERY",
            "guardrails": {},
            "sources": [],
            "engine": "Validación de Entrada",
        }

    # 1. Pre-sanitizar PII antes de buscar o evaluar
    sanitized_query, _ = FiscalGuardrails.redact_pii(query_str)

    # 2. Recuperación en la base de conocimiento privada
    retrieved = rag_engine.retrieve(sanitized_query, top_k=4)

    # 3. Evaluación de Guardarraíles de Entrada y Alcance
    evaluation = FiscalGuardrails.evaluate_input_and_retrieval(
        user_query=query_str,
        retrieved_chunks=retrieved,
        min_retrieval_score=RUNTIME_CONFIG["min_retrieval_score"],
    )

    if not evaluation.allowed:
        guardrails_dict = evaluation.to_dict()
        trace_record = trace_pipeline.record_interaction(
            sanitized_query=evaluation.sanitized_query,
            answer_text=evaluation.forced_response or OUT_OF_SCOPE_RESPONSE,
            status_code=evaluation.status_code,
            guardrails_dict=guardrails_dict,
            sources=[],
            engine_used="Guardarraíl de Seguridad Activo (Solicitud Rechazada)",
        )
        return {
            "answer": evaluation.forced_response,
            "status_code": evaluation.status_code,
            "guardrails": guardrails_dict,
            "sources": [],
            "engine": "Guardarraíl de Seguridad Activo (Solicitud Rechazada)",
            "trace_record": trace_record,
        }

    # 4. Generación con Google Gemini API Cloud Privada (solo recibe texto sanitizado y fragmentos oficiales)
    raw_answer, engine_used = rag_engine.generate_grounded_response(
        sanitized_query=evaluation.sanitized_query,
        retrieved_chunks=retrieved,
        api_key=RUNTIME_CONFIG.get("gemini_api_key"),
        model_name=RUNTIME_CONFIG.get("gemini_model", "gemini-2.5-flash"),
    )

    # 5. Guardarraíl de Salida (Verificación de citas y no alucinación)
    verified_answer, output_layer = FiscalGuardrails.verify_output(raw_answer, retrieved)
    evaluation.layers_summary.append(output_layer)

    if output_layer.get("status") == "OUT_OF_SCOPE_BY_LLM":
        evaluation.status_code = "BLOCKED_OUT_OF_SCOPE"
        sources_out: List[Dict[str, Any]] = []
    else:
        sources_out = [
            {
                "chunk_id": c["chunk_id"],
                "doc_name": c["doc_name"],
                "category": c["category"],
                "section": c["section"],
                "score": c["score"],
                "excerpt": c["content"][:280] + ("..." if len(c["content"]) > 280 else ""),
                "drive_url": f"https://drive.google.com/file/d/{c['drive_id']}/view"
                if c.get("drive_id") and c["drive_id"] != DRIVE_FOLDER_ID
                else DRIVE_FOLDER_URL,
            }
            for c in retrieved
        ]

    guardrails_dict = evaluation.to_dict()

    # 6. Generar registro estructurado inmutable en el Pipeline de Trazabilidad
    trace_record = trace_pipeline.record_interaction(
        sanitized_query=evaluation.sanitized_query,
        answer_text=verified_answer,
        status_code=evaluation.status_code,
        guardrails_dict=guardrails_dict,
        sources=sources_out,
        engine_used=engine_used,
    )

    return {
        "answer": verified_answer,
        "status_code": evaluation.status_code,
        "guardrails": guardrails_dict,
        "sources": sources_out,
        "engine": engine_used,
        "trace_record": trace_record,
    }


class FiscalRAGRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return json.loads(raw)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        route = parsed.path

        if route == "/api/status":
            has_key = bool(RUNTIME_CONFIG.get("gemini_api_key", "").strip())
            integrity = trace_pipeline.verify_chain_integrity()
            self._send_json(
                {
                    "status": "online",
                    "drive_folder_id": DRIVE_FOLDER_ID,
                    "drive_folder_url": DRIVE_FOLDER_URL,
                    "manifest_files": rag_engine.drive_manifest,
                    "indexed_chunks_count": len(rag_engine.chunks),
                    "gemini_configured": has_key,
                    "gemini_model": RUNTIME_CONFIG.get("gemini_model", "gemini-2.5-flash"),
                    "min_retrieval_score": RUNTIME_CONFIG.get("min_retrieval_score", 0.18),
                    "out_of_scope_policy": OUT_OF_SCOPE_RESPONSE,
                    "jailbreak_policy": JAILBREAK_BLOCKED_RESPONSE,
                    "audit_events_count": integrity["total_records"],
                    "ledger_integrity": integrity,
                }
            )
            return

        if route in ("/api/audit-log", "/api/traceability"):
            records = trace_pipeline.get_records(limit=100)
            integrity = trace_pipeline.verify_chain_integrity()
            self._send_json({"records": records, "integrity": integrity})
            return

        if route == "/api/traceability/verify":
            self._send_json(trace_pipeline.verify_chain_integrity())
            return

        if route == "/api/traceability/export":
            content = LEDGER_PATH.read_bytes() if LEDGER_PATH.exists() else b""
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="audit_ledger_inmutable.jsonl"')
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # Servir archivos estáticos de la aplicación web
        if route == "/" or route == "/index.html":
            file_path = STATIC_DIR / "index.html"
        elif route.startswith("/static/"):
            rel = route[len("/static/") :]
            file_path = (STATIC_DIR / rel).resolve()
            if not str(file_path).startswith(str(STATIC_DIR.resolve())):
                self.send_error(403, "Forbidden")
                return
        else:
            file_path = (STATIC_DIR / route.lstrip("/")).resolve()
            if not str(file_path).startswith(str(STATIC_DIR.resolve())):
                self.send_error(404, "Not Found")
                return

        if not file_path.exists() or not file_path.is_file():
            self.send_error(404, "Archivo no encontrado")
            return

        mime_type, _ = mimetypes.guess_type(str(file_path))
        content = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{mime_type or 'text/plain'}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        route = parsed.path

        try:
            body = self._read_json_body()
        except Exception as e:
            self._send_json({"error": f"JSON inválido: {e}"}, status=400)
            return

        if route == "/api/chat":
            query = body.get("query", "")
            result = process_fiscal_query(query)
            self._send_json(result)
            return

        if route == "/api/config":
            if "gemini_api_key" in body:
                RUNTIME_CONFIG["gemini_api_key"] = str(body["gemini_api_key"]).strip()
            if "gemini_model" in body and body["gemini_model"]:
                RUNTIME_CONFIG["gemini_model"] = str(body["gemini_model"]).strip()
            if "min_retrieval_score" in body:
                try:
                    val = float(body["min_retrieval_score"])
                    RUNTIME_CONFIG["min_retrieval_score"] = max(0.05, min(0.85, val))
                except ValueError:
                    pass
            self._send_json(
                {
                    "ok": True,
                    "gemini_configured": bool(RUNTIME_CONFIG.get("gemini_api_key")),
                    "gemini_model": RUNTIME_CONFIG["gemini_model"],
                    "min_retrieval_score": RUNTIME_CONFIG["min_retrieval_score"],
                }
            )
            return

        if route == "/api/upload":
            filename = os.path.basename(body.get("filename", "")).strip()
            content_b64 = body.get("content_base64", "")
            if not filename or not content_b64:
                self._send_json({"error": "Nombre de archivo y contenido requeridos."}, status=400)
                return
            ext = Path(filename).suffix.lower()
            if ext not in (".docx", ".csv", ".txt", ".md"):
                self._send_json(
                    {"error": "Formato soportado para indexación directa: .docx, .csv, .txt, .md"},
                    status=400,
                )
                return
            raw_bytes = base64.b64decode(content_b64)
            dest = DATA_RAW_DIR / filename
            dest.write_bytes(raw_bytes)
            total_chunks = rag_engine.reload_corpus()
            self._send_json(
                {
                    "ok": True,
                    "filename": filename,
                    "indexed_chunks_count": total_chunks,
                }
            )
            return

        self._send_json({"error": "Ruta no encontrada"}, status=404)

    def log_message(self, format: str, *args: Any) -> None:
        return


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = HTTPServer((host, port), FiscalRAGRequestHandler)
    print(f"=======================================================================")
    print(f" Agente RAG Privado de Revisoría Fiscal (Gemini Cloud + Guardrails)")
    print(f" Carpeta Drive vinculada: {DRIVE_FOLDER_URL}")
    print(f" Fragmentos indexados   : {len(rag_engine.chunks)}")
    print(f" Ledger Inmutable       : {LEDGER_PATH}")
    print(f" Interfaz Web activa en : http://{host}:{port}")
    print(f"=======================================================================")
    server.serve_forever()


if __name__ == "__main__":
    port_env = int(os.environ.get("PORT", "8080"))
    run_server(port=port_env)
