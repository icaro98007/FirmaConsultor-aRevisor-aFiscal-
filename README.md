# Agente RAG Privado de Revisoría Fiscal (Google Gemini Cloud + Guardarraíles Estrictos)

Prototipo funcional de un **Agente RAG Privado de Revisoría Fiscal** alimentado exclusivamente por los documentos de la carpeta de Google Drive (`https://drive.google.com/drive/folders/1tvvQu33y3-85cQHF6Q6ayUfFqYt_l0BZ?hl=es`):
- **Manuales Internos:** `01_Procedimientos_auditoria.docx`, `03_Control_interno_COSO_y_hallazgos.docx`, `04_Cumplimiento_SARLAFT_SAGRILAFT_ROS.docx`, `05_Indice_fuentes_y_metadatos.csv`.
- **Normas Internacionales de Auditoría (NIAs) y Aseguramiento:** `02_Guia_practica_NIA.docx`, `Decreto_2420_de_2015_Normas_de_contabilidad,_de_información_financiera_y_de_aseguramiento_de_información.pdf`.
- **Doctrina Societaria y Tributaria:** Circulares Externas de la Superintendencia de Sociedades (2020–2026) y **Estatuto Tributario Colombiano** (Art. 580, 581, 596, 602, 606, 641, 647, 659, 660, 772–777).

## Arquitectura de Guardarraíles de 4 Capas

1. **Capa 1 — Privacidad y DLP (Redacción PII):** Enmascara automáticamente NIT (`[NIT_REDACTADO]`), documentos de identidad (`[ID_REDACTADO]`), correos (`[EMAIL_REDACTADO]`), teléfonos y credenciales antes de enviar la consulta a la API Cloud Privada de Google Gemini o guardarla en el log de auditoría.
2. **Capa 2 — Escudo Anti-Jailbreak & Prompt Injection:** Detecta y bloquea intentos de ignorar instrucciones, cambiar de rol (`DAN`, modo desarrollador), extraer el *system prompt* o exfiltrar datos de otros usuarios.
3. **Capa 3 — Control de Alcance y Grounding Documental Estricto:** Evalúa la afinidad temática y el puntaje de recuperación híbrido (`BM25 + Coincidencia Normativa`). Si la pregunta no pertenece a la base de conocimiento o no supera el umbral de evidencia, responde obligatoriamente:
   > *"Soy un agente de Revisoría Fiscal alimentado exclusivamente por los manuales internos, las NIAs y el Estatuto Tributario de nuestra base de conocimiento privada. Este tema no se encuentra en mi base de conocimiento; por favor, investigue este tema en otro sitio."*
4. **Capa 4 — Verificación de Salida y Citas:** Garantiza que la respuesta de Gemini (`gemini-2.5-flash` con `temperature=0.0`) cite los documentos fuente (`[Fuente: ...]`) y nunca filtre datos sensibles.

## Ejecución Rápida

```powershell
cd C:\Users\user\.gemini\antigravity\scratch\rag-revisoria-fiscal
$env:GEMINI_API_KEY="TU_API_KEY_DE_GEMINI"
python app.py
```

Luego abre `http://127.0.0.1:8080` en tu navegador (también puedes configurar la `GEMINI_API_KEY` directamente desde el panel lateral de la aplicación web).
