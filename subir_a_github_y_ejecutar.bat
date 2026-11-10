@echo off
chcp 65001 >nul
cd /d "C:\Users\user\.gemini\antigravity\scratch\rag-revisoria-fiscal"
echo =====================================================================
echo  1. Subiendo proyecto a GitHub (icaro98007/FirmaConsultor-aRevisor-aFiscal-)
echo  (Si aparece la ventana de Git Credential Manager, inicia sesion con tu navegador)
echo =====================================================================
git push -u origin main

echo.
echo =====================================================================
echo  2. Iniciando Servidor Web en http://127.0.0.1:8080
echo =====================================================================
start "" "http://127.0.0.1:8080"
python app.py
pause
