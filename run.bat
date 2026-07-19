@echo off
title AegisDFIR - Launching Forensic Assistant...
echo ===================================================================
echo               AegisDFIR Forensic Assistant Launcher
echo ===================================================================
echo.

python --version >nul 2>&1
if errorlevel 1 goto nopython

:: Check if the virtual environment exists and is healthy
if not exist .venv\Scripts\activate.bat goto run_global

:run_venv
echo [INFO] Healthy virtual environment found. Activating...
call .venv\Scripts\activate.bat
echo [INFO] Installing/updating project dependencies inside venv...
pip install -r requirements.txt
if errorlevel 1 goto pipfail_venv
goto run_app_venv

:pipfail_venv
echo [WARNING] Venv pip failed. Trying fallback to global environment...
goto run_global

:run_app_venv
echo [INFO] Launching default browser to http://127.0.0.1:8000 ...
start "" "http://127.0.0.1:8000"
echo [INFO] Starting FastAPI application server inside venv...
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
goto end

:run_global
echo [INFO] No healthy venv found (or venv activation failed). Running globally...
echo [INFO] Installing/updating project dependencies globally...
pip install -r requirements.txt
if errorlevel 1 goto pipfail_global

:run_app_global
echo [INFO] Launching default browser to http://127.0.0.1:8000 ...
start "" "http://127.0.0.1:8000"
echo [INFO] Starting FastAPI application server globally...
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
goto end

:pipfail_global
echo [WARNING] Global pip install failed. Installing packages individually...
pip install fastapi uvicorn pydantic
goto run_app_global

:nopython
echo [ERROR] Python is not installed or not added to your PATH.
echo Please install Python 3.8+ and try again.
pause
exit /b 1

:end
pause
