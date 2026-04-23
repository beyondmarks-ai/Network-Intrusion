@echo off
setlocal

cd /d "%~dp0"

set PY_CMD=
where py >nul 2>nul
if %errorlevel%==0 set PY_CMD=py
if "%PY_CMD%"=="" (
  where python >nul 2>nul
  if %errorlevel%==0 set PY_CMD=python
)

if "%PY_CMD%"=="" (
  echo [ERROR] Python is not installed or not in PATH.
  echo Install Python 3.12+ and retry.
  pause
  exit /b 1
)

if not exist "venv\Scripts\python.exe" (
  echo [INFO] Virtual environment not found. Creating venv...
  if /I "%PY_CMD%"=="py" (
    py -3.12 -m venv venv
    if errorlevel 1 py -m venv venv
  ) else (
    python -m venv venv
  )
  if errorlevel 1 (
    echo [ERROR] Failed to create virtual environment.
    pause
    exit /b 1
  )

  echo [INFO] Installing dependencies...
  "venv\Scripts\python.exe" -m pip install --upgrade pip
  "venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 (
    echo [ERROR] Failed to install requirements.
    pause
    exit /b 1
  )
)

echo Running safe RNIDS traffic test...
echo.
echo Choose mode:
echo   0. mock (recommended for demo on this PC)
echo   1. normal
echo   2. stress
echo   3. scan-like
echo.
set /p MODE_CHOICE=Enter option [0-3, default 0]:

set MODE=mock
if "%MODE_CHOICE%"=="0" set MODE=mock
if "%MODE_CHOICE%"=="1" set MODE=normal
if "%MODE_CHOICE%"=="2" set MODE=stress
if "%MODE_CHOICE%"=="3" set MODE=scan-like

echo.
echo Target host (default 127.0.0.1):
set /p TARGET_HOST=
if "%TARGET_HOST%"=="" set TARGET_HOST=127.0.0.1

echo Target port (default 5000):
set /p TARGET_PORT=
if "%TARGET_PORT%"=="" set TARGET_PORT=5000

echo.
echo Starting safe_traffic_test.py with:
echo   mode=%MODE%
echo   host=%TARGET_HOST%
echo   port=%TARGET_PORT%
echo.

"venv\Scripts\python.exe" "safe_traffic_test.py" --mode "%MODE%" --host "%TARGET_HOST%" --port "%TARGET_PORT%"

echo.
echo Test finished. Press any key to close...
pause >nul
endlocal
