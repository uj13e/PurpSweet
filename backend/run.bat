@echo off
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" run.py %*
  goto end
)

py -3.12 -c "import sys" >nul 2>&1
if not errorlevel 1 (
  py -3.12 run.py %*
  goto end
)

py -3.13 -c "import sys" >nul 2>&1
if not errorlevel 1 (
  py -3.13 run.py %*
  goto end
)

echo [!] Python 3.12 or 3.13 not found. Python 3.14 is not supported
echo     because zstandard/cffi have no 3.14 prebuilt wheels.
echo.
echo     Install: winget install -e --id Python.Python.3.12
echo     Deps:    py -3.12 -m pip install -r requirements.txt
echo     Run:     run.bat  (or: py -3.12 run.py)
exit /b 1

:end
