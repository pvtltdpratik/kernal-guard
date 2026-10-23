@echo off
rem Starts the KernelGuard API, collector and dashboard, each in its own window.
rem Close a window (or press Ctrl+C in it) to stop that process.
setlocal
set "ROOT=%~dp0"
set "PY=%ROOT%server\.venv\Scripts\python.exe"

if not exist "%PY%" (
    echo Python virtual environment not found at server\.venv
    echo Set it up first - see docs\operations.md
    pause
    exit /b 1
)

echo Applying database migrations...
pushd "%ROOT%server"
"%PY%" -m app.db.migrate
if errorlevel 1 (
    popd
    echo Migration failed; not starting.
    pause
    exit /b 1
)
popd

start "KernelGuard API" /D "%ROOT%server" cmd /k ""%PY%" -m app"
start "KernelGuard Collector" /D "%ROOT%server" cmd /k ""%PY%" -m app.collectors"
start "KernelGuard Dashboard" /D "%ROOT%client" cmd /k "npm run dev"

echo.
echo Started:
echo   API        http://127.0.0.1:8000  (docs at /docs)
echo   Dashboard  http://localhost:3000
echo   Collector  reading Sysmon, Security and System logs
endlocal
