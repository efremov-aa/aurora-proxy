@echo off
setlocal EnableDelayedExpansion
rem Aurora Proxy - установка Windows-службы
rem Запускать от имени Администратора
cd /d "%~dp0"

set "ROOT=%~dp0.."
set "NSSM=%~dp0nssm.exe"

if not exist "%NSSM%" (
  echo [ОШИБКА] nssm.exe не найден в %~dp0
  pause
  exit /b 1
)

rem --- поиск pythonw.exe ---
set "PYW="
if exist "%ROOT%\venv\Scripts\pythonw.exe" set "PYW=%ROOT%\venv\Scripts\pythonw.exe"
if not defined PYW (
  for /f "delims=" %%i in ('where pythonw 2^>nul') do if not defined PYW set "PYW=%%i"
)
if not defined PYW (
  for /f "delims=" %%i in ('py -3 -c "import sys,os;print(os.path.join(os.path.dirname(sys.executable),'pythonw.exe'))" 2^>nul') do if not defined PYW set "PYW=%%i"
)
if not defined PYW (
  echo [ОШИБКА] pythonw.exe не найден. Установите Python 3.8+ и добавьте в PATH.
  pause
  exit /b 1
)

echo Python: %PYW%
echo Root:   %ROOT%

"%NSSM%" stop Aurora >nul 2>nul
"%NSSM%" remove Aurora confirm >nul 2>nul

"%NSSM%" install Aurora "%PYW%" "%ROOT%\run.py"
if errorlevel 1 (
  echo [ОШИБКА] не удалось создать службу Aurora.
  pause
  exit /b 1
)

"%NSSM%" set Aurora AppDirectory "%ROOT%"
"%NSSM%" set Aurora DisplayName "Aurora Proxy"
"%NSSM%" set Aurora Description "Прокси-сервер Aurora (VLESS Reality + TG WS). Панель :8890, xray :8899, api :8897, tg-ws :1443."
"%NSSM%" set Aurora Start SERVICE_AUTO_START
"%NSSM%" set Aurora AppStdout "%ROOT%\service.log"
"%NSSM%" set Aurora AppStderr "%ROOT%\service.log"
"%NSSM%" set Aurora AppRotateFiles 1
"%NSSM%" set Aurora AppRotateBytes 10485760
"%NSSM%" set Aurora AppExit Default Restart
"%NSSM%" set Aurora AppRestartDelay 3000

"%NSSM%" start Aurora

echo.
echo [OK] Служба Aurora установлена и запущена.
echo Панель: http://127.0.0.1:8890
echo Логи:   %ROOT%\service.log , %ROOT%\aurora.log
pause