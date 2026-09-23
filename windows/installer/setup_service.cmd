@echo off
rem Aurora Proxy - установка Windows-службы (NSSM) поверх готового бандла Aurora.exe
rem Вызывается установщиком Inno Setup (runhidden) и при обновлении.
setlocal EnableDelayedExpansion

set "NSSM=%~dp0_internal\nssm\nssm.exe"
if not exist "%NSSM%" set "NSSM=%~dp0nssm\nssm.exe"
if not exist "%NSSM%" (
  echo [ERROR] nssm.exe not found
  exit /b 1
)

set "APP=%~dp0"
if "%APP:~-1%"=="\" set "APP=%APP:~0,-1%"

set "DATA=%LOCALAPPDATA%\Aurora"
if not exist "%DATA%" mkdir "%DATA%"

"%NSSM%" stop Aurora >nul 2>nul
"%NSSM%" remove Aurora confirm >nul 2>nul

"%NSSM%" install Aurora "%APP%\Aurora.exe"
if errorlevel 1 (
  echo [ERROR] failed to create Aurora service
  exit /b 1
)

"%NSSM%" set Aurora AppDirectory "%APP%"
"%NSSM%" set Aurora DisplayName "Aurora Proxy"
"%NSSM%" set Aurora Description "Aurora Proxy (VLESS Reality + TG WS). Panel :8890, xray :8899, api :8897, tg-ws :443."
"%NSSM%" set Aurora Start SERVICE_AUTO_START
"%NSSM%" set Aurora AppEnvironmentExtra AURORA_DATA_DIR=%DATA%
"%NSSM%" set Aurora AppStdout "%DATA%\service.log"
"%NSSM%" set Aurora AppStderr "%DATA%\service.log"
"%NSSM%" set Aurora AppRotateFiles 1
"%NSSM%" set Aurora AppRotateBytes 10485760
"%NSSM%" set Aurora AppExit Default Restart
"%NSSM%" set Aurora AppRestartDelay 3000

"%NSSM%" start Aurora

echo [OK] Aurora service installed.
exit /b 0