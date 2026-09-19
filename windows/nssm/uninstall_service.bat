@echo off
rem Aurora Proxy - удаление Windows-службы
rem Запускать от имени Администратора
set "NSSM=%~dp0nssm.exe"
if not exist "%NSSM%" (
  echo [ОШИБКА] nssm.exe не найден в %~dp0
  pause
  exit /b 1
)
"%NSSM%" stop Aurora
"%NSSM%" remove Aurora confirm
echo.
echo [OK] Служба Aurora удалена.
pause