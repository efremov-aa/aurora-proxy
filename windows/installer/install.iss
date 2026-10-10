; Aurora Proxy - Inno Setup 7 installer for the Windows bundle
; SrcDir is passed on the command line:
;   ISCC.exe /DSrcDir=C:\path\to\dist\Aurora /DAuroraVersion=1.9.2 /DAuroraVersionName=Кот-глашатай install.iss

#ifndef SrcDir
  #define SrcDir "..\..\..\Temp\opencode\aurora_build\dist\Aurora"
#endif
#ifndef AuroraVersion
  #define AuroraVersion "1.10.7"
#endif
#ifndef AuroraVersionName
  #define AuroraVersionName "Кот-оберег"
#endif

[Setup]
AppId={{3C5F2A91-7E4D-4B88-9A6B-1D0E5F2B7A44}
AppName=Aurora Proxy
AppVersion={#AuroraVersion}
AppVerName=Aurora Proxy {#AuroraVersion} {#AuroraVersionName}
AppPublisher=efremov-aa
VersionInfoVersion={#AuroraVersion}
DefaultDirName={autopf}\Aurora
DefaultGroupName=Aurora Proxy
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\Aurora.exe
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
OutputDir=output
OutputBaseFilename=Aurora-Setup-{#AuroraVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
ShowLanguageDialog=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Files]
Source: "{#SrcDir}\Aurora.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\_internal\*"; DestDir: "{app}\_internal"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "TgWsProxy_windows.exe"
Source: "setup_service.cmd"; DestDir: "{app}"; Flags: ignoreversion

[Run]
Filename: "{app}\setup_service.cmd"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; StatusMsg: "Installing Aurora Windows service..."
; A-WARP-M-8: после старта службы открываем панель - там первым делом
; показываются ПРАВИЛА (политика, ревизия) и МАСТЕР настроек первого запуска.
; Пауза 12 c нужна, чтобы xray и панель успели подняться, иначе вкладка
; откроется до первого запроса и пользователь увидит пустую страницу.
Filename: "{sys}\cmd.exe"; Parameters: "/c ping -n 13 127.0.0.1 >nul & start "" ""http://127.0.0.1:8890"""; Flags: runhidden; StatusMsg: "Opening Aurora panel..."

[UninstallRun]
Filename: "{app}\_internal\nssm\nssm.exe"; Parameters: "stop Aurora"; Flags: runhidden; StatusMsg: "Stopping Aurora service..."
Filename: "{app}\_internal\nssm\nssm.exe"; Parameters: "remove Aurora confirm"; Flags: runhidden; StatusMsg: "Removing Aurora service..."