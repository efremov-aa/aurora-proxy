; Aurora Proxy - Inno Setup 7 installer for the Windows bundle
; SrcDir is passed on the command line:
;   ISCC.exe /DSrcDir=C:\path\to\dist\Aurora install.iss

#ifndef SrcDir
  #define SrcDir "..\..\..\Temp\opencode\aurora_build\dist\Aurora"
#endif

[Setup]
AppId={{3C5F2A91-7E4D-4B88-9A6B-1D0E5F2B7A44}
AppName=Aurora Proxy
AppVersion=1.6.0
AppVerName=Aurora Proxy 1.6.0
AppPublisher=efremov-aa
VersionInfoVersion=1.6.0
DefaultDirName={autopf}\Aurora
DefaultGroupName=Aurora Proxy
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\Aurora.exe
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
OutputDir=output
OutputBaseFilename=Aurora-Setup-1.6.0
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

[UninstallRun]
Filename: "{app}\_internal\nssm\nssm.exe"; Parameters: "stop Aurora"; Flags: runhidden; StatusMsg: "Stopping Aurora service..."
Filename: "{app}\_internal\nssm\nssm.exe"; Parameters: "remove Aurora confirm"; Flags: runhidden; StatusMsg: "Removing Aurora service..."