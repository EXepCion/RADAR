; Inno Setup script for RADAR: installs for the current user only, no administrator rights.
; Built by packaging/build.ps1:  ISCC /DAppVersion=1.0.0 packaging\radar.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{57D5ACF4-9066-4DD4-993D-02728CD26DD8}
AppName=RADAR
AppVersion={#AppVersion}
AppVerName=RADAR {#AppVersion}
AppPublisher=The RADAR authors
AppPublisherURL=https://github.com/EXepCion/RADAR
AppSupportURL=https://github.com/EXepCion/RADAR/issues
AppComments=Risky Activity Data Analyzer and Reporter, for Microsoft Entra ID
VersionInfoVersion={#AppVersion}
VersionInfoDescription=RADAR setup
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\RADAR
DisableDirPage=yes
DefaultGroupName=RADAR
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=RADAR-{#AppVersion}-setup
SetupIconFile=build\radar.ico
UninstallDisplayIcon={app}\RADAR.exe
UninstallDisplayName=RADAR
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; RADAR holds this while it runs: the installer asks to close it before replacing files
AppMutex=Local\RADAR.instance
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart"; Description: "Start RADAR when I sign in to Windows"; GroupDescription: "Options:"

[Files]
Source: "..\dist\RADAR\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; an example of a check of your own, inactive until renamed (kept on uninstall like the rest of your data)
Source: "..\templates\example_plugin.py"; DestDir: "{localappdata}\RADAR\plugins"; DestName: "_example_plugin.py.txt"; Flags: onlyifdoesntexist uninsneveruninstall

[Icons]
Name: "{userprograms}\RADAR"; Filename: "{app}\RADAR.exe"; Comment: "Risky Activity Data Analyzer and Reporter, for Microsoft Entra ID"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "RADAR"; ValueData: """{app}\RADAR.exe"""; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{app}\RADAR.exe"; Description: "Start RADAR now"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Messages]
; Your settings, alerts and the sign-in history stay in %LOCALAPPDATA%\RADAR when RADAR is removed.
ConfirmUninstall=Remove RADAR from this PC?%n%nYour settings, alerts and the stored sign-in history in %LOCALAPPDATA%\RADAR are kept. Delete that folder yourself if you want them gone.
