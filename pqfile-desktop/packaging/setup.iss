; pqfile Windows Installer — Inno Setup 6
;
; Prerequisites:
;   1. Build the release binary first:
;        cargo build --release -p pqfile-desktop
;   2. Install Inno Setup 6: https://jrsoftware.org/isinfo.php
;   3. Compile:  iscc setup.iss
;      or open in Inno Setup IDE and press F9.
;
; Output: pqfile-desktop\packaging\output\pqfile-setup-{AppVersion}.exe

#define AppName      "pqfile"
#define AppVersion   "3.0.0"
#define AppPublisher "Derek"
#define AppExeName   "pqfile-desktop.exe"
#define BinPath      "..\..\target\release\" + AppExeName

[Setup]
; Generate a new GUID for your app at https://guidgenerator.com/
AppId={{F3A2B1C4-D5E6-4789-A0BC-1D2E3F405060}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
; Output location (relative to this .iss file)
OutputDir=output
OutputBaseFilename=pqfile-setup-{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
; Allow non-admin install; prompts for elevation if admin path chosen
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
; Hide the "Select Start Menu folder" page (keeps it simple)
DisableProgramGroupPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#BinPath}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent
