; pqfile Windows Installer — Inno Setup 6
;
; Prerequisites:
;   1. Build the release binary first:
;        cargo build --release -p pqfile-desktop
;   2. Install Inno Setup 6: https://jrsoftware.org/isinfo.php
;   3. Place assets\icon.ico next to this file (same folder as setup.iss)
;   4. Compile:  iscc setup.iss
;      or open in Inno Setup IDE and press F9.
;
; Output: pqfile-desktop\packaging\output\pqfile-setup-{AppVersion}.exe
;
; ── Optional code signing ────────────────────────────────────────────────────
; Uncomment the SignTool line below once you have a certificate.
; With SignPath Foundation (free for OSS): configure the tool path they provide.
; With a local PFX cert: signtool sign /fd SHA256 /f cert.pfx /p pass /tr http://timestamp.digicert.com /td SHA256 $f

#define AppName      "pqfile"
#define AppVersion   "4.2.3"
#define AppPublisher "Derek"
#define AppExeName   "pqfile-desktop.exe"
#define BinPath      "..\..\target\release\" + AppExeName
#define IconPath     "assets\icon.ico"

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
; App icon shown in the installer wizard pages and Add/Remove Programs
SetupIconFile={#IconPath}
UninstallDisplayIcon={app}\{#AppExeName}
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
; Uncomment to sign the installer itself after building:
;SignTool=signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 $f

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; signonce tells Inno Setup to sign the EXE before bundling it into the installer
Source: "{#BinPath}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent
