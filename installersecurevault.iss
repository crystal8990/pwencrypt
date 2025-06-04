; -- SecureVault Installer Script for Inno Setup --
; This script installs the SecureVault application into Program Files
; and creates a user data folder in the user's AppData.

[Setup]
; Application details:
AppName=SecureVault
AppVersion=1.0
AppPublisher=nun
AppPublisherURL=
AppSupportURL=
DefaultDirName={pf}\SecureVault
DefaultGroupName=SecureVault
DisableProgramGroupPage=yes

; Where to output the installer
OutputDir=Output
OutputBaseFilename=SecureVaultInstaller
Compression=lzma
SolidCompression=yes

; Ask for elevation to install in Program Files
PrivilegesRequired=admin

[Dirs]
; Create an additional directory for user data in APPDATA.
; This is where your storage module should write its dynamic files.
Name: "{userappdata}\SecureVault"; Flags: uninsalwaysuninstall

[Files]
; Copy the executable to the installation folder.
Source: "dist\main.exe"; DestDir: "{app}"; Flags: ignoreversion

; (If you have additional resource files or configuration defaults, list them here.)
; Example: Source: "config.ini"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Create a Start Menu shortcut.
Name: "{group}\SecureVault"; Filename: "{app}\main.exe"
; Create an optional desktop shortcut.
Name: "{userdesktop}\SecureVault"; Filename: "{app}\main.exe"; Tasks: desktopicon

[Tasks]
; Optional task to create a desktop icon.
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
; Optionally, offer to run the application immediately after installation.
Filename: "{app}\main.exe"; Description: "Launch SecureVault"; Flags: nowait postinstall skipifsilent