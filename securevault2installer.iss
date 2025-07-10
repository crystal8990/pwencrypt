;–– setup.iss –– SecureVault2 installer

[Setup]
AppName=SecureVault2
AppVersion=1.0
DefaultDirName={pf}\SecureVault
DefaultGroupName=SecureVault
OutputBaseFilename=SecureVaultInstaller
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
SetupIconFile=vault_icon.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Dirs]
; Create per-user folder for OAuth token
Name: "{userappdata}\SecureVault2"; Flags: uninsneveruninstall

[Files]
; Main executable (contains embedded credentials.json)
Source: "dist\main.exe"; DestDir: "{app}"; Flags: ignoreversion
; (Optional) external icon
; Source: "vault_icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Shortcut in Start→Programs
[Icons]
Name: "{group}\SecureVault2"; Filename: "{app}\main.exe"; WorkingDir: "{app}"; IconFilename: "{app}\vault_icon.ico"
[Run]
; Offer to launch SecureVault2 immediately
Filename: "{app}\main.exe"; Description: "Launch SecureVault2" ;Flags: nowait postinstall skipifsilent