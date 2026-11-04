; Inno Setup script for Interlace.
; Build with: iscc installer\interlace.iss   (requires Inno Setup 6+, https://jrsoftware.org/isdl.php)
; Produces: installer\Output\interlace-setup-0.1.0.exe
;
; The installed app stores its data (captured traffic, CA, findings, scope) in
; %LOCALAPPDATA%\Interlace so it works from Program Files without admin rights.

#define AppName "Interlace"
#define AppVersion "0.1.0"
#define AppPublisher "Interlace"

[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\interlace.exe
OutputDir=Output
OutputBaseFilename=interlace-setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "..\release\interlace.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\release\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\release\plugins-example\*"; DestDir: "{app}\plugins-example"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{localappdata}\Interlace"

[Icons]
Name: "{group}\Interlace"; Filename: "{app}\interlace.exe"; Parameters: "-data ""{localappdata}\Interlace"""; WorkingDir: "{localappdata}\Interlace"
Name: "{group}\Uninstall Interlace"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Interlace"; Filename: "{app}\interlace.exe"; Parameters: "-data ""{localappdata}\Interlace"""; WorkingDir: "{localappdata}\Interlace"; Tasks: desktopicon

[Run]
Filename: "{app}\interlace.exe"; Parameters: "-data ""{localappdata}\Interlace"""; WorkingDir: "{localappdata}\Interlace"; Description: "Launch Interlace now"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\Interlace"
