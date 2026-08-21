#ifndef BundleRoot
  #error BundleRoot is required
#endif
#ifndef OutputRoot
  #error OutputRoot is required
#endif
#ifndef DisplayVersion
  #error DisplayVersion is required
#endif
#ifndef FileVersion
  #error FileVersion is required
#endif
#ifndef SourceCommit
  #error SourceCommit is required
#endif
#ifndef BuiltAt
  #error BuiltAt is required
#endif

[Setup]
AppId={{7A76221A-CFA0-4860-B250-7083B736F3FB}
AppName=AgentGuardian
AppVersion={#DisplayVersion}
AppVerName=AgentGuardian {#DisplayVersion}
AppPublisher=AgentGuardian
AppComments=Source {#SourceCommit}; built {#BuiltAt}
VersionInfoVersion={#FileVersion}
VersionInfoDescription=AgentGuardian private beta {#SourceCommit} {#BuiltAt}
DefaultDirName={localappdata}\Programs\AgentGuardian
DefaultGroupName=AgentGuardian
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
SetupArchitecture=x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.22000
Uninstallable=yes
CreateUninstallRegKey=yes
UninstallDisplayName=AgentGuardian
UninstallDisplayIcon={app}\AgentGuardian.exe
OutputDir={#OutputRoot}
OutputBaseFilename=AgentGuardian-Setup-{#DisplayVersion}-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ChangesAssociations=no
ChangesEnvironment=no
CloseApplications=yes
CloseApplicationsFilter=AgentGuardian.exe
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#BundleRoot}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\AgentGuardian"; Filename: "{app}\AgentGuardian.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\AgentGuardian"; Filename: "{app}\AgentGuardian.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
