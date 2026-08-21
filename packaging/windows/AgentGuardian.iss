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
DisableDirPage=yes
UsePreviousAppDir=no
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

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{{7A76221A-CFA0-4860-B250-7083B736F3FB}_is1"; ValueType: string; ValueName: "AgentGuardianFileVersion"; ValueData: "{#FileVersion}"; Flags: uninsdeletevalue

[Code]
const
  UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{7A76221A-CFA0-4860-B250-7083B736F3FB}_is1';
  FileVersionValue = 'AgentGuardianFileVersion';
  PurgeStateParameter = '/PURGEAGENTGUARDIANSTATE';

function ReadInstalledFileVersion(var InstalledVersion: String): Boolean;
begin
  Result := RegQueryStringValue(HKCU, UninstallKey, FileVersionValue, InstalledVersion) and (InstalledVersion <> '');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  InstalledVersion: String;
  InstalledPackedVersion: Int64;
  CandidatePackedVersion: Int64;
begin
  Result := '';
  if WizardDirValue <> ExpandConstant('{localappdata}\Programs\AgentGuardian') then begin
    Result := 'AgentGuardian must be installed in the current-user AgentGuardian program directory.';
    exit;
  end;

  if not RegKeyExists(HKCU, UninstallKey) then
    exit;

  if (not ReadInstalledFileVersion(InstalledVersion)) or
     (not StrToVersion(InstalledVersion, InstalledPackedVersion)) or
     (not StrToVersion('{#FileVersion}', CandidatePackedVersion)) then begin
    Result := 'An existing AgentGuardian installation has an unknown version. Uninstall it before continuing.';
    exit;
  end;

  if ComparePackedVersion(CandidatePackedVersion, InstalledPackedVersion) < 0 then begin
    Result := 'A newer AgentGuardian version is already installed. Uninstall it before installing an older version.';
  end;
end;

function HasPurgeStateParameter(): Boolean;
var
  Index: Integer;
begin
  Result := False;
  for Index := 1 to ParamCount do
    if CompareText(ParamStr(Index), PurgeStateParameter) = 0 then begin
      Result := True;
      exit;
    end;
end;

function ShouldPurgeProtectedState(): Boolean;
begin
  if UninstallSilent then begin
    Result := HasPurgeStateParameter();
    exit;
  end;
  Result := MsgBox('Delete AgentGuardian protected state?', mbConfirmation, MB_YESNO) = IDYES;
end;

procedure PurgeProtectedStateOrAbort();
var
  ResultCode: Integer;
begin
  if Exec(ExpandConstant('{app}\AgentGuardian.exe'), '--purge-protected-state', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
    exit;
  SuppressibleMsgBox('AgentGuardian protected state could not be removed. Uninstall was stopped.', mbError, MB_OK, IDOK);
  Abort;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usUninstall) and ShouldPurgeProtectedState() then
    PurgeProtectedStateOrAbort();
end;
