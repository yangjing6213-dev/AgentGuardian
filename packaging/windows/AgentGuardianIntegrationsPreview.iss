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
AppId={{A64DBF23-FE14-4E04-89AE-0924666A03DE}
AppName=AgentGuardian
AppVersion={#DisplayVersion}
AppVerName=AgentGuardian {#DisplayVersion}
AppPublisher=AgentGuardian
AppComments=Source {#SourceCommit}; built {#BuiltAt}
VersionInfoVersion={#FileVersion}
VersionInfoDescription=AgentGuardian integrations preview {#SourceCommit} {#BuiltAt}
DefaultDirName={localappdata}\Programs\AgentGuardian Integrations Preview
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
CloseApplications=no
RestartApplications=no

[Tasks]
Name: "codexskill"; Description: "Install AgentGuardian Codex Skill"; Flags: unchecked
Name: "codexmcp"; Description: "Enable AgentGuardian local MCP"; Flags: unchecked
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#BundleRoot}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\AgentGuardian"; Filename: "{app}\AgentGuardian.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\AgentGuardian"; Filename: "{app}\AgentGuardian.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{{A64DBF23-FE14-4E04-89AE-0924666A03DE}_is1"; ValueType: string; ValueName: "AgentGuardianFileVersion"; ValueData: "{#FileVersion}"; Flags: uninsdeletevalue

[Code]
const
  UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{A64DBF23-FE14-4E04-89AE-0924666A03DE}_is1';
  FileVersionValue = 'AgentGuardianFileVersion';
  PurgeStateParameter = '/PURGEAGENTGUARDIANSTATE';

function ReadInstalledFileVersion(var InstalledVersion: String): Boolean;
begin
  Result := RegQueryStringValue(HKCU, UninstallKey, FileVersionValue, InstalledVersion) and (InstalledVersion <> '');
end;

function SelectedTargets(): String;
begin
  Result := 'Selected categories:' + #13#10;
  if WizardIsTaskSelected('codexskill') then
    Result := Result + '- Codex Skill' + #13#10;
  if WizardIsTaskSelected('codexmcp') then
    Result := Result + '- local MCP' + #13#10;
  if WizardIsTaskSelected('desktopicon') then
    Result := Result + '- desktop shortcut' + #13#10;
  if (not WizardIsTaskSelected('codexskill')) and
     (not WizardIsTaskSelected('codexmcp')) and
     (not WizardIsTaskSelected('desktopicon')) then
    Result := Result + '- program only' + #13#10;
  Result := Result + #13#10 + 'Targets:' + #13#10 +
    '{userprofile}\.agents\skills\agentguardian' + #13#10 +
    '{userprofile}\.codex\config.toml' + #13#10 +
    '{localappdata}\AgentGuardian';
end;

function IntegrationArgument(): String;
begin
  Result := '';
  if WizardIsTaskSelected('codexskill') and WizardIsTaskSelected('codexmcp') then
    Result := '--install-codex-integration=skill,mcp'
  else if WizardIsTaskSelected('codexskill') then
    Result := '--install-codex-integration=skill'
  else if WizardIsTaskSelected('codexmcp') then
    Result := '--install-codex-integration=mcp';
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  InstalledVersion: String;
  InstalledPackedVersion: Int64;
  CandidatePackedVersion: Int64;
begin
  Result := '';
  NeedsRestart := False;
  if WizardDirValue <> ExpandConstant('{localappdata}\Programs\AgentGuardian Integrations Preview') then begin
    Result := 'AgentGuardian must be installed in the current-user preview directory.';
    exit;
  end;
  SuppressibleMsgBox(SelectedTargets(), mbInformation, MB_OK, IDOK);
  if not RegKeyExists(HKCU, UninstallKey) then
    exit;
  if (not ReadInstalledFileVersion(InstalledVersion)) or
     (not StrToVersion(InstalledVersion, InstalledPackedVersion)) or
     (not StrToVersion('{#FileVersion}', CandidatePackedVersion)) then begin
    Result := 'An existing preview installation has an unknown version.';
    exit;
  end;
  if ComparePackedVersion(CandidatePackedVersion, InstalledPackedVersion) < 0 then
    Result := 'A newer preview installation is already present.';
end;

procedure RunIntegrationHelperOrAbort();
var
  HelperArgument: String;
  ResultCode: Integer;
begin
  HelperArgument := IntegrationArgument();
  if HelperArgument = '' then
    exit;
  if (not Exec(ExpandConstant('{app}\AgentGuardian.exe'), HelperArgument, '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or
     (ResultCode <> 0) then
    RaiseException('AgentGuardian integration setup failed; no client was started.');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    if not RegWriteStringValue(HKCU, UninstallKey, FileVersionValue, '{#FileVersion}') then
      RaiseException('AgentGuardian installer version could not be recorded.');
    RunIntegrationHelperOrAbort();
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

procedure RemoveIntegrationOrAbort();
var
  ResultCode: Integer;
begin
  if (not FileExists(ExpandConstant('{app}\AgentGuardian.exe'))) then
    exit;
  if (not Exec(ExpandConstant('{app}\AgentGuardian.exe'), '--remove-codex-integration', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or
     (ResultCode <> 0) then begin
    SuppressibleMsgBox('AgentGuardian integration could not be removed. Uninstall was stopped.', mbError, MB_OK, IDOK);
    Abort;
  end;
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
  if CurUninstallStep = usUninstall then begin
    RemoveIntegrationOrAbort();
    if ShouldPurgeProtectedState() then
      PurgeProtectedStateOrAbort();
  end;
end;
