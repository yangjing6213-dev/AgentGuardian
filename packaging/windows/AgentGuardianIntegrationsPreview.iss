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
SetupIconFile={#BundleRoot}\_internal\agentguardian\assets\agentguardian.ico
OutputDir={#OutputRoot}
OutputBaseFilename=AgentGuardian-Setup-{#DisplayVersion}-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ChangesAssociations=no
ChangesEnvironment=no
CloseApplications=no
RestartApplications=no
ShowLanguageDialog=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[CustomMessages]
english.PreviewNotice=AgentGuardian %1 Integrations Preview (unsigned).%nUse only personal non-regulated configuration data.%nWindows may show Unknown Publisher or SmartScreen warnings.%nReports and redacted results may be visible to the configured host.%n%nSelected categories:
chinesesimplified.PreviewNotice=AgentGuardian %1 集成预览版（未签名）。%n仅用于个人非受监管配置数据。%nWindows 可能显示“未知发布者”或 SmartScreen 警告。%n报告和脱敏结果可能会被已配置的主机看到。%n%n所选项目：
english.CodexSkill=Install AgentGuardian Codex Skill
chinesesimplified.CodexSkill=安装 AgentGuardian Codex 技能
english.LocalMcp=Enable AgentGuardian local MCP
chinesesimplified.LocalMcp=启用 AgentGuardian 本地 MCP
english.DesktopShortcut=Create a desktop shortcut
chinesesimplified.DesktopShortcut=创建桌面快捷方式
english.CodexSkillItem=- Codex Skill
chinesesimplified.CodexSkillItem=- Codex 技能
english.LocalMcpItem=- local MCP
chinesesimplified.LocalMcpItem=- 本地 MCP
english.DesktopShortcutItem=- desktop shortcut
chinesesimplified.DesktopShortcutItem=- 桌面快捷方式
english.ProgramOnlyItem=- program only
chinesesimplified.ProgramOnlyItem=- 仅安装程序
english.Targets=Targets:
chinesesimplified.Targets=安装位置：
english.InvalidTestRoot=AgentGuardian test installation root is invalid.
chinesesimplified.InvalidTestRoot=AgentGuardian 测试安装目录无效。
english.InvalidInstallRoot=AgentGuardian must be installed in the current-user preview directory.
chinesesimplified.InvalidInstallRoot=AgentGuardian 必须安装到当前用户的预览版目录。
english.UnknownExistingVersion=An existing preview installation has an unknown version.
chinesesimplified.UnknownExistingVersion=现有预览版的版本信息无法识别。
english.NewerPreviewPresent=A newer preview installation is already present.
chinesesimplified.NewerPreviewPresent=当前已安装更新版本的预览版。
english.IntegrationSetupFailed=AgentGuardian integration setup failed; no client was started.
chinesesimplified.IntegrationSetupFailed=AgentGuardian 集成设置失败；未启动任何客户端。
english.VersionRecordFailed=AgentGuardian installer version could not be recorded.
chinesesimplified.VersionRecordFailed=无法记录 AgentGuardian 安装版本。
english.PurgeStatePrompt=Delete AgentGuardian protected state?
chinesesimplified.PurgeStatePrompt=是否删除 AgentGuardian 受保护状态？
english.RemoveIntegrationFailed=AgentGuardian integration could not be removed. Uninstall was stopped.
chinesesimplified.RemoveIntegrationFailed=无法移除 AgentGuardian 集成，已停止卸载。
english.PurgeStateFailed=AgentGuardian protected state could not be removed. Uninstall was stopped.
chinesesimplified.PurgeStateFailed=无法删除 AgentGuardian 受保护状态，已停止卸载。

[Tasks]
Name: "codexskill"; Description: "{cm:CodexSkill}"; Flags: unchecked
Name: "codexmcp"; Description: "{cm:LocalMcp}"; Flags: unchecked
Name: "desktopicon"; Description: "{cm:DesktopShortcut}"; Flags: unchecked

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
  TestModeArgument = '/AGENTGUARDIAN_TEST_MODE';
  TestModeEnvironment = 'AGENTGUARDIAN_INNO_TEST_MODE';
  TestInstallRootEnvironment = 'AGENTGUARDIAN_INNO_TEST_INSTALL_ROOT';

function IsLifecycleTestMode(): Boolean;
var
  Index: Integer;
begin
  Result := GetEnv(TestModeEnvironment) = '1';
  if not Result then
    exit;
  Result := False;
  for Index := 1 to ParamCount do
    if CompareText(ParamStr(Index), TestModeArgument) = 0 then begin
      Result := True;
      exit;
    end;
end;

function TestInstallRootMatches(): Boolean;
var
  ExpectedRoot: String;
begin
  ExpectedRoot := GetEnv(TestInstallRootEnvironment);
  Result := IsLifecycleTestMode() and (ExpectedRoot <> '') and
    (CompareText(ExpandFileName(WizardDirValue), ExpandFileName(ExpectedRoot)) = 0);
end;

function ReadInstalledFileVersion(var InstalledVersion: String): Boolean;
begin
  Result := RegQueryStringValue(HKCU, UninstallKey, FileVersionValue, InstalledVersion) and (InstalledVersion <> '');
end;

function SelectedTargets(): String;
begin
  Result := FmtMessage(CustomMessage('PreviewNotice'), ['{#DisplayVersion}']) + #13#10;
  if WizardIsTaskSelected('codexskill') then
    Result := Result + CustomMessage('CodexSkillItem') + #13#10;
  if WizardIsTaskSelected('codexmcp') then
    Result := Result + CustomMessage('LocalMcpItem') + #13#10;
  if WizardIsTaskSelected('desktopicon') then
    Result := Result + CustomMessage('DesktopShortcutItem') + #13#10;
  if (not WizardIsTaskSelected('codexskill')) and
     (not WizardIsTaskSelected('codexmcp')) and
     (not WizardIsTaskSelected('desktopicon')) then
    Result := Result + CustomMessage('ProgramOnlyItem') + #13#10;
  Result := Result + #13#10 + CustomMessage('Targets') + #13#10 +
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
  if IsLifecycleTestMode() then begin
    if not TestInstallRootMatches() then begin
      Result := CustomMessage('InvalidTestRoot');
      exit;
    end;
  end else if WizardDirValue <> ExpandConstant('{localappdata}\Programs\AgentGuardian Integrations Preview') then begin
    Result := CustomMessage('InvalidInstallRoot');
    exit;
  end;
  SuppressibleMsgBox(SelectedTargets(), mbInformation, MB_OK, IDOK);
  if not RegKeyExists(HKCU, UninstallKey) then
    exit;
  if (not ReadInstalledFileVersion(InstalledVersion)) or
     (not StrToVersion(InstalledVersion, InstalledPackedVersion)) or
     (not StrToVersion('{#FileVersion}', CandidatePackedVersion)) then begin
    Result := CustomMessage('UnknownExistingVersion');
    exit;
  end;
  if ComparePackedVersion(CandidatePackedVersion, InstalledPackedVersion) < 0 then
    Result := CustomMessage('NewerPreviewPresent');
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
    RaiseException(CustomMessage('IntegrationSetupFailed'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    if not RegWriteStringValue(HKCU, UninstallKey, FileVersionValue, '{#FileVersion}') then
      RaiseException(CustomMessage('VersionRecordFailed'));
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
    Result := MsgBox(CustomMessage('PurgeStatePrompt'), mbConfirmation, MB_YESNO) = IDYES;
end;

procedure RemoveIntegrationOrAbort();
var
  ResultCode: Integer;
begin
  if (not FileExists(ExpandConstant('{app}\AgentGuardian.exe'))) then
    exit;
  if (not Exec(ExpandConstant('{app}\AgentGuardian.exe'), '--remove-codex-integration', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or
     (ResultCode <> 0) then begin
    SuppressibleMsgBox(CustomMessage('RemoveIntegrationFailed'), mbError, MB_OK, IDOK);
    Abort;
  end;
end;

procedure PurgeProtectedStateOrAbort();
var
  ResultCode: Integer;
begin
  if Exec(ExpandConstant('{app}\AgentGuardian.exe'), '--purge-protected-state', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
    exit;
  SuppressibleMsgBox(CustomMessage('PurgeStateFailed'), mbError, MB_OK, IDOK);
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
