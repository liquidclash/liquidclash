Unicode true
ManifestDPIAware true
; Add in `dpiAwareness` `PerMonitorV2` to manifest for Windows 10 1607+ (note this should not affect lower versions since they should be able to ignore this and pick up `dpiAware` `true` set by `ManifestDPIAware true`)
; Currently undocumented on NSIS's website but is in the Docs folder of source tree, see
; https://github.com/kichik/nsis/blob/5fc0b87b819a9eec006df4967d08e522ddd651c9/Docs/src/attributes.but#L286-L300
; https://github.com/tauri-apps/tauri/pull/10106
ManifestDPIAwareness PerMonitorV2

!if "{{compression}}" == "none"
  SetCompress off
!else
  ; Set the compression algorithm. We default to LZMA.
  SetCompressor /SOLID "{{compression}}"
!endif

!include MUI2.nsh
!include FileFunc.nsh
!include x64.nsh
!include WordFunc.nsh
!include "utils.nsh"
!include "FileAssociation.nsh"
!include "Win\COM.nsh"
!include "Win\Propkey.nsh"
!include "WinVer.nsh"
!include "LogicLib.nsh"
!include "StrFunc.nsh"
${StrCase}
${StrLoc}

!addplugindir "$%AppData%\Local\NSIS\"

{{#if installer_hooks}}
!include "{{installer_hooks}}"
{{/if}}

!define WEBVIEW2APPGUID "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

!define MANUFACTURER "{{manufacturer}}"
!define PRODUCTNAME "{{product_name}}"
!define VERSION "{{version}}"
!define VERSIONWITHBUILD "{{version_with_build}}"
!define SHORTDESCRIPTION "{{short_description}}"
!define HOMEPAGE "{{homepage}}"
!define INSTALLMODE "{{install_mode}}"
!define LICENSE "{{license}}"
!define INSTALLERICON "{{installer_icon}}"
!define SIDEBARIMAGE "{{sidebar_image}}"
!define HEADERIMAGE "{{header_image}}"
!define MAINBINARYNAME "{{main_binary_name}}"
!define MAINBINARYSRCPATH "{{main_binary_path}}"
!define BUNDLEID "{{bundle_id}}"
!define COPYRIGHT "{{copyright}}"
!define OUTFILE "{{out_file}}"
!define ARCH "{{arch}}"
!define ADDITIONALPLUGINSPATH "{{additional_plugins_path}}"
!define ALLOWDOWNGRADES "{{allow_downgrades}}"
!define DISPLAYLANGUAGESELECTOR "{{display_language_selector}}"
!define INSTALLWEBVIEW2MODE "{{install_webview2_mode}}"
!define WEBVIEW2INSTALLERARGS "{{webview2_installer_args}}"
!define WEBVIEW2BOOTSTRAPPERPATH "{{webview2_bootstrapper_path}}"
!define WEBVIEW2INSTALLERPATH "{{webview2_installer_path}}"
!define MINIMUMWEBVIEW2VERSION "{{minimum_webview2_version}}"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCTNAME}"
!define MANUKEY "Software\${MANUFACTURER}"
!define MANUPRODUCTKEY "${MANUKEY}\${PRODUCTNAME}"
!define UNINSTALLERSIGNCOMMAND "{{uninstaller_sign_cmd}}"
!define ESTIMATEDSIZE "{{estimated_size}}"
!define STARTMENUFOLDER "{{start_menu_folder}}"
; One name for the emergency-disarm shortcut so creation and removal can never drift apart. The
; wording matches what `service.rs` tells the user to right-click when the disarm is refused.
!define RESTORENETWORKLINK "${PRODUCTNAME} — 恢复网络 (Restore Network).lnk"

Var PassiveMode
Var UpdateMode
Var NoShortcutMode
Var WixMode
Var OldMainBinaryName
Var VC_REDIST_URL
Var VC_REDIST_EXE
Var VC_RUNTIME_READY
Var VC_RUNTIME_NEEDED
; Set once this run has handed control to the Service installer, so `.onInstFailed` only tears
; down a registration this install could have created and never an unrelated healthy Service.
Var ServiceInstallAttempted
Var ServiceInstallRetries

Name "${PRODUCTNAME}"
BrandingText "${COPYRIGHT}"
OutFile "${OUTFILE}"

; We don't actually use this value as default install path,
; it's just for nsis to append the product name folder in the directory selector
; https://nsis.sourceforge.io/Reference/InstallDir
!define PLACEHOLDER_INSTALL_DIR "placeholder\${PRODUCTNAME}"
InstallDir "${PLACEHOLDER_INSTALL_DIR}"

VIProductVersion "${VERSIONWITHBUILD}"
VIAddVersionKey "ProductName" "${PRODUCTNAME}"
VIAddVersionKey "FileDescription" "${SHORTDESCRIPTION}"
VIAddVersionKey "LegalCopyright" "${COPYRIGHT}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"

# additional plugins
!if "${ADDITIONALPLUGINSPATH}" != ""
  !addplugindir "${ADDITIONALPLUGINSPATH}"
!endif

; Uninstaller signing command
!if "${UNINSTALLERSIGNCOMMAND}" != ""
  !uninstfinalize '${UNINSTALLERSIGNCOMMAND}'
!endif

; Handle install mode, `perUser`, `perMachine` or `both`
!if "${INSTALLMODE}" == "perMachine"
  RequestExecutionLevel admin
!endif

!if "${INSTALLMODE}" == "currentUser"
  RequestExecutionLevel user
!endif

!if "${INSTALLMODE}" == "both"
  !define MULTIUSER_MUI
  !define MULTIUSER_INSTALLMODE_INSTDIR "${PRODUCTNAME}"
  !define MULTIUSER_INSTALLMODE_COMMANDLINE
  !if "${ARCH}" == "x64"
    !define MULTIUSER_USE_PROGRAMFILES64
  !else if "${ARCH}" == "arm64"
    !define MULTIUSER_USE_PROGRAMFILES64
  !endif
  !define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_KEY "${UNINSTKEY}"
  !define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_VALUENAME "CurrentUser"
  !define MULTIUSER_INSTALLMODEPAGE_SHOWUSERNAME
  !define MULTIUSER_INSTALLMODE_FUNCTION RestorePreviousInstallLocation
  !define MULTIUSER_EXECUTIONLEVEL Highest
  !include MultiUser.nsh
!endif

; Installer icon
!if "${INSTALLERICON}" != ""
  !define MUI_ICON "${INSTALLERICON}"
  !define MUI_UNICON "${INSTALLERICON}"
!endif

; Installer sidebar image
!if "${SIDEBARIMAGE}" != ""
  !define MUI_WELCOMEFINISHPAGE_BITMAP "${SIDEBARIMAGE}"
!endif

; Installer header image
!if "${HEADERIMAGE}" != ""
  !define MUI_HEADERIMAGE
  !define MUI_HEADERIMAGE_BITMAP  "${HEADERIMAGE}"
!endif

; Define registry key to store installer language
!define MUI_LANGDLL_REGISTRY_ROOT "HKCU"
!define MUI_LANGDLL_REGISTRY_KEY "${MANUPRODUCTKEY}"
!define MUI_LANGDLL_REGISTRY_VALUENAME "Installer Language"

; Installer pages, must be ordered as they appear
; 1. Welcome Page
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
!insertmacro MUI_PAGE_WELCOME

; 2. License Page (if defined)
!if "${LICENSE}" != ""
  !define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
  !insertmacro MUI_PAGE_LICENSE "${LICENSE}"
!endif

; 3. Install mode (if it is set to `both`)
!if "${INSTALLMODE}" == "both"
  !define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
  !insertmacro MULTIUSER_PAGE_INSTALLMODE
!endif

; 4. Custom page to ask user if he wants to reinstall/uninstall
;    only if a previous installation was detected
Var ReinstallPageCheck
Page custom PageReinstall PageLeaveReinstall
Function PageReinstall
  ; Uninstall previous WiX installation if exists.
  ;
  ; A WiX installer stores the installation info in registry
  ; using a UUID and so we have to loop through all keys under
  ; `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
  ; and check if `DisplayName` and `Publisher` keys match ${PRODUCTNAME} and ${MANUFACTURER}
  ;
  ; This has a potential issue that there maybe another installation that matches
  ; our ${PRODUCTNAME} and ${MANUFACTURER} but wasn't installed by our WiX installer,
  ; however, this should be fine since the user will have to confirm the uninstallation
  ; and they can chose to abort it if doesn't make sense.
  StrCpy $0 0
  wix_loop:
    EnumRegKey $1 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" $0
    StrCmp $1 "" wix_loop_done ; Exit loop if there is no more keys to loop on
    IntOp $0 $0 + 1
    ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$1" "DisplayName"
    ReadRegStr $R1 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$1" "Publisher"
    StrCmp "$R0$R1" "${PRODUCTNAME}${MANUFACTURER}" 0 wix_loop
    ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$1" "UninstallString"
    ${StrCase} $R1 $R0 "L"
    ${StrLoc} $R0 $R1 "msiexec" ">"
    StrCmp $R0 0 0 wix_loop_done
    StrCpy $WixMode 1
    StrCpy $R6 "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$1"
    Goto compare_version
  wix_loop_done:

  ; Check if there is an existing installation, if not, abort the reinstall page
  ReadRegStr $R0 SHCTX "${UNINSTKEY}" ""
  ReadRegStr $R1 SHCTX "${UNINSTKEY}" "UninstallString"
  ${IfThen} "$R0$R1" == "" ${|} Abort ${|}

  ; Compare this installar version with the existing installation
  ; and modify the messages presented to the user accordingly
  compare_version:
  StrCpy $R4 "$(older)"
  ${If} $WixMode = 1
    ReadRegStr $R0 HKLM "$R6" "DisplayVersion"
  ${Else}
    ReadRegStr $R0 SHCTX "${UNINSTKEY}" "DisplayVersion"
  ${EndIf}
  ${IfThen} $R0 == "" ${|} StrCpy $R4 "$(unknown)" ${|}

  nsis_tauri_utils::SemverCompare "${VERSION}" $R0
  Pop $R0
  ; Reinstalling the same version
  ${If} $R0 = 0
    StrCpy $R1 "$(alreadyInstalledLong)"
    StrCpy $R2 "$(addOrReinstall)"
    StrCpy $R3 "$(uninstallApp)"
    !insertmacro MUI_HEADER_TEXT "$(alreadyInstalled)" "$(chooseMaintenanceOption)"
  ; Upgrading
  ${ElseIf} $R0 = 1
    StrCpy $R1 "$(olderOrUnknownVersionInstalled)"
    StrCpy $R2 "$(uninstallBeforeInstalling)"
    StrCpy $R3 "$(dontUninstall)"
    !insertmacro MUI_HEADER_TEXT "$(alreadyInstalled)" "$(choowHowToInstall)"
  ; Downgrading
  ${ElseIf} $R0 = -1
    StrCpy $R1 "$(newerVersionInstalled)"
    StrCpy $R2 "$(uninstallBeforeInstalling)"
    !if "${ALLOWDOWNGRADES}" == "true"
      StrCpy $R3 "$(dontUninstall)"
    !else
      StrCpy $R3 "$(dontUninstallDowngrade)"
    !endif
    !insertmacro MUI_HEADER_TEXT "$(alreadyInstalled)" "$(choowHowToInstall)"
  ${Else}
    Abort
  ${EndIf}

  ; Skip showing the page if passive
  ;
  ; Note that we don't call this earlier at the begining
  ; of this function because we need to populate some variables
  ; related to current installed version if detected and whether
  ; we are downgrading or not.
  ${If} $PassiveMode = 1
    Call PageLeaveReinstall
  ${Else}
    nsDialogs::Create 1018
    Pop $R4
    ${IfThen} $(^RTL) = 1 ${|} nsDialogs::SetRTL $(^RTL) ${|}

    ${NSD_CreateLabel} 0 0 100% 24u $R1
    Pop $R1

    ${NSD_CreateRadioButton} 30u 50u -30u 8u $R2
    Pop $R2
    ${NSD_OnClick} $R2 PageReinstallUpdateSelection

    ${NSD_CreateRadioButton} 30u 70u -30u 8u $R3
    Pop $R3
    ; Disable this radio button if downgrading and downgrades are disabled
    !if "${ALLOWDOWNGRADES}" == "false"
      ${IfThen} $R0 = -1 ${|} EnableWindow $R3 0 ${|}
    !endif
    ${NSD_OnClick} $R3 PageReinstallUpdateSelection

    ; Check the first radio button if this the first time
    ; we enter this page or if the second button wasn't
    ; selected the last time we were on this page
    ${If} $ReinstallPageCheck <> 2
      SendMessage $R2 ${BM_SETCHECK} ${BST_CHECKED} 0
    ${Else}
      SendMessage $R3 ${BM_SETCHECK} ${BST_CHECKED} 0
    ${EndIf}

    ${NSD_SetFocus} $R2
    nsDialogs::Show
  ${EndIf}
FunctionEnd
Function PageReinstallUpdateSelection
  ${NSD_GetState} $R2 $R1
  ${If} $R1 == ${BST_CHECKED}
    StrCpy $ReinstallPageCheck 1
  ${Else}
    StrCpy $ReinstallPageCheck 2
  ${EndIf}
FunctionEnd
Function PageLeaveReinstall
  ${NSD_GetState} $R2 $R1

  ; If migrating from Wix, always uninstall
  ${If} $WixMode = 1
    Goto reinst_uninstall
  ${EndIf}

  ; In update mode, always proceeds without uninstalling
  ${If} $UpdateMode = 1
    Goto reinst_done
  ${EndIf}

  ; $R0 holds whether same(0)/upgrading(1)/downgrading(-1) version
  ; $R1 holds the radio buttons state:
  ;   1 => first choice was selected
  ;   0 => second choice was selected
  ${If} $R0 = 0 ; Same version, proceed
    ${If} $R1 = 1              ; User chose to add/reinstall
      Goto reinst_done
    ${Else}                    ; User chose to uninstall
      Goto reinst_uninstall
    ${EndIf}
  ${ElseIf} $R0 = 1 ; Upgrading
    ${If} $R1 = 1              ; User chose to uninstall
      Goto reinst_uninstall
    ${Else}
      Goto reinst_done         ; User chose NOT to uninstall
    ${EndIf}
  ${ElseIf} $R0 = -1 ; Downgrading
    ${If} $R1 = 1              ; User chose to uninstall
      Goto reinst_uninstall
    ${Else}
      Goto reinst_done         ; User chose NOT to uninstall
    ${EndIf}
  ${EndIf}

  reinst_uninstall:
    HideWindow
    ClearErrors

    ${If} $WixMode = 1
      ReadRegStr $R1 HKLM "$R6" "UninstallString"
      ExecWait '$R1' $0
    ${Else}
      ReadRegStr $4 SHCTX "${MANUPRODUCTKEY}" ""
      ReadRegStr $R1 SHCTX "${UNINSTKEY}" "UninstallString"
      ${IfThen} $UpdateMode = 1 ${|} StrCpy $R1 "$R1 /UPDATE" ${|} ; append /UPDATE
      ${IfThen} $PassiveMode = 1 ${|} StrCpy $R1 "$R1 /P" ${|} ; append /P
      StrCpy $R1 "$R1 _?=$4" ; append uninstall directory
      ExecWait '$R1' $0
    ${EndIf}

    BringToFront

    ${IfThen} ${Errors} ${|} StrCpy $0 2 ${|} ; ExecWait failed, set fake exit code

    ${If} $0 <> 0
    ${OrIf} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
      ; User cancelled wix uninstaller? return to select un/reinstall page
      ${If} $WixMode = 1
      ${AndIf} $0 = 1602
        Abort
      ${EndIf}

      ; User cancelled NSIS uninstaller? return to select un/reinstall page
      ${If} $0 = 1
        Abort
      ${EndIf}

      ; Other erros? show generic error message and return to select un/reinstall page
      MessageBox MB_ICONEXCLAMATION "$(unableToUninstall)"
      Abort
    ${EndIf}
  reinst_done:
FunctionEnd

; 5. Start menu shortcut page. Tono's privileged core allowlist requires the per-machine
; Program Files location selected in .onInit, so do not offer an unsupported custom directory.
Var AppStartMenuFolder
!if "${STARTMENUFOLDER}" != ""
  !define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
  !define MUI_STARTMENUPAGE_DEFAULTFOLDER "${STARTMENUFOLDER}"
!else
  !define MUI_PAGE_CUSTOMFUNCTION_PRE Skip
!endif
!insertmacro MUI_PAGE_STARTMENU Application $AppStartMenuFolder

; 6. Installation page
!insertmacro MUI_PAGE_INSTFILES

; 7. Finish page
;
; Don't auto jump to finish page after installation page,
; because the installation page has useful info that can be used debug any issues with the installer.
!define MUI_FINISHPAGE_NOAUTOCLOSE
; Use show readme button in the finish page as a button create a desktop shortcut
!define MUI_FINISHPAGE_SHOWREADME
!define MUI_FINISHPAGE_SHOWREADME_TEXT "$(createDesktop)"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION CreateOrUpdateDesktopShortcut
; Show run app after installation.
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION RunMainBinary
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
!insertmacro MUI_PAGE_FINISH

Function RunMainBinary
  IfRebootFlag skipRunMainBinary runMainBinaryNow
  skipRunMainBinary:
    DetailPrint "A reboot is required before ${PRODUCTNAME} can start with the updated Service."
    Return
  runMainBinaryNow:
  nsis_tauri_utils::RunAsUser "$INSTDIR\${MAINBINARYNAME}.exe" ""
FunctionEnd

; Uninstaller Pages
; 1. Confirm uninstall page
Var DeleteAppDataCheckbox
Var DeleteAppDataCheckboxState
!define /ifndef WS_EX_LAYOUTRTL         0x00400000
!define MUI_PAGE_CUSTOMFUNCTION_SHOW un.ConfirmShow
Function un.ConfirmShow ; Add add a `Delete app data` check box
  ; $1 inner dialog HWND
  ; $2 window DPI
  ; $3 style
  ; $4 x
  ; $5 y
  ; $6 width
  ; $7 height
  FindWindow $1 "#32770" "" $HWNDPARENT ; Find inner dialog
  System::Call "user32::GetDpiForWindow(p r1) i .r2"
  ${If} $(^RTL) = 1
    StrCpy $3 "${__NSD_CheckBox_EXSTYLE} | ${WS_EX_LAYOUTRTL}"
    IntOp $4 50 * $2
  ${Else}
    StrCpy $3 "${__NSD_CheckBox_EXSTYLE}"
    IntOp $4 0 * $2
  ${EndIf}
  IntOp $5 100 * $2
  IntOp $6 400 * $2
  IntOp $7 25 * $2
  IntOp $4 $4 / 96
  IntOp $5 $5 / 96
  IntOp $6 $6 / 96
  IntOp $7 $7 / 96
  System::Call 'user32::CreateWindowEx(i r3, w "${__NSD_CheckBox_CLASS}", w "$(deleteAppData)", i ${__NSD_CheckBox_STYLE}, i r4, i r5, i r6, i r7, p r1, i0, i0, i0) i .s'
  Pop $DeleteAppDataCheckbox
  SendMessage $HWNDPARENT ${WM_GETFONT} 0 0 $1
  SendMessage $DeleteAppDataCheckbox ${WM_SETFONT} $1 1
FunctionEnd
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE un.ConfirmLeave
Function un.ConfirmLeave
  SendMessage $DeleteAppDataCheckbox ${BM_GETCHECK} 0 0 $DeleteAppDataCheckboxState
FunctionEnd
!define MUI_PAGE_CUSTOMFUNCTION_PRE un.SkipIfPassive
!insertmacro MUI_UNPAGE_CONFIRM

; 2. Uninstalling Page
!insertmacro MUI_UNPAGE_INSTFILES

;Languages
{{#each languages}}
!insertmacro MUI_LANGUAGE "{{this}}"
{{/each}}
!insertmacro MUI_RESERVEFILE_LANGDLL
{{#each language_files}}
  !include "{{this}}"
{{/each}}

LangString legacyLocationAbort ${LANG_SIMPCHINESE} "检测到 ${PRODUCTNAME} 安装在不受支持的位置：$4$\r$\n$\r$\n此版本必须安装在 Program Files 中。请先卸载现有版本（不要勾选删除应用数据），然后重新运行此安装程序。"
LangString legacyLocationAbort ${LANG_ENGLISH} "${PRODUCTNAME} is installed in an unsupported location: $4$\r$\n$\r$\nThis version must be installed under Program Files. Uninstall the existing version first (do not select Delete application data), then run this installer again."
LangString legacyLocationAbort ${LANG_RUSSIAN} "${PRODUCTNAME} установлен в неподдерживаемой папке: $4$\r$\n$\r$\nЭта версия должна быть установлена в Program Files. Сначала удалите текущую версию (не выбирайте удаление данных приложения), затем снова запустите этот установщик."

LangString restoreNetworkTooltip ${LANG_SIMPCHINESE} "当 ${PRODUCTNAME} 无法恢复网络时，解除网络保护（需要管理员权限）。"
LangString restoreNetworkTooltip ${LANG_ENGLISH} "Restores your network if ${PRODUCTNAME} cannot. Requires administrator approval."
LangString restoreNetworkTooltip ${LANG_RUSSIAN} "Восстанавливает сеть, если ${PRODUCTNAME} не может. Требуются права администратора."

Function .onInit
  ${GetOptions} $CMDLINE "/P" $PassiveMode
  ${IfNot} ${Errors}
    StrCpy $PassiveMode 1
  ${EndIf}

  ${GetOptions} $CMDLINE "/NS" $NoShortcutMode
  ${IfNot} ${Errors}
    StrCpy $NoShortcutMode 1
  ${EndIf}

  ${GetOptions} $CMDLINE "/UPDATE" $UpdateMode
  ${IfNot} ${Errors}
    StrCpy $UpdateMode 1
  ${EndIf}

  !if "${DISPLAYLANGUAGESELECTOR}" == "true"
    ; Auto-update forwards the app's UI language as `/LANG=<NSIS-lang-id>` so
    ; the installer uses it directly and skips the interactive language
    ; selector, letting the update start without prompting the user.
    ; See `src-tauri/src/core/updater.rs` (`nsis_language_id`).
    ${GetOptions} $CMDLINE "/LANG=" $0
    ${IfNot} ${Errors}
      ${If} $0 == "1033"
      ${OrIf} $0 == "1049"
      ${OrIf} $0 == "2052"
        StrCpy $LANGUAGE $0
      ${Else}
        !insertmacro MUI_LANGDLL_DISPLAY
      ${EndIf}
    ${Else}
      !insertmacro MUI_LANGDLL_DISPLAY
    ${EndIf}
  !endif

  !insertmacro SetContext

  !if "${INSTALLMODE}" == "perMachine"
    ; The privileged Service only trusts its core under Program Files. Force the supported
    ; location even when /D= is passed, which bypasses NSIS's directory page handling.
    ${If} ${RunningX64}
      !if "${ARCH}" == "x64"
        StrCpy $INSTDIR "$PROGRAMFILES64\${PRODUCTNAME}"
      !else if "${ARCH}" == "arm64"
        StrCpy $INSTDIR "$PROGRAMFILES64\${PRODUCTNAME}"
      !else
        StrCpy $INSTDIR "$PROGRAMFILES\${PRODUCTNAME}"
      !endif
    ${Else}
      StrCpy $INSTDIR "$PROGRAMFILES\${PRODUCTNAME}"
    ${EndIf}

    ; Refuse to layer a second copy over a legacy custom-location install. Automatic migration
    ; would leave its shortcuts and scheduled-task autostart pointing at the old executable.
    ReadRegStr $4 SHCTX "${MANUPRODUCTKEY}" ""
    ${If} $4 != ""
    ${AndIf} $4 != $INSTDIR
      ${IfNot} ${Silent}
        MessageBox MB_ICONSTOP "$(legacyLocationAbort)"
      ${EndIf}
      SetErrorLevel 5
      Abort
    ${EndIf}
  !else
    ${If} $INSTDIR == "${PLACEHOLDER_INSTALL_DIR}"
      !if "${INSTALLMODE}" == "currentUser"
        StrCpy $INSTDIR "$LOCALAPPDATA\${PRODUCTNAME}"
      !endif
      Call RestorePreviousInstallLocation
    ${EndIf}
  !endif


  !if "${INSTALLMODE}" == "both"
    !insertmacro MULTIUSER_INIT
  !endif
FunctionEnd


Function CheckVCRuntime64
  Push $R0
  Push $R1
  StrCpy $VC_RUNTIME_READY "0"
  ; A 32-bit installer only reaches the native system directory through the Sysnative alias;
  ; where that alias does not exist, System32 already is the native one. Use labels: the former
  ; `+3` counted onto `Goto found` and both declared the runtime present without probing it and
  ; made the System32 fallback unreachable.
  StrCpy $R1 "$WINDIR\Sysnative"
  IfFileExists "$R1\kernel32.dll" probe 0
  StrCpy $R1 "$WINDIR\System32"
  probe:
  IfFileExists "$R1\vcruntime140.dll" 0 missing
  IfFileExists "$R1\msvcp140.dll" 0 missing
  found:
    StrCpy $VC_RUNTIME_READY "1"
    Goto done
  missing:
    StrCpy $VC_RUNTIME_READY "0"
  done:
    Pop $R1
    Pop $R0
FunctionEnd


!macro StartVergeService
  ; The per-machine installer is already elevated, so create/repair the Service here instead
  ; of forcing the first Connect through a second UAC prompt. The helper also waits for the
  ; Service IPC protocol to become ready before it returns success.
  ${IfNot} ${FileExists} "$INSTDIR\resources\tono-service-install.exe"
    Abort "Tono Service installer is missing. Installation cannot continue safely."
  ${EndIf}
  DetailPrint "Installing and verifying ${PRODUCTNAME} Service..."
  ; Arm `.onInstFailed` for exactly this step: from here until the helper returns, a Service may
  ; exist that this run registered but never proved ready. Cleared again on the way out — once a
  ; verified Service is running, a later failure must leave it alone and let uninstall.exe (already
  ; written above) be the removal path, rather than silently opening the user's network.
  StrCpy $ServiceInstallAttempted 1
  StrCpy $ServiceInstallRetries 0
  serviceInstallAttempt:
  ; Bound output inactivity as well as the helper's own SCM/IPC waits. Without this, a wedged
  ; helper freezes the whole NSIS installer forever. "timeout" is handled as a failure below.
  nsExec::ExecToLog /TIMEOUT=180000 '"$INSTDIR\resources\tono-service-install.exe"'
  Pop $0
  ; nsExec returns a string: "error" and "timeout" must not be coerced to integer zero.
  ${If} $0 == "3010"
    DetailPrint "${PRODUCTNAME} Service update will finish after a reboot."
    SetRebootFlag true
  ${ElseIf} $0 == "75"
    ; 75 = REPAIR_IN_PROGRESS_EXIT_CODE (service/src/core/repair.rs): another elevated repair
    ; holds the gate. That is transient and retryable, so it must not dead-end a whole install.
    ${If} $ServiceInstallRetries < 5
      IntOp $ServiceInstallRetries $ServiceInstallRetries + 1
      DetailPrint "Another ${PRODUCTNAME} Service repair is in progress; retrying ($ServiceInstallRetries/5)..."
      Sleep 2000
      Goto serviceInstallAttempt
    ${EndIf}
    Abort "A ${PRODUCTNAME} Service repair is still in progress. Wait for it to finish (or reboot Windows), then run this installer again."
  ${ElseIf} $0 != "0"
    Abort "Tono Service installation failed (exit $0). Installation was stopped."
  ${EndIf}
  ; Only reachable when the helper reported success (every other path Aborts): the Service is
  ; registered and verified, so it is no longer this install's to tear down.
  StrCpy $ServiceInstallAttempted 0
!macroend

!macro RemoveVergeService
  ; An updater temporarily removes the old application files but must preserve the running
  ; Service until the new install helper replaces it. The helper itself distinguishes a durable
  ; active/wanted session (preserve fail-closed) from a disconnected old build (write a one-start
  ; wanted:false tombstone so late-visible orphan filters are cleaned by the replacement).
  ${If} $UpdateMode == 1
    DetailPrint "Update mode: preserving ${PRODUCTNAME} Service until replacement."
  ${Else}
    ; The dedicated helper restores protected DNS, removes persistent WFP objects, then deletes
    ; the SCM registration. Never delete its recovery binaries after a failed or unverifiable
    ; cleanup. A damaged install must be repaired first rather than fail open here.
    ;
    ; What "unverifiable" means changed, and the reason is worth keeping: this macro used to
    ; abort unless the user's exact prior DNS configuration was provably restored. On a machine
    ; whose live DNS apply keeps failing that proof never arrives, so the abort fired every time
    ; and Tono could not be uninstalled at all. The helper now escalates instead (exact restore →
    ; automatic/DHCP → refuse), and the only thing that still blocks here is "the kill-switch
    ; filters may still be installed" — because removing the app while a persistent WFP barrier
    ; stays armed leaves a blocked machine with no software left to unblock it. An inexact
    ; resolver does not: the user can change DNS from Windows' own network settings.
    ${IfNot} ${FileExists} "$INSTDIR\resources\tono-service-uninstall.exe"
      Abort "Tono Service uninstaller is missing. Reinstall Tono, then uninstall again."
    ${EndIf}
    DetailPrint "Restoring network protection and removing ${PRODUCTNAME} Service..."
    ; Preserve the recovery files but return control instead of hanging forever if cleanup stalls.
    nsExec::ExecToLog /TIMEOUT=180000 '"$INSTDIR\resources\tono-service-uninstall.exe"'
    Pop $0
    ; The helper's exit-code contract (uninstall_service.rs `cleanup_exit_code`):
    ;   0 = the machine is clean (or was already clean)
    ;   2 = the network was provably restored; only cosmetic cleanup (SCM record/binary) failed
    ;   4 = the kill-switch filters were removed; DNS may be inexact (DHCP fallback, still on a
    ;       Tono resolver, or unproven). Continue — an inexact resolver is not a blocked machine.
    ;   3 = cleanup could not show the WFP barrier was removed; recovery files stay on disk
    ; nsExec may also return "error"/"timeout" or another numeric string. Only a proven-safe
    ; result may let the uninstall continue: anything that is not 0, 2 or 4 is treated exactly
    ; like 3, because nothing showed the machine was made safe. That discipline is unchanged —
    ; unknown results still block, and every blocking path still preserves the recovery files.
    ${If} $0 == "2"
      DetailPrint "${PRODUCTNAME} network protection was restored; some Service leftovers could not be removed and will be cleaned up by a future install."
    ${ElseIf} $0 == "4"
      DetailPrint "${PRODUCTNAME} network protection (kill switch) was removed. DNS may need a manual check: Settings > Network & Internet > your adapter > DNS server assignment > Automatic (DHCP) for IPv4 and IPv6. Install/uninstall continues because the machine is no longer blocked."
    ${ElseIf} $0 != "0"
      ; Result 3 means the kill-switch filters may still be installed. DNS-only problems no longer
      ; land here (they are exit 4). Reboot and retry, or reinstall to repair the Service first.
      Abort "Tono could not confirm this machine was made safe to uninstall (result $0), so nothing was deleted and the recovery files were kept. See the messages above for what failed. The kill switch may still be installed — reboot Windows and run this uninstaller or installer again. Removing Tono while the barrier stays armed would leave the machine blocked with nothing left to unblock it. Installing Tono again first also repairs the Service."
    ${EndIf}
  ${EndIf}
!macroend

; Test 5 and older installers copied a second Mihomo plus Unix-named service helpers/scripts into
; Program Files. They are intentionally absent from the current resource manifest, which also
; means Tauri's generated uninstall loop cannot know they exist. Remove the exact historical
; names on both upgrade and uninstall; /REBOOTOK covers an old core image that Windows still has
; mapped without broadening the target beyond Tono's own install directory.
!macro RemoveKnownLegacyPayload
  Delete /REBOOTOK "$INSTDIR\verge-mihomo-alpha.exe"
  Delete /REBOOTOK "$INSTDIR\resources\clash-verge-service"
  Delete /REBOOTOK "$INSTDIR\resources\clash-verge-service-install"
  Delete /REBOOTOK "$INSTDIR\resources\clash-verge-service-uninstall"
  Delete /REBOOTOK "$INSTDIR\resources\clash-verge-service.exe"
  Delete /REBOOTOK "$INSTDIR\resources\clash-verge-service-install.exe"
  Delete /REBOOTOK "$INSTDIR\resources\clash-verge-service-uninstall.exe"
  Delete /REBOOTOK "$INSTDIR\resources\set_dns.sh"
  Delete /REBOOTOK "$INSTDIR\resources\unset_dns.sh"
!macroend

Section EarlyChecks
  ; Abort silent installer if downgrades is disabled
  !if "${ALLOWDOWNGRADES}" == "false"
  ${If} ${Silent}
    ; If downgrading
    ${If} $R0 = -1
      System::Call 'kernel32::AttachConsole(i -1)i.r0'
      ${If} $0 <> 0
        System::Call 'kernel32::GetStdHandle(i -11)i.r0'
        System::call 'kernel32::SetConsoleTextAttribute(i r0, i 0x0004)' ; set red color
        FileWrite $0 "$(silentDowngrades)"
      ${EndIf}
      Abort
    ${EndIf}
  ${EndIf}
  !endif

SectionEnd

Section CheckAndInstallVSRuntime
  StrCpy $VC_RUNTIME_NEEDED "0"

  ${If} ${IsNativeARM64}
    StrCpy $VC_REDIST_URL "https://aka.ms/vs/17/release/vc_redist.arm64.exe"
    StrCpy $VC_REDIST_EXE "vc_redist.arm64.exe"
    Call CheckVCRuntime64
    ${If} $VC_RUNTIME_READY != "1"
      StrCpy $VC_RUNTIME_NEEDED "1"
    ${EndIf}

  ${ElseIf} ${RunningX64}
    StrCpy $VC_REDIST_URL "https://aka.ms/vs/17/release/vc_redist.x64.exe"
    StrCpy $VC_REDIST_EXE "vc_redist.x64.exe"
    Call CheckVCRuntime64
    ${If} $VC_RUNTIME_READY != "1"
      StrCpy $VC_RUNTIME_NEEDED "1"
    ${EndIf}

  ${Else}
    StrCpy $VC_REDIST_URL "https://aka.ms/vs/17/release/vc_redist.x86.exe"
    StrCpy $VC_REDIST_EXE "vc_redist.x86.exe"

    IfFileExists "$SYSDIR\vcruntime140.dll" 0 filesMissing32
    IfFileExists "$SYSDIR\msvcp140.dll" 0 filesMissing32
    Goto afterFileCheck32
  filesMissing32:
    StrCpy $VC_RUNTIME_NEEDED "1"
  afterFileCheck32:
  ${EndIf}

  ${If} $VC_RUNTIME_NEEDED != "1"
    ; These probes need the native view, but they must hand the installer's own view back when
    ; they are done: `.onInit`'s SetContext selected view 64 for this build, and every later
    ; section (WebView2's literal WOW6432Node paths, the uninstall/ARP keys) is written for it.
    ; Leaving view 32 behind double-redirects those reads into keys that can never exist.
    ${If} ${IsNativeARM64}
      SetRegView 64
      ClearErrors
      ReadRegDword $R0 HKLM "SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\arm64" "Installed"
      ${If} ${Errors}
        StrCpy $R0 0
      ${EndIf}
      !insertmacro SetContext
    ${ElseIf} ${RunningX64}
      SetRegView 64
      ClearErrors
      ReadRegDword $R0 HKLM "SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\${ARCH}" "Installed"
      ${If} ${Errors}
        StrCpy $R0 0
      ${EndIf}
      !insertmacro SetContext
    ${Else}
      ClearErrors
      ReadRegDword $R0 HKLM "SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x86" "Installed"
      ${If} ${Errors}
        StrCpy $R0 0
      ${EndIf}
    ${EndIf}

    ${If} $R0 != "1"
      StrCpy $VC_RUNTIME_NEEDED "1"
    ${EndIf}
  ${EndIf}

  ${If} $VC_RUNTIME_NEEDED != "1"
    DetailPrint "已检测到匹配的 Visual C++ Redistributable，跳过安装"
    Goto done_vc
  ${EndIf}

  DetailPrint "正在下载 Visual C++ Redistributable..."
  nsisdl::download "$VC_REDIST_URL" "$TEMP\$VC_REDIST_EXE"
  Pop $0
  ${If} $0 == "success"
    DetailPrint "正在安装 Visual C++ Redistributable..."
    ExecWait '"$TEMP\$VC_REDIST_EXE" /quiet /norestart' $0
    ${If} $0 == 0
      DetailPrint "Visual C++ Redistributable 安装成功"
    ${ElseIf} $0 == 3010
      ; 3010 is "installed, reboot required" — a success the old branch logged as a failure.
      DetailPrint "Visual C++ Redistributable 安装成功，需要重启后生效"
      SetRebootFlag true
    ${ElseIf} $0 == 1638
      ; 1638 means a same-or-newer runtime is already registered; nothing to install.
      DetailPrint "已安装同版本或更新的 Visual C++ Redistributable，跳过安装"
    ${Else}
      DetailPrint "Visual C++ Redistributable 安装失败"
    ${EndIf}
    Delete "$TEMP\$VC_REDIST_EXE"
  ${Else}
    DetailPrint "Visual C++ Redistributable 下载失败"
  ${EndIf}

  done_vc:
SectionEnd

Section WebView2
  ; The literal WOW6432Node paths below are only correct in the native register view this build
  ; installs under. Re-assert it rather than inheriting whatever an earlier section left set: a
  ; misdetected WebView2 sends an offline install into the bootstrapper and Aborts it.
  !insertmacro SetContext

  ; Check if Webview2 is already installed and skip this section
  ${If} ${RunningX64}
    ReadRegStr $4 HKLM "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\${WEBVIEW2APPGUID}" "pv"
  ${Else}
    ReadRegStr $4 HKLM "SOFTWARE\Microsoft\EdgeUpdate\Clients\${WEBVIEW2APPGUID}" "pv"
  ${EndIf}
  ${If} $4 == ""
    ReadRegStr $4 HKCU "SOFTWARE\Microsoft\EdgeUpdate\Clients\${WEBVIEW2APPGUID}" "pv"
  ${EndIf}

  ${If} $4 == ""
    ; Webview2 installation
    ;
    ; Skip if updating
    ${If} $UpdateMode <> 1
      !if "${INSTALLWEBVIEW2MODE}" == "downloadBootstrapper"
        Delete "$TEMP\MicrosoftEdgeWebview2Setup.exe"
        DetailPrint "$(webview2Downloading)"
        NSISdl::download "https://go.microsoft.com/fwlink/p/?LinkId=2124703" "$TEMP\MicrosoftEdgeWebview2Setup.exe"
        Pop $0
        ${If} $0 == "success"
          DetailPrint "$(webview2DownloadSuccess)"
        ${Else}
          DetailPrint "$(webview2DownloadError)"
          Abort "$(webview2AbortError)"
        ${EndIf}
        StrCpy $6 "$TEMP\MicrosoftEdgeWebview2Setup.exe"
        Goto install_webview2
      !endif

      !if "${INSTALLWEBVIEW2MODE}" == "embedBootstrapper"
        Delete "$TEMP\MicrosoftEdgeWebview2Setup.exe"
        File "/oname=$TEMP\MicrosoftEdgeWebview2Setup.exe" "${WEBVIEW2BOOTSTRAPPERPATH}"
        DetailPrint "$(installingWebview2)"
        StrCpy $6 "$TEMP\MicrosoftEdgeWebview2Setup.exe"
        Goto install_webview2
      !endif

      !if "${INSTALLWEBVIEW2MODE}" == "offlineInstaller"
        Delete "$TEMP\MicrosoftEdgeWebView2RuntimeInstaller.exe"
        File "/oname=$TEMP\MicrosoftEdgeWebView2RuntimeInstaller.exe" "${WEBVIEW2INSTALLERPATH}"
        DetailPrint "$(installingWebview2)"
        StrCpy $6 "$TEMP\MicrosoftEdgeWebView2RuntimeInstaller.exe"
        Goto install_webview2
      !endif

      Goto webview2_done

      install_webview2:
        DetailPrint "$(installingWebview2)"
        ; $6 holds the path to the webview2 installer; quote it, $TEMP routinely has a space.
        ExecWait '"$6" ${WEBVIEW2INSTALLERARGS} /install' $1
        ${If} $1 = 0
          DetailPrint "$(webview2InstallSuccess)"
        ${Else}
          DetailPrint "$(webview2InstallError)"
          Abort "$(webview2AbortError)"
        ${EndIf}
      webview2_done:
    ${EndIf}
  ${Else}
    !if "${MINIMUMWEBVIEW2VERSION}" != ""
      ${VersionCompare} "${MINIMUMWEBVIEW2VERSION}" "$4" $R0
      ${If} $R0 = 1
        update_webview:
          DetailPrint "$(installingWebview2)"
          ${If} ${RunningX64}
            ReadRegStr $R1 HKLM "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate" "path"
          ${Else}
            ReadRegStr $R1 HKLM "SOFTWARE\Microsoft\EdgeUpdate" "path"
          ${EndIf}
          ${If} $R1 == ""
            ReadRegStr $R1 HKCU "SOFTWARE\Microsoft\EdgeUpdate" "path"
          ${EndIf}
          ${If} $R1 != ""
            ; Chromium updater docs: https://source.chromium.org/chromium/chromium/src/+/main:docs/updater/user_manual.md
            ; Modified from "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView\ModifyPath"
            ExecWait `"$R1" /install appguid=${WEBVIEW2APPGUID}&needsadmin=true` $1
            ${If} $1 = 0
              DetailPrint "$(webview2InstallSuccess)"
            ${Else}
              MessageBox MB_ICONEXCLAMATION|MB_ABORTRETRYIGNORE "$(webview2InstallError)" IDIGNORE ignore IDRETRY update_webview
              Quit
              ignore:
            ${EndIf}
          ${EndIf}
      ${EndIf}
    !endif
  ${EndIf}
SectionEnd

Section Install
  SetOutPath $INSTDIR

  !ifmacrodef NSIS_HOOK_PREINSTALL
    !insertmacro NSIS_HOOK_PREINSTALL
  !endif

  !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"

  ; Ensure startup folders exist. `$SMSTARTUP` follows the shell context and the machine's real
  ; ProgramData location, which a hardcoded English C:-rooted path does not.
  SetShellVarContext all
  CreateDirectory "$SMSTARTUP"
  DetailPrint "Ensured system startup folder exists: $SMSTARTUP"

  SetShellVarContext current
  StrCpy $0 "$SMPROGRAMS\Startup"
  CreateDirectory "$0"
  DetailPrint "Ensured user startup folder exists: $0"

  ; Remove stale window-state files
  DetailPrint "Removing window-state.json / .window-state.json"
  Delete "$APPDATA\com.raydocs.tono\window-state.json"
  Delete "$APPDATA\com.raydocs.tono\.window-state.json"

  !insertmacro SetContext

  ; Copy main executable
  File "${MAINBINARYSRCPATH}"

  ; Copy resources
  {{#each resources_dirs}}
    CreateDirectory "$INSTDIR\\{{this}}"
  {{/each}}
  {{#each resources}}
    File /a "/oname={{this.[1]}}" "{{no-escape @key}}"
  {{/each}}

  ; Copy external binaries
  {{#each binaries}}
    File /a "/oname={{this}}" "{{no-escape @key}}"
  {{/each}}

  ; Register the removal path BEFORE the Service is created and started. NSIS rolls back neither
  ; `File` nor an SCM registration, and StartVergeService can Abort after create/start succeeded
  ; (a failed readiness wait). Writing uninstall.exe and the Add/Remove entry first is what keeps
  ; that failure from leaving an AutoStart Service arming the WFP floor with no way to remove it
  ; — on upgrades the old uninstaller has already deleted the previous uninstall.exe and UNINSTKEY.
  ; Create uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Save $INSTDIR in registry for future installations
  WriteRegStr SHCTX "${MANUPRODUCTKEY}" "" $INSTDIR

  !if "${INSTALLMODE}" == "both"
    ; Save install mode to be selected by default for the next installation such as updating
    ; or when uninstalling
    WriteRegStr SHCTX "${UNINSTKEY}" $MultiUser.InstallMode 1
  !endif

  ; Remove old main binary if it doesn't match new main binary name
  ReadRegStr $OldMainBinaryName SHCTX "${UNINSTKEY}" "MainBinaryName"
  ${If} $OldMainBinaryName != ""
  ${AndIf} $OldMainBinaryName != "${MAINBINARYNAME}.exe"
    Delete "$INSTDIR\$OldMainBinaryName"
  ${EndIf}

  ; Save current MAINBINARYNAME for future updates
  WriteRegStr SHCTX "${UNINSTKEY}" "MainBinaryName" "${MAINBINARYNAME}.exe"

  ; Registry information for add/remove programs
  WriteRegStr SHCTX "${UNINSTKEY}" "DisplayName" "${PRODUCTNAME}"
  WriteRegStr SHCTX "${UNINSTKEY}" "DisplayIcon" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\""
  WriteRegStr SHCTX "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr SHCTX "${UNINSTKEY}" "Publisher" "${MANUFACTURER}"
  WriteRegStr SHCTX "${UNINSTKEY}" "InstallLocation" "$\"$INSTDIR$\""
  WriteRegStr SHCTX "${UNINSTKEY}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
  WriteRegDWORD SHCTX "${UNINSTKEY}" "NoModify" "1"
  WriteRegDWORD SHCTX "${UNINSTKEY}" "NoRepair" "1"

  ${GetSize} "$INSTDIR" "/M=uninstall.exe /S=0K /G=0" $0 $1 $2
  IntOp $0 $0 + ${ESTIMATEDSIZE}
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD SHCTX "${UNINSTKEY}" "EstimatedSize" "$0"

  !if "${HOMEPAGE}" != ""
    WriteRegStr SHCTX "${UNINSTKEY}" "URLInfoAbout" "${HOMEPAGE}"
    WriteRegStr SHCTX "${UNINSTKEY}" "URLUpdateInfo" "${HOMEPAGE}"
    WriteRegStr SHCTX "${UNINSTKEY}" "HelpLink" "${HOMEPAGE}"
  !endif

  ; A fresh/repair install may follow an older uninstaller that deleted its SCM record and state
  ; file but accidentally left persistent WFP filters behind. Starting the new Service directly
  ; would interpret that orphaned combination as an intentional fail-closed state and take the
  ; customer offline until the App happened to release it. A non-update install runs the full
  ; disarm helper here. UpdateMode deliberately keeps the Service in place, then the replacement
  ; helper preserves active protection or marks a proven-disconnected legacy state for cleanup.
  !insertmacro RemoveVergeService
  !insertmacro StartVergeService

  ; The replacement Service is verified and no legacy core can still own these files.
  !insertmacro RemoveKnownLegacyPayload

  ; Create file associations
  {{#each file_associations as |association| ~}}
    {{#each association.ext as |ext| ~}}
       !insertmacro APP_ASSOCIATE "{{ext}}" "{{or association.name ext}}" "{{association-description association.description ext}}" "$INSTDIR\${MAINBINARYNAME}.exe,0" "Open with ${PRODUCTNAME}" "$INSTDIR\${MAINBINARYNAME}.exe $\"%1$\""
    {{/each}}
  {{/each}}

  ; Register deep links
  {{#each deep_link_protocols as |protocol| ~}}
    WriteRegStr SHCTX "Software\Classes\\{{protocol}}" "URL Protocol" ""
    WriteRegStr SHCTX "Software\Classes\\{{protocol}}" "" "URL:${BUNDLEID} protocol"
    WriteRegStr SHCTX "Software\Classes\\{{protocol}}\DefaultIcon" "" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\",0"
    WriteRegStr SHCTX "Software\Classes\\{{protocol}}\shell\open\command" "" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\" $\"%1$\""
  {{/each}}

  ; Create start menu shortcut
  !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
    Call CreateOrUpdateStartMenuShortcut
    ; Refreshed on every install, including updates and /NS: this is the recovery control the
    ; Service points users at, not a convenience shortcut, and its target moves with $INSTDIR.
    Call CreateOrUpdateRestoreNetworkShortcut
  !insertmacro MUI_STARTMENU_WRITE_END

  ; Create desktop shortcut for silent and passive installers
  ; because finish page will be skipped
  ${If} $PassiveMode = 1
  ${OrIf} ${Silent}
    Call CreateOrUpdateDesktopShortcut
  ${EndIf}

  !ifmacrodef NSIS_HOOK_POSTINSTALL
    !insertmacro NSIS_HOOK_POSTINSTALL
  !endif

  ; Auto close this page for passive mode
  ${If} $PassiveMode = 1
    SetAutoClose true
  ${EndIf}
SectionEnd

Function .onInstFailed
  ; NSIS rolls back neither `File` nor an SCM registration, so a failed install can end with a
  ; Service that this run registered but never proved ready: AutoStart, with SCM restart actions,
  ; arming a persistent WFP floor. Undo that registration with the same helper the uninstaller
  ; uses. The flag narrows this to the Service step itself, so an abort before it (a cancelled or
  ; refused install) and a failure after it (a verified Service that is now the user's, removable
  ; through Add/Remove Programs) both stay the no-op they have to be.
  ${If} $ServiceInstallAttempted <> 1
    Return
  ${EndIf}
  ${IfNot} ${FileExists} "$INSTDIR\resources\tono-service-uninstall.exe"
    DetailPrint "Installation failed and the Service uninstaller is missing; run uninstall.exe from Add/Remove Programs to remove the ${PRODUCTNAME} Service."
    Return
  ${EndIf}
  DetailPrint "Installation failed; removing the ${PRODUCTNAME} Service registered by this install..."
  nsExec::ExecToLog /TIMEOUT=180000 '"$INSTDIR\resources\tono-service-uninstall.exe"'
  Pop $0
  ; Same contract as RemoveVergeService. Nothing here may block or delete: uninstall.exe and the
  ; Add/Remove entry were written before the Service was touched, so an unproven cleanup still
  ; leaves the user a supported removal path instead of a dead end.
  ${If} $0 == "0"
    DetailPrint "${PRODUCTNAME} Service was removed and network protection was restored."
  ${ElseIf} $0 == "2"
    DetailPrint "${PRODUCTNAME} network protection was restored; some Service leftovers remain and will be cleaned up by a future install."
  ${ElseIf} $0 == "4"
    DetailPrint "${PRODUCTNAME} network protection was removed, but your previous DNS servers could not be verified, so the affected adapters were set back to automatic (DHCP)."
  ${Else}
    DetailPrint "${PRODUCTNAME} Service cleanup could not be verified (result $0); your connection may still be protected by the kill switch. Reboot Windows, then run this installer again or uninstall ${PRODUCTNAME} from Add/Remove Programs."
  ${EndIf}
FunctionEnd

Function .onInstSuccess
  ; Exit 3010 means the old Service is running and its replacement is queued for reboot. Do not
  ; launch a new app binary against that potentially incompatible protocol generation.
  IfRebootFlag skipPostInstallRun checkPostInstallRun
  skipPostInstallRun:
    Return
  checkPostInstallRun:
  ; Check for `/R` flag only in silent and passive installers because
  ; GUI installer has a toggle for the user to (re)start the app
  ${If} $PassiveMode = 1
  ${OrIf} ${Silent}
    ${GetOptions} $CMDLINE "/R" $R0
    ${IfNot} ${Errors}
      ${GetOptions} $CMDLINE "/ARGS" $R0
      nsis_tauri_utils::RunAsUser "$INSTDIR\${MAINBINARYNAME}.exe" "$R0"
    ${EndIf}
  ${EndIf}
FunctionEnd

Function un.onInit
  !insertmacro SetContext

  !if "${INSTALLMODE}" == "both"
    !insertmacro MULTIUSER_UNINIT
  !endif

  !insertmacro MUI_UNGETLANGUAGE

  ${GetOptions} $CMDLINE "/P" $PassiveMode
  ${IfNot} ${Errors}
    StrCpy $PassiveMode 1
  ${EndIf}

  ${GetOptions} $CMDLINE "/UPDATE" $UpdateMode
  ${IfNot} ${Errors}
    StrCpy $UpdateMode 1
  ${EndIf}
FunctionEnd

Section Uninstall

  !ifmacrodef NSIS_HOOK_PREUNINSTALL
    !insertmacro NSIS_HOOK_PREUNINSTALL
  !endif

  !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
  !insertmacro RemoveVergeService

  ; Remove cached window state files
  DetailPrint "Removing window-state.json / .window-state.json"
  SetShellVarContext current
  Delete "$APPDATA\com.raydocs.tono\window-state.json"
  Delete "$APPDATA\com.raydocs.tono\.window-state.json"

  !insertmacro SetContext

  ; Delete the app directory and its content from disk
  ; Copy main executable
  Delete "$INSTDIR\${MAINBINARYNAME}.exe"

  ; Delete resources
  {{#each resources}}
    Delete "$INSTDIR\\{{this.[1]}}"
  {{/each}}

  ; Delete external binaries
  {{#each binaries}}
    Delete "$INSTDIR\\{{this}}"
  {{/each}}

  ; These files came from older bundles and therefore never appear in the generated lists above.
  !insertmacro RemoveKnownLegacyPayload

  ; Delete app associations
  {{#each file_associations as |association| ~}}
    {{#each association.ext as |ext| ~}}
      !insertmacro APP_UNASSOCIATE "{{ext}}" "{{or association.name ext}}"
    {{/each}}
  {{/each}}

  ; Delete deep links
  {{#each deep_link_protocols as |protocol| ~}}
    ReadRegStr $R7 SHCTX "Software\Classes\\{{protocol}}\shell\open\command" ""
    ${If} $R7 == "$\"$INSTDIR\${MAINBINARYNAME}.exe$\" $\"%1$\""
      DeleteRegKey SHCTX "Software\Classes\\{{protocol}}"
    ${EndIf}
  {{/each}}


  ; Delete uninstaller
  Delete "$INSTDIR\uninstall.exe"

  {{#each resources_ancestors}}
  RMDir /REBOOTOK "$INSTDIR\\{{this}}"
  {{/each}}
  ; A known legacy core may have required /REBOOTOK above. Schedule the exact product root too so
  ; Windows can remove the now-empty directory after those mapped images are released.
  RMDir /REBOOTOK "$INSTDIR"

  ; Remove shortcuts if not updating
  ${If} $UpdateMode <> 1
    !insertmacro DeleteAppUserModelId

    ; Remove start menu shortcut
    !insertmacro MUI_STARTMENU_GETFOLDER Application $AppStartMenuFolder

    ; The recovery shortcut targets powershell.exe, so IsShortcutTarget cannot recognise it.
    ; Delete it before the RMDir below, or the leftover keeps the start menu folder alive.
    Delete "$SMPROGRAMS\$AppStartMenuFolder\${RESTORENETWORKLINK}"
    Delete "$SMPROGRAMS\${RESTORENETWORKLINK}"

    !insertmacro IsShortcutTarget "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro UnpinShortcut "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
      Delete "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
      RMDir "$SMPROGRAMS\$AppStartMenuFolder"
    ${EndIf}
    !insertmacro IsShortcutTarget "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro UnpinShortcut "$SMPROGRAMS\${PRODUCTNAME}.lnk"
      Delete "$SMPROGRAMS\${PRODUCTNAME}.lnk"
    ${EndIf}

    ; Remove desktop shortcuts
    !insertmacro IsShortcutTarget "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro UnpinShortcut "$DESKTOP\${PRODUCTNAME}.lnk"
      Delete "$DESKTOP\${PRODUCTNAME}.lnk"
    ${EndIf}

  ${EndIf}

  ; Remove registry information for add/remove programs
  !if "${INSTALLMODE}" == "both"
    DeleteRegKey SHCTX "${UNINSTKEY}"
  !else if "${INSTALLMODE}" == "perMachine"
    DeleteRegKey HKLM "${UNINSTKEY}"
  !else
    DeleteRegKey HKCU "${UNINSTKEY}"
  !endif

  ; Removes the Autostart entry for ${PRODUCTNAME} from the HKCU Run key if it exists.
  ; This ensures the program does not launch automatically after uninstallation if it exists.
  ; If it doesn't exist, it does nothing.
  ; We do this when not updating (to preserve the registry value on updates)
  ${If} $UpdateMode <> 1
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCTNAME}"
  ${EndIf}

  ; Delete app data if the checkbox is selected
  ; and if not updating
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    ; Clear the install location $INSTDIR from registry
    DeleteRegKey SHCTX "${MANUPRODUCTKEY}"
    DeleteRegKey /ifempty SHCTX "${MANUKEY}"

    ; Clear the install language from registry
    DeleteRegValue HKCU "${MANUPRODUCTKEY}" "Installer Language"
    DeleteRegKey /ifempty HKCU "${MANUPRODUCTKEY}"
    DeleteRegKey /ifempty HKCU "${MANUKEY}"

    SetShellVarContext current
    RmDir /r "$APPDATA\${BUNDLEID}"
    RmDir /r "$LOCALAPPDATA\${BUNDLEID}"
  ${EndIf}

  !ifmacrodef NSIS_HOOK_POSTUNINSTALL
    !insertmacro NSIS_HOOK_POSTUNINSTALL
  !endif

  ; Auto close if passive mode or updating
  ${If} $PassiveMode = 1
  ${OrIf} $UpdateMode = 1
    SetAutoClose true
  ${EndIf}
SectionEnd

Function RestorePreviousInstallLocation
  ReadRegStr $4 SHCTX "${MANUPRODUCTKEY}" ""
  StrCmp $4 "" +2 0
    StrCpy $INSTDIR $4
FunctionEnd

Function Skip
  Abort
FunctionEnd

Function SkipIfPassive
  ${IfThen} $PassiveMode = 1  ${|} Abort ${|}
FunctionEnd
Function un.SkipIfPassive
  ${IfThen} $PassiveMode = 1  ${|} Abort ${|}
FunctionEnd

Function CreateOrUpdateStartMenuShortcut
  ; We used to use product name as MAINBINARYNAME
  ; migrate old shortcuts to target the new MAINBINARYNAME
  StrCpy $R0 0

  !insertmacro IsShortcutTarget "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\$OldMainBinaryName"
  Pop $0
  ${If} $0 = 1
    !insertmacro SetShortcutTarget "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    StrCpy $R0 1
  ${EndIf}

  !insertmacro IsShortcutTarget "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\$OldMainBinaryName"
  Pop $0
  ${If} $0 = 1
    !insertmacro SetShortcutTarget "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    StrCpy $R0 1
  ${EndIf}

  ${If} $R0 = 1
    Return
  ${EndIf}

  ; Skip creating shortcut if in update mode or no shortcut mode
  ; but always create if migrating from wix
  ${If} $WixMode = 0
    ${If} $UpdateMode = 1
    ${OrIf} $NoShortcutMode = 1
      Return
    ${EndIf}
  ${EndIf}

  !if "${STARTMENUFOLDER}" != ""
    CreateDirectory "$SMPROGRAMS\$AppStartMenuFolder"
    CreateShortcut "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    !insertmacro SetLnkAppUserModelId "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
  !else
    CreateShortcut "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    !insertmacro SetLnkAppUserModelId "$SMPROGRAMS\${PRODUCTNAME}.lnk"
  !endif
FunctionEnd

; The last way back onto the network when the App cannot release the WFP barrier. Today that
; escape is an elevated `tono-service.exe --emergency-disarm` — a path and a flag nobody knows,
; on a machine that by definition cannot look them up. A .lnk cannot request elevation by itself,
; so the shortcut runs PowerShell's `Start-Process -Verb RunAs`, which is what raises UAC, over
; `cmd /k`, which holds the window open long enough to read the bilingual result the disarm
; prints. It is user-initiated only, and grants no authority the Add/Remove uninstaller lacks.
Function CreateOrUpdateRestoreNetworkShortcut
  Push $R0
  Push $R1

  ; System32 is resolved by the (64-bit) shell that launches the .lnk; either PowerShell bitness
  ; runs `-Verb RunAs` identically, so WOW64 redirection of this string is harmless.
  StrCpy $R0 "$WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
  ; `$\"` is how NSIS writes a quote; `\$\"` is the backslash-escaped quote CommandLineToArgvW
  ; needs so the install path — which always contains a space — survives inside -Command.
  StrCpy $R1 "-NoProfile -ExecutionPolicy Bypass -Command $\"Start-Process -FilePath 'cmd.exe' -ArgumentList '/k','\$\"$INSTDIR\resources\tono-service.exe\$\" --emergency-disarm' -Verb RunAs$\""

  ; SW_SHOWMINIMIZED keeps the launcher window out of the way; the elevated console it starts is
  ; the one the user reads.
  !if "${STARTMENUFOLDER}" != ""
    CreateDirectory "$SMPROGRAMS\$AppStartMenuFolder"
    CreateShortcut "$SMPROGRAMS\$AppStartMenuFolder\${RESTORENETWORKLINK}" "$R0" "$R1" "$INSTDIR\${MAINBINARYNAME}.exe" 0 SW_SHOWMINIMIZED "" "$(restoreNetworkTooltip)"
  !else
    CreateShortcut "$SMPROGRAMS\${RESTORENETWORKLINK}" "$R0" "$R1" "$INSTDIR\${MAINBINARYNAME}.exe" 0 SW_SHOWMINIMIZED "" "$(restoreNetworkTooltip)"
  !endif

  Pop $R1
  Pop $R0
FunctionEnd

Function CreateOrUpdateDesktopShortcut
  ; We used to use product name as MAINBINARYNAME
  ; migrate old shortcuts to target the new MAINBINARYNAME
  !insertmacro IsShortcutTarget "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\$OldMainBinaryName"
  Pop $0
  ${If} $0 = 1
    !insertmacro SetShortcutTarget "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Return
  ${EndIf}

  ; Skip creating shortcut if in update mode or no shortcut mode
  ; but always create if migrating from wix
  ${If} $WixMode = 0
    ${If} $UpdateMode = 1
    ${OrIf} $NoShortcutMode = 1
      Return
    ${EndIf}
  ${EndIf}

  CreateShortcut "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
  !insertmacro SetLnkAppUserModelId "$DESKTOP\${PRODUCTNAME}.lnk"
FunctionEnd
