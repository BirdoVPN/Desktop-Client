; NSIS installer hooks for BirdoVPN (wired via bundle.windows.nsis.installerHooks).
;
; The app registers an elevated launch-at-login Scheduled Task
; ("BirdoVPN Launch At Login" — see commands/settings.rs set_autostart_windows)
; because the requireAdministrator exe can never be launched from the HKCU Run
; key. The uninstaller must remove that task, or it lingers pointing at a
; missing exe and fires a silent failure at every logon.
;
; This file is !included near the top of Tauri's installer.nsi (tauri-bundler
; 2.10.0, from @tauri-apps/cli 2.12.0), BEFORE the template defines MANUFACTURER,
; PRODUCTNAME and MANUPRODUCTKEY. Code outside the NSIS_HOOK_* macros is
; parsed right here, so it uses its own literals; NSIS_HOOK_PREINSTALL, which
; expands later, checks at compile time that they match the template's.

!include LogicLib.nsh

; ── D8 (owner decision 2026-10-01): publisher "Birdo Networks Ltd" ─────────
;
; tauri.conf.json `bundle.publisher` is the template's MANUFACTURER. It does
; NOT name the Apps & features entry: that key is
; ...\CurrentVersion\Uninstall\${PRODUCTNAME} ("BirdoVPN"), so an upgrade
; rewrites the SAME entry, Publisher value included, and there is one entry.
; What the publisher does name is the install's own record,
; Software\${MANUFACTURER}\${PRODUCTNAME}, whose default value is the install
; folder. Every release up to 1.4.45 wrote it under "Birdo VPN". Under the new
; name it is missing, and the template then
;   - installs into the DEFAULT folder (.onInit, RestorePreviousInstallLocation),
;     not the one the user chose, leaving the old folder behind; and
;   - when the user picks "Uninstall before installing" on its reinstall page,
;     runs the old uninstaller with `_?=` and an EMPTY folder.
; So the old record is adopted before any page reads it. Once the install has
; succeeded it is kept as a mirror of the new one (see NSIS_HOOK_POSTINSTALL).
; User data never depended on the publisher: it lives under the bundle
; identifier and the fixed BirdoVPN names below.
;
; The install is per-machine (tauri.conf.json `installMode`, checked in
; NSIS_HOOK_PREINSTALL), so the records are HKLM's. Where the template may
; have switched SHCTX to the current user by then — the uninstaller does,
; after "Delete the application data" — the machine records are named as
; HKLM explicitly (REVIEW-WIN2-016).
!define BIRDO_MANUKEY "Software\Birdo Networks Ltd"
!define BIRDO_MANUPRODUCTKEY "${BIRDO_MANUKEY}\BirdoVPN"
!define BIRDO_LEGACY_MANUKEY "Software\Birdo VPN"
!define BIRDO_LEGACY_MANUPRODUCTKEY "${BIRDO_LEGACY_MANUKEY}\BirdoVPN"

Var BirdoAdoptedLegacyRecord
Var BirdoOutPathBeforeAdoption

; Carry the old publisher's record over to the new one, once, if this machine
; has only the old one. Runs from the GUI init (GUI and passive installs, the
; in-app updater's included), before the reinstall and folder pages, and again
; from NSIS_HOOK_PREINSTALL for a silent install, which has no GUI init.
Function BirdoAdoptLegacyRecord
  Push $0
  ReadRegStr $0 SHCTX "${BIRDO_MANUPRODUCTKEY}" ""
  ${If} $0 == ""
    ReadRegStr $0 SHCTX "${BIRDO_LEGACY_MANUPRODUCTKEY}" ""
    ${If} $0 != ""
      WriteRegStr SHCTX "${BIRDO_MANUPRODUCTKEY}" "" $0
      StrCpy $BirdoAdoptedLegacyRecord 1
      ; .onInit fell back to the default folder for lack of the record; the
      ; folder to update is the old install's. A folder given with /D stays.
      ${If} $INSTDIR == "$PROGRAMFILES64\BirdoVPN"
        StrCpy $INSTDIR $0
      ${EndIf}
    ${EndIf}
  ${EndIf}
  Pop $0
FunctionEnd

; Not installed after all: leave the registry as the old install had it.
Function BirdoForgetAdoptedRecord
  ${If} $BirdoAdoptedLegacyRecord == 1
    DeleteRegKey SHCTX "${BIRDO_MANUPRODUCTKEY}"
    DeleteRegKey /ifempty SHCTX "${BIRDO_MANUKEY}"
  ${EndIf}
FunctionEnd

; Modern UI calls these from the .onGUIInit and .onUserAbort it generates
; (the template defines neither name itself).
!define MUI_CUSTOMFUNCTION_GUIINIT BirdoAdoptLegacyRecord
!define MUI_CUSTOMFUNCTION_ABORT BirdoForgetAdoptedRecord

; REVIEW-WIN2-014: a FAILED install — not a cancel — must forget the adopted
; record too: the template's "BirdoVPN is running" abort after
; NSIS_HOOK_PREINSTALL, a WebView2 abort, a file error. .onUserAbort covers
; only Cancel, and the template defines no .onInstFailed.
Function .onInstFailed
  Call BirdoForgetAdoptedRecord
FunctionEnd

; The installer language MUI keeps beside the old publisher's record, for the
; user who ran an old installer.
!macro BIRDO_DROP_LEGACY_LANGUAGE
  DeleteRegValue HKCU "${BIRDO_LEGACY_MANUPRODUCTKEY}" "Installer Language"
  DeleteRegKey /ifempty HKCU "${BIRDO_LEGACY_MANUPRODUCTKEY}"
  DeleteRegKey /ifempty HKCU "${BIRDO_LEGACY_MANUKEY}"
!macroend

; The old publisher's record, and its language value. Only the "BirdoVPN"
; product key: a 1.0.0 install (product "Birdo VPN") has a record of its own
; under the same parent.
!macro BIRDO_DROP_LEGACY_PUBLISHER_RECORD
  DeleteRegKey HKLM "${BIRDO_LEGACY_MANUPRODUCTKEY}"
  DeleteRegKey /ifempty HKLM "${BIRDO_LEGACY_MANUKEY}"
  !insertmacro BIRDO_DROP_LEGACY_LANGUAGE
!macroend

; REVIEW-WIN2-008: stop a running BirdoVPN with the template's OWN macro,
; called EXACTLY as the template calls it, on this one line only. Both hooks
; that need a stopped app use this macro (NSIS_HOOK_PREUNINSTALL always;
; NSIS_HOOK_PREINSTALL only before it uninstalls an MSI-era install).
;
; tauri-bundler 2.10.0 (CLI 2.12) changed the macro's first parameter from an
; executable NAME to an executable PATH that it hands to Restart Manager
; (RmRegisterResources -> RmGetList -> RmShutdown). Given the old bare
; "${MAINBINARYNAME}.exe", the new macro matches nothing, reports "not
; running", and the hooks silently stop protecting the live session.
; tests.yml's frontend job runs scripts/ci/check-nsis-hook-macros.sh, which
; fails the PR if this call ever differs from the template compiled into the
; locked @tauri-apps/cli, or if the call appears on more than this one line.
!macro BIRDO_STOP_APP_IF_RUNNING
  !insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
!macroend

; ── WIN2-012: the MSI-era install ──────────────────────────────────────────
;
; From b15aece (2026-04-16, productName "BirdoVPN") to 79fd4ae (2026-07-29),
; every release also built an MSI from Tauri's default WiX template
; (tauri.conf.json "wix": null; CLI 2.9.6 to 2.11.4), with publisher
; "Birdo VPN". That MSI:
;   - installed per-machine into [ProgramFiles64Folder]BirdoVPN, which is THIS
;     installer's default folder. It installed the same birdo-vpn-desktop.exe
;     and resources, the same birdo:// key (HKLM\Software\Classes\birdo) and
;     the same Public Desktop BirdoVPN.lnk;
;   - registered its own Apps & features entry, Uninstall\{ProductCode}: a
;     new GUID per build, DisplayName "BirdoVPN", Publisher "Birdo VPN",
;     WindowsInstaller = 1, UninstallString "MsiExec.exe /X{ProductCode}".
;     Every build shares the UpgradeCode {A5391D09-4F7F-5D63-841B-D35670681DB4},
;     a UUID v5 of "BirdoVPN.exe.app.x64";
;   - put "Uninstall BirdoVPN.lnk" (msiexec /x [ProductCode]) into that same
;     folder, and BirdoVPN.lnk into a Start-menu folder of its own.
; (Read from the tables of a 1.3.2 MSI of that era. Root 2, HKLM, holds
; Classes\birdo; Root 1, HKCU, holds Software\Birdo VPN\BirdoVPN\InstallDir.)
;
; The template's WiX migration (PageReinstall) matches DisplayName plus
; ${MANUFACTURER}, which has been "Birdo Networks Ltd" since D8, so it no
; longer finds that entry (REVIEW-WIN2-012). It never ran for a silent
; install at all. Left alone, the MSI keeps a second Apps & features entry.
; Uninstalling it later, from there or from its shortcut, deletes the exe,
; the resources, birdo:// and the desktop shortcut that this install now
; owns. Deleting only its entry would not help either: Windows Installer
; would still own those files, and the shortcut would still uninstall it.
;
; So each such entry goes before any file is laid down:
;   - Windows Installer knows the product: `msiexec /x {ProductCode} /qn`.
;     The files it deletes are the old version's; ours are written right
;     after. A running BirdoVPN is stopped first (BIRDO_STOP_APP_IF_RUNNING),
;     so none of its files is in use.
;   - Windows Installer does not know it: the entry is a leftover that can
;     only fail to uninstall, so only the entry is deleted.
; The entry's UninstallString is never run. Nothing else matches: the key
; must be a {GUID} (a ProductCode), with DisplayName exactly "BirdoVPN",
; Publisher exactly "Birdo VPN" and WindowsInstaller = 1. A 1.0.0 MSI
; (product "Birdo VPN", its own folder) is a different product and is not
; touched. With no such entry (the usual case), nothing happens.
!define BIRDO_UNINSTALL_ROOT "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
!define BIRDO_MSI_ERA_PUBLISHER "Birdo VPN"

Var BirdoMsiEraRemoved

; Stack in: the name of an Uninstall subkey. Stack out: 1 if it is an MSI-era
; BirdoVPN entry, else 0. Reads the 64-bit view, where the x64 MSI registered
; (the template's SetContext has set SetRegView 64 by now).
Function BirdoIsMsiEraEntry
  Exch $0
  Push $1
  Push $2
  StrCpy $2 0
  StrLen $1 $0
  ${If} $1 = 38
    StrCpy $1 $0 1
    ${If} $1 == "{"
      StrCpy $1 $0 1 -1
      ${If} $1 == "}"
        ReadRegStr $1 HKLM "${BIRDO_UNINSTALL_ROOT}\$0" "DisplayName"
        ${If} $1 S== "BirdoVPN"
          ReadRegStr $1 HKLM "${BIRDO_UNINSTALL_ROOT}\$0" "Publisher"
          ${If} $1 S== "${BIRDO_MSI_ERA_PUBLISHER}"
            ReadRegDWORD $1 HKLM "${BIRDO_UNINSTALL_ROOT}\$0" "WindowsInstaller"
            ${If} $1 == 1
              StrCpy $2 1
            ${EndIf}
          ${EndIf}
        ${EndIf}
      ${EndIf}
    ${EndIf}
  ${EndIf}
  StrCpy $0 $2
  Pop $2
  Pop $1
  Exch $0
FunctionEnd

; Stack in: the {ProductCode} key of an MSI-era entry. Stack out: 1 if the
; entry is gone afterwards, else 0.
Function BirdoRemoveMsiEraEntry
  Exch $0
  Push $1
  ; INSTALLSTATE_UNKNOWN (-1): Windows Installer has no such product.
  System::Call 'msi::MsiQueryProductStateW(w r0) i .r1'
  ${If} $1 == -1
    DetailPrint "Removing the leftover Apps & features entry $0 of the old BirdoVPN MSI"
    DeleteRegKey HKLM "${BIRDO_UNINSTALL_ROOT}\$0"
  ${Else}
    DetailPrint "Uninstalling the old BirdoVPN MSI $0 (Windows Installer state $1)"
    ClearErrors
    ExecWait '"$SYSDIR\msiexec.exe" /x $0 /qn /norestart /l*v "$TEMP\BirdoVPN-msi-era-uninstall.log"' $1
    ${If} ${Errors}
      StrCpy $1 "not started"
    ${EndIf}
    DetailPrint "msiexec /x $0: $1 (log: $TEMP\BirdoVPN-msi-era-uninstall.log)"
    ; 3010: done, a reboot completes it (ERROR_SUCCESS_REBOOT_REQUIRED).
    ${If} $1 == 0
    ${OrIf} $1 == 3010
      StrCpy $BirdoMsiEraRemoved 1
    ${EndIf}
  ${EndIf}
  ClearErrors
  ReadRegStr $1 HKLM "${BIRDO_UNINSTALL_ROOT}\$0" "DisplayName"
  ${If} ${Errors}
    StrCpy $0 1
  ${Else}
    StrCpy $0 0
  ${EndIf}
  Pop $1
  Exch $0
FunctionEnd

; Stack in: 0 to count the MSI-era entries, 1 to remove them. Stack out: how
; many there were.
Function BirdoMsiEraEntries
  Exch $R0
  Push $R1
  Push $R2
  Push $R3
  Push $R4
  StrCpy $R1 0
  StrCpy $R3 0
  ${Do}
    EnumRegKey $R2 HKLM "${BIRDO_UNINSTALL_ROOT}" $R1
    ${If} $R2 == ""
      ${ExitDo}
    ${EndIf}
    Push $R2
    Call BirdoIsMsiEraEntry
    Pop $R4
    ${If} $R4 = 1
      IntOp $R3 $R3 + 1
      ${If} $R0 = 1
        Push $R2
        Call BirdoRemoveMsiEraEntry
        Pop $R4
        ; Gone: the next key has moved up to this index.
        ${If} $R4 = 1
          ${Continue}
        ${EndIf}
      ${EndIf}
    ${EndIf}
    IntOp $R1 $R1 + 1
  ${Loop}
  StrCpy $R0 $R3
  Pop $R4
  Pop $R3
  Pop $R2
  Pop $R1
  Exch $R0
FunctionEnd

!macro NSIS_HOOK_PREINSTALL
  ; The literals above must be the template's, or the adoption writes a key
  ; nothing reads: fail the build instead (REVIEW-WIN2-017: the parent key
  ; too, which BirdoForgetAdoptedRecord removes).
  !if "${BIRDO_MANUPRODUCTKEY}" != "${MANUPRODUCTKEY}"
    !error "nsis-hooks.nsh: BIRDO_MANUPRODUCTKEY is not Software\<bundle.publisher>\<productName>"
  !endif
  !if "${BIRDO_MANUKEY}" != "${MANUKEY}"
    !error "nsis-hooks.nsh: BIRDO_MANUKEY is not Software\<bundle.publisher>"
  !endif
  !if "${PRODUCTNAME}" != "BirdoVPN"
    !error "nsis-hooks.nsh: the D8 migration assumes productName BirdoVPN"
  !endif
  !if "${INSTALLMODE}" != "perMachine"
    !error "nsis-hooks.nsh: the machine records are written to HKLM; installMode must be perMachine"
  !endif
  ; The template already created the folder it had chosen (SetOutPath before
  ; this hook); the adoption may move $INSTDIR to the old install's.
  StrCpy $BirdoOutPathBeforeAdoption $INSTDIR
  Call BirdoAdoptLegacyRecord
  SetOutPath $INSTDIR
  ; REVIEW-WIN2-015: a silent upgrade of a custom-folder install left that
  ; first folder behind, empty. RMDir without /r removes it only if it IS
  ; empty, and only now: it was the working directory until SetOutPath.
  ${If} $INSTDIR != $BirdoOutPathBeforeAdoption
    RMDir $BirdoOutPathBeforeAdoption
  ${EndIf}

  ; WIN2-012 (above): an MSI-era install goes before any file of ours is
  ; laid down. When there is none (the usual case), this is a no-op.
  Push 0
  Call BirdoMsiEraEntries
  Pop $0
  ${If} $0 > 0
    ; Its exe sits at our exe's path. Stop it the way the template does right
    ; after this hook, so that msiexec finds nothing in use.
    !insertmacro BIRDO_STOP_APP_IF_RUNNING
    ; Not from inside the folder that the MSI's uninstall may remove.
    SetOutPath $TEMP
    Push 1
    Call BirdoMsiEraEntries
    Pop $0
    SetOutPath $INSTDIR
    ; The MSI took its Start-menu and desktop shortcuts with it. Let the
    ; template re-create them, even on an in-app update (/UPDATE): that is
    ; the template's own rule after a WiX migration.
    ${If} $BirdoMsiEraRemoved = 1
      StrCpy $WixMode 1
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Installed: the record lives under the new publisher. The old one is
  ; MIRRORED, not dropped (REVIEW-WIN2-013): a rollback to 1.4.45 or older —
  ; whose installer reads only that key to find this install for its forced
  ; "uninstall before installing" (downgrades are not allowed in place) —
  ; otherwise ran our uninstaller with an EMPTY `_?=`. Rewritten on every
  ; install, so it follows the folder; the uninstaller drops it. Keep it for
  ; as long as a rollback to a pre-D8 build is supported.
  WriteRegStr HKLM "${BIRDO_LEGACY_MANUPRODUCTKEY}" "" $INSTDIR
  !insertmacro BIRDO_DROP_LEGACY_LANGUAGE
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; REVIEW-WIN2-008: stop a running BirdoVPN FIRST. The template does it only
  ; AFTER this hook, so the reconcile below used to run beside a live
  ; session: it deleted the routes the session had just journaled (the
  ; relay's traffic then fell into the /1 routes and the tunnel died) and
  ; rewrote the journal — and a Cancel on the template's "BirdoVPN is
  ; running" prompt then left that session broken, its routes forgotten.
  ; Stopping the app first leaves only what a stopped app left behind, which
  ; is what the reconcile is for. (The template's own check, after this
  ; hook, then finds nothing.) The template's macro, called exactly as the
  ; template calls it: see BIRDO_STOP_APP_IF_RUNNING.
  !insertmacro BIRDO_STOP_APP_IF_RUNNING

  ; W1-008: put back what a BirdoVPN that was killed rather than quit left
  ; behind — DNS an OLDER version parked on the physical adapters, routes a
  ; crash stranded — BEFORE anything is deleted. The exe is the only program
  ; that can, and $APPDATA\BirdoVPN\dns-restore.json is the only record of the
  ; user's own resolvers; uninstalling first used to strand the machine with
  ; no DNS for good. `--reconcile-and-exit` (main.rs) does that and exits
  ; before any window, tray or single-instance check.
  ;
  ; The uninstaller is elevated (per-machine install), so the
  ; requireAdministrator exe starts without a prompt. The hook and the flag
  ; ship in the same build, so an older uninstaller never runs a newer flag.
  ;
  ; REVIEW-WIN2-019: bounded. An exe that ignores the flag (a stale binary
  ; left by a file error) would start the full app and hold the uninstall
  ; until someone quit it; nsExec gives up after 60 s without output (the
  ; reconcile logs as it goes) and the template's check that follows stops
  ; whatever is still running. A reconcile cut short keeps its record (I5).
  nsExec::Exec /TIMEOUT=60000 '"$INSTDIR\${MAINBINARYNAME}.exe" --reconcile-and-exit'
  Pop $0
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; Remove the launch-at-login task, if the user had it enabled — but not on
  ; an in-place update, which keeps everything (the template's own rule for
  ; the app data). (A GUI upgrade runs the OLD uninstaller without /UPDATE;
  ; the app re-creates the task at its next start, REVIEW-WIN2-011.)
  ${If} $UpdateMode <> 1
    nsExec::Exec 'schtasks /Delete /F /TN "BirdoVPN Launch At Login"'
    Pop $0
  ${EndIf}
  ; Remove the legacy Run-key entry older builds wrote via tauri-plugin-autostart
  ; (it never worked — Windows refuses to launch elevated binaries from Run).
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "BirdoVPN"
  ; D8: the old publisher's record (the mirror NSIS_HOOK_POSTINSTALL keeps).
  !insertmacro BIRDO_DROP_LEGACY_PUBLISHER_RECORD

  ; D-23 (audit 2026-09-29): "Delete the application data".
  ;
  ; Tauri's uninstaller already shows that checkbox on its confirm page and,
  ; when it is ticked, removes $APPDATA\<identifier> and
  ; $LOCALAPPDATA\<identifier> (settings.json, the Xray config, the WebView2
  ; profile holding the consent flag). The client ALSO writes outside those two
  ; folders, so the same tick has to clear these too:
  ;   $APPDATA\BirdoVPN        logs (birdo.log*), dns-restore.json
  ;   $LOCALAPPDATA\BirdoVPN   birdo_pq_v1.bin (the ML-KEM SECRET key), device_id
  ;   $LOCALAPPDATA\Birdo VPN  crash files
  ;   Credential Manager       access/refresh tokens, settings HMAC key,
  ;                            biometric flag (keyring targets "<name>.BirdoVPN")
  ;
  ; Same gate as the template's own deletion: only when the user ticked the box
  ; and never on an in-place update (/UPDATE), which must keep everything.
  ; SetShellVarContext current is repeated so this does not depend on the
  ; template's block having run first. Both variables are declared by Tauri's
  ; installer.nsi, into which this macro is expanded.
  ;
  ; W1-008: the DNS journal survives the deletion when it still exists. The
  ; pre-uninstall reconcile deletes it once everything it describes is back;
  ; one that is left describes resolvers that could NOT be restored, and it is
  ; what lets a reinstall (whose start-up reconcile reads it) or a support
  ; session still put them back. So does a journal the app set aside as
  ; unreadable (`dns-restore.json.corrupt`, kept for support), and the
  ; staging copy (REVIEW-WIN2-018): `dns-restore.json*`. If they cannot be
  ; copied aside, only the logs go — never the record.
  ;
  ; Not removed: the Wintun driver/adapter (shared, system-wide).
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    SetShellVarContext current
    ${If} ${FileExists} "$APPDATA\BirdoVPN\dns-restore.json*"
      RMDir /r "$TEMP\birdo-journal-keep"
      CreateDirectory "$TEMP\birdo-journal-keep"
      ClearErrors
      CopyFiles /SILENT "$APPDATA\BirdoVPN\dns-restore.json*" "$TEMP\birdo-journal-keep"
      ${IfNot} ${Errors}
        RMDir /r "$APPDATA\BirdoVPN"
        CreateDirectory "$APPDATA\BirdoVPN"
        ClearErrors
        CopyFiles /SILENT "$TEMP\birdo-journal-keep\dns-restore.json*" "$APPDATA\BirdoVPN"
        ; A copy back that failed leaves the only copy in %TEMP%: keep it.
        ${IfNot} ${Errors}
          RMDir /r "$TEMP\birdo-journal-keep"
        ${EndIf}
      ${Else}
        RMDir /r "$APPDATA\BirdoVPN\logs"
      ${EndIf}
    ${Else}
      RMDir /r "$APPDATA\BirdoVPN"
    ${EndIf}
    RMDir /r "$LOCALAPPDATA\BirdoVPN"
    RMDir /r "$LOCALAPPDATA\Birdo VPN"
    ; CredDeleteW(target, CRED_TYPE_GENERIC = 1, 0). A missing entry just
    ; returns FALSE; there is nothing to handle.
    System::Call 'advapi32::CredDeleteW(w "access_token.BirdoVPN", i 1, i 0) i .r0'
    System::Call 'advapi32::CredDeleteW(w "refresh_token.BirdoVPN", i 1, i 0) i .r0'
    System::Call 'advapi32::CredDeleteW(w "settings_hmac_key.BirdoVPN", i 1, i 0) i .r0'
    System::Call 'advapi32::CredDeleteW(w "biometric_lock_enabled.BirdoVPN", i 1, i 0) i .r0'
  ${EndIf}
!macroend
