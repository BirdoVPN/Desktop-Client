; NSIS installer hooks for BirdoVPN (wired via bundle.windows.nsis.installerHooks).
;
; The app registers an elevated launch-at-login Scheduled Task
; ("BirdoVPN Launch At Login" — see commands/settings.rs set_autostart_windows)
; because the requireAdministrator exe can never be launched from the HKCU Run
; key. The uninstaller must remove that task, or it lingers pointing at a
; missing exe and fires a silent failure at every logon.
;
; This file is !included near the top of Tauri's installer.nsi (tauri-bundler,
; @tauri-apps/cli 2.11.4), BEFORE the template defines MANUFACTURER,
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
; So the old record is adopted before any page reads it, and dropped once the
; install has succeeded. User data never depended on the publisher: it lives
; under the bundle identifier and the fixed BirdoVPN names below.
!define BIRDO_MANUPRODUCTKEY "Software\Birdo Networks Ltd\BirdoVPN"
!define BIRDO_LEGACY_MANUKEY "Software\Birdo VPN"
!define BIRDO_LEGACY_MANUPRODUCTKEY "${BIRDO_LEGACY_MANUKEY}\BirdoVPN"

Var BirdoAdoptedLegacyRecord

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

; Cancelled before installing: leave the registry as the old install had it.
Function BirdoForgetAdoptedRecord
  ${If} $BirdoAdoptedLegacyRecord == 1
    DeleteRegKey SHCTX "${BIRDO_MANUPRODUCTKEY}"
    DeleteRegKey /ifempty SHCTX "Software\Birdo Networks Ltd"
  ${EndIf}
FunctionEnd

; Modern UI calls these from the .onGUIInit and .onUserAbort it generates
; (the template defines neither name itself).
!define MUI_CUSTOMFUNCTION_GUIINIT BirdoAdoptLegacyRecord
!define MUI_CUSTOMFUNCTION_ABORT BirdoForgetAdoptedRecord

; The old publisher's record, and the installer language MUI keeps beside it
; for the user who ran the installer. Only the "BirdoVPN" product key: a 1.0.0
; install (product "Birdo VPN") has a record of its own under the same parent.
!macro BIRDO_DROP_LEGACY_PUBLISHER_RECORD
  DeleteRegKey SHCTX "${BIRDO_LEGACY_MANUPRODUCTKEY}"
  DeleteRegKey /ifempty SHCTX "${BIRDO_LEGACY_MANUKEY}"
  DeleteRegValue HKCU "${BIRDO_LEGACY_MANUPRODUCTKEY}" "Installer Language"
  DeleteRegKey /ifempty HKCU "${BIRDO_LEGACY_MANUPRODUCTKEY}"
  DeleteRegKey /ifempty HKCU "${BIRDO_LEGACY_MANUKEY}"
!macroend

!macro NSIS_HOOK_PREINSTALL
  ; The literals above must be the template's, or the adoption writes a key
  ; nothing reads: fail the build instead.
  !if "${BIRDO_MANUPRODUCTKEY}" != "${MANUPRODUCTKEY}"
    !error "nsis-hooks.nsh: BIRDO_MANUPRODUCTKEY is not Software\<bundle.publisher>\<productName>"
  !endif
  !if "${PRODUCTNAME}" != "BirdoVPN"
    !error "nsis-hooks.nsh: the D8 migration assumes productName BirdoVPN"
  !endif
  Call BirdoAdoptLegacyRecord
  ; The template set the output path before this hook; the adoption may have
  ; moved $INSTDIR to the old install's folder.
  SetOutPath $INSTDIR
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Installed: the record lives under the new publisher now.
  !insertmacro BIRDO_DROP_LEGACY_PUBLISHER_RECORD
!macroend

!macro NSIS_HOOK_PREUNINSTALL
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
  ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --reconcile-and-exit' $0
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; Remove the launch-at-login task, if the user had it enabled.
  nsExec::Exec 'schtasks /Delete /F /TN "BirdoVPN Launch At Login"'
  Pop $0
  ; Remove the legacy Run-key entry older builds wrote via tauri-plugin-autostart
  ; (it never worked — Windows refuses to launch elevated binaries from Run).
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "BirdoVPN"
  ; D8: an old-publisher record the install never adopted (it is dropped on
  ; every successful install, so normally there is none left to find).
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
  ; W1-008: dns-restore.json survives the deletion when it still exists. The
  ; pre-uninstall reconcile deletes it once everything it describes is back;
  ; one that is left describes resolvers that could NOT be restored, and it is
  ; what lets a reinstall (whose start-up reconcile reads it) or a support
  ; session still put them back.
  ;
  ; Not removed: the Wintun driver/adapter (shared, system-wide).
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    SetShellVarContext current
    ${If} ${FileExists} "$APPDATA\BirdoVPN\dns-restore.json"
      CopyFiles /SILENT "$APPDATA\BirdoVPN\dns-restore.json" "$TEMP\birdo-dns-restore.json"
      RMDir /r "$APPDATA\BirdoVPN"
      CreateDirectory "$APPDATA\BirdoVPN"
      CopyFiles /SILENT "$TEMP\birdo-dns-restore.json" "$APPDATA\BirdoVPN\dns-restore.json"
      Delete "$TEMP\birdo-dns-restore.json"
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
