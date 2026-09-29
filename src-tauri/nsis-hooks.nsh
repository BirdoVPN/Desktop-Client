; NSIS installer hooks for BirdoVPN (wired via bundle.windows.nsis.installerHooks).
;
; The app registers an elevated launch-at-login Scheduled Task
; ("BirdoVPN Launch At Login" — see commands/settings.rs set_autostart_windows)
; because the requireAdministrator exe can never be launched from the HKCU Run
; key. The uninstaller must remove that task, or it lingers pointing at a
; missing exe and fires a silent failure at every logon.

!macro NSIS_HOOK_POSTUNINSTALL
  ; Remove the launch-at-login task, if the user had it enabled.
  nsExec::Exec 'schtasks /Delete /F /TN "BirdoVPN Launch At Login"'
  Pop $0
  ; Remove the legacy Run-key entry older builds wrote via tauri-plugin-autostart
  ; (it never worked — Windows refuses to launch elevated binaries from Run).
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "BirdoVPN"

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
  ; Not removed: the Wintun driver/adapter (shared, system-wide).
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    SetShellVarContext current
    RMDir /r "$APPDATA\BirdoVPN"
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
