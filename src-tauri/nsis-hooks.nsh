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
!macroend
