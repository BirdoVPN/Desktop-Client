//! Biometric authentication support.
//!
//! - Windows: Windows Hello via UserConsentVerifier
//! - macOS: Touch ID via LocalAuthentication.framework (osascript bridge)
//!
//! Provides biometric lock functionality matching Android's BiometricPrompt.

use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

#[derive(Debug, Serialize, Deserialize)]
pub struct BiometricStatus {
    pub available: bool,
    pub enabled: bool,
    pub method: String, // "windows_hello", "touch_id", "none"
}

/// Check if biometric authentication is available on this device.
#[tauri::command]
pub async fn check_biometric_available() -> Result<BiometricStatus, String> {
    #[cfg(windows)]
    {
        let available = is_windows_hello_available();
        let enabled = keyring::Entry::new("BirdoVPN", "biometric_lock_enabled")
            .ok()
            .and_then(|e| e.get_password().ok())
            .unwrap_or_default()
            == "true";

        Ok(BiometricStatus {
            available,
            enabled,
            method: if available {
                "windows_hello".to_string()
            } else {
                "none".to_string()
            },
        })
    }
    #[cfg(target_os = "macos")]
    {
        let available = is_touch_id_available();
        let enabled = keyring::Entry::new("BirdoVPN", "biometric_lock_enabled")
            .ok()
            .and_then(|e| e.get_password().ok())
            .unwrap_or_default()
            == "true";

        Ok(BiometricStatus {
            available,
            enabled,
            method: if available {
                "touch_id".to_string()
            } else {
                "none".to_string()
            },
        })
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Ok(BiometricStatus {
            available: false,
            enabled: false,
            method: "none".to_string(),
        })
    }
}

/// Enable or disable biometric lock.
#[tauri::command]
pub async fn set_biometric_enabled(enabled: bool) -> Result<(), String> {
    let entry = keyring::Entry::new("BirdoVPN", "biometric_lock_enabled")
        .map_err(|e| format!("Failed to create keyring entry: {e}"))?;
    entry
        .set_password(if enabled { "true" } else { "false" })
        .map_err(|e| format!("Failed to store biometric setting: {e}"))?;

    if enabled {
        info!("Biometric lock enabled");
    } else {
        info!("Biometric lock disabled");
    }
    Ok(())
}

/// Prompt for biometric authentication.
/// Returns Ok(true) if authenticated, Ok(false) if cancelled.
#[tauri::command]
pub async fn authenticate_biometric(_reason: String) -> Result<bool, String> {
    #[cfg(windows)]
    {
        use std::process::Command;

        // SEC: Use hardcoded verification message to prevent PowerShell injection.
        // The `reason` parameter from the frontend is intentionally ignored —
        // user-supplied strings must never be interpolated into shell scripts.
        let safe_reason = "Birdo VPN requires your identity";

        // Use PowerShell to invoke Windows Hello via UserConsentVerifier
        // This triggers the Windows Hello prompt (fingerprint, face, PIN)
        let script = format!(
            r#"
            Add-Type -AssemblyName System.Runtime.WindowsRuntime
            $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {{ $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' }})[0]
            Function Await($WinRtTask, $ResultType) {{
                $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
                $netTask = $asTask.Invoke($null, @($WinRtTask))
                $netTask.Wait(-1) | Out-Null
                $netTask.Result
            }}
            $ucvType = [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
            $available = Await ($ucvType::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])
            if ($available -ne 'Available') {{
                Write-Output 'UNAVAILABLE'
                exit
            }}
            $result = Await ($ucvType::RequestVerificationAsync('{safe_reason}')) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])
            if ($result -eq 'Verified') {{ Write-Output 'VERIFIED' }} else {{ Write-Output 'DENIED' }}
            "#
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .map_err(|e| format!("Failed to launch Windows Hello: {e}"))?;

        let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
        match result.as_str() {
            "VERIFIED" => {
                info!("Biometric authentication successful");
                Ok(true)
            }
            "DENIED" => {
                warn!("Biometric authentication denied/cancelled");
                Ok(false)
            }
            "UNAVAILABLE" => {
                warn!("Windows Hello not available");
                Err("Windows Hello is not configured on this device".to_string())
            }
            other => {
                error!("Unexpected Windows Hello result: {}", other);
                Err(format!("Authentication failed: {other}"))
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;

        // SEC: Use hardcoded reason string — never interpolate user input into osascript.
        // Uses `osascript` to call LocalAuthentication framework via AppleScript bridge.
        // This triggers the Touch ID / password prompt.
        let script = r#"
            use framework "LocalAuthentication"
            set laContext to current application's LAContext's alloc()'s init()
            set {canEvaluate, theError} to laContext's canEvaluatePolicy:1 |error|:(reference)
            if canEvaluate as boolean is false then
                return "UNAVAILABLE"
            end if
            set {authResult, theError} to laContext's evaluatePolicy:1 localizedReason:"Birdo VPN requires your identity" |error|:(reference)
            if authResult as boolean then
                return "VERIFIED"
            else
                return "DENIED"
            end if
        "#;

        let output = Command::new("osascript")
            .args(["-l", "AppleScript", "-e", script])
            .output()
            .map_err(|e| format!("Failed to launch Touch ID: {e}"))?;

        let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
        match result.as_str() {
            "VERIFIED" => {
                info!("Touch ID authentication successful");
                Ok(true)
            }
            "DENIED" => {
                warn!("Touch ID authentication denied/cancelled");
                Ok(false)
            }
            "UNAVAILABLE" => {
                warn!("Touch ID not available");
                Err("Touch ID is not configured on this device".to_string())
            }
            other => {
                error!("Unexpected Touch ID result: {}", other);
                Err(format!("Authentication failed: {other}"))
            }
        }
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err("Biometric authentication not supported on this platform".to_string())
    }
}

#[cfg(windows)]
fn is_windows_hello_available() -> bool {
    use std::process::Command;
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r#"
            Add-Type -AssemblyName System.Runtime.WindowsRuntime
            $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
            Function Await($WinRtTask, $ResultType) {
                $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
                $netTask = $asTask.Invoke($null, @($WinRtTask))
                $netTask.Wait(-1) | Out-Null
                $netTask.Result
            }
            $ucvType = [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
            $result = Await ($ucvType::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])
            Write-Output $result
            "#,
        ])
        .output();

    match output {
        Ok(o) => {
            let result = String::from_utf8_lossy(&o.stdout).trim().to_string();
            result == "Available"
        }
        Err(_) => false,
    }
}

/// Check if Touch ID is available on this Mac.
#[cfg(target_os = "macos")]
fn is_touch_id_available() -> bool {
    use std::process::Command;

    // Use osascript to check LocalAuthentication canEvaluatePolicy
    let script = r#"
        use framework "LocalAuthentication"
        set laContext to current application's LAContext's alloc()'s init()
        set {canEvaluate, theError} to laContext's canEvaluatePolicy:1 |error|:(reference)
        if canEvaluate as boolean then
            return "Available"
        else
            return "Unavailable"
        end if
    "#;

    let output = Command::new("osascript")
        .args(["-l", "AppleScript", "-e", script])
        .output();

    match output {
        Ok(o) => {
            let result = String::from_utf8_lossy(&o.stdout).trim().to_string();
            result == "Available"
        }
        Err(_) => false,
    }
}
