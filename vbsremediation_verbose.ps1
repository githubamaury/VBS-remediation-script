Write-Host "`n🧨 VBS Auto-Remediation Script — Verbose Mode"

# --- Memory Integrity ---
Write-Host "`n🔍 Checking Memory Integrity..."
try {
    $memoryIntegrity = Get-CimInstance -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard" -ErrorAction Stop
    if ($memoryIntegrity.SecurityServicesRunning -contains 1) {
        Write-Host "⚠️ Memory Integrity is active — attempting to disable..."
        Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0 -ErrorAction Stop
        Write-Host "✅ HVCI registry key disabled successfully."
    } else {
        Write-Host "✅ Memory Integrity is not active."
    }
} catch {
    Write-Host "❌ Failed to retrieve or disable Memory Integrity: $($_.Exception.Message)"
}

# --- Registry Keys ---
Write-Host "`n🧠 Registry keys — disabling VBS, HVCI, Credential Guard..."

# DeviceGuard root
try {
    $dgRoot = "Registry::HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    if (-not (Test-Path $dgRoot)) {
        New-Item -Path $dgRoot -Force | Out-Null
        Write-Host "✅ Created DeviceGuard root key."
    }
    Set-ItemProperty -Path $dgRoot -Name "EnableVirtualizationBasedSecurity" -Value 0 -ErrorAction Stop
    Set-ItemProperty -Path $dgRoot -Name "RequirePlatformSecurityFeatures" -Value 0 -ErrorAction Stop
    Write-Host "✅ DeviceGuard root values disabled."
} catch {
    Write-Host "❌ Failed to disable DeviceGuard root keys: $($_.Exception.Message)"
}

# HVCI scenario
try {
    $hvciKey = "$dgRoot\Scenarios\HypervisorEnforcedCodeIntegrity"
    if (-not (Test-Path $hvciKey)) {
        New-Item -Path $hvciKey -Force | Out-Null
        Write-Host "✅ Created HVCI scenario key."
    }
    Set-ItemProperty -Path $hvciKey -Name "Enabled" -Value 0 -ErrorAction Stop
    Write-Host "✅ HVCI scenario disabled."
} catch {
    Write-Host "❌ Failed to disable HVCI scenario: $($_.Exception.Message)"
}

# Credential Guard policy
try {
    $cgPolicy = "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    if (-not (Test-Path $cgPolicy)) {
        New-Item -Path $cgPolicy -Force | Out-Null
        Write-Host "✅ Created Credential Guard policy key."
    }
    Set-ItemProperty -Path $cgPolicy -Name "EnableCredentialGuard" -Value 0 -ErrorAction Stop
    Write-Host "✅ Credential Guard policy disabled."
} catch {
    Write-Host "❌ Failed to disable Credential Guard policy: $($_.Exception.Message)"
}

# --- Boot Configuration ---
Write-Host "`n📦 Boot Configuration — checking hypervisor launch..."
try {
    $bcd = bcdedit /enum all | Select-String "hypervisorlaunchtype"
    if ($bcd -match "Auto|On") {
        Write-Host "⚠️ Hypervisor launch is active — disabling..."
        bcdedit /set hypervisorlaunchtype off
        Write-Host "✅ Hypervisor launch disabled via BCD."
    } else {
        Write-Host "✅ Hypervisor launch already disabled."
    }
} catch {
    Write-Host "❌ Failed to check or modify BCD: $($_.Exception.Message)"
}

# --- Defender Tamper Protection ---
Write-Host "`n🛡️ Defender Tamper Protection..."
try {
    $defender = Get-MpComputerStatus
    if ($defender.IsTamperProtected) {
        Write-Host "⚠️ Tamper Protection is enabled — cannot disable via script. Manual action required in Windows Security."
    } else {
        Write-Host "✅ Tamper Protection is not active."
    }
} catch {
    Write-Host "❌ Failed to retrieve Defender status: $($_.Exception.Message)"
}

# --- Hyper-V Platform Features ---
Write-Host "`n🧰 Hyper-V Platform Features..."
$features = @("Microsoft-Hyper-V-All", "HypervisorPlatform", "VirtualMachinePlatform")
foreach ($feature in $features) {
    try {
        $state = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction Stop
        if ($state.State -eq "Enabled") {
            Write-Host "⚠️ $feature is enabled — disabling..."
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop
            Write-Host "✅ $feature disabled."
        } else {
            Write-Host "✅ $feature already disabled."
        }
    } catch {
        Write-Host "❌ Failed to check or disable ${feature}: $($_.Exception.Message)"
    }
}

# --- TPM Status ---
Write-Host "`n🔒 TPM Status..."
try {
    $tpm = Get-WmiObject -Namespace "root\CIMV2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop
    Write-Host "TPM Manufacturer: $($tpm.ManufacturerID)"
    Write-Host "TPM Version: $($tpm.SpecVersion)"
    Write-Host "TPM Enabled: $($tpm.IsEnabled())"
    Write-Host "TPM Activated: $($tpm.IsActivated())"
    Write-Host "TPM Ready: $($tpm.IsReady())"
    Write-Host "⚠️ TPM must be disabled manually in BIOS."
} catch {
    Write-Host "❌ TPM not detected or inaccessible: $($_.Exception.Message)"
}

# --- Secure Boot ---
Write-Host "`n🔐 Secure Boot..."
try {
    $secureBoot = Confirm-SecureBootUEFI
    if ($secureBoot) {
        Write-Host "⚠️ Secure Boot is enabled — must be disabled manually in BIOS."
    } else {
        Write-Host "✅ Secure Boot is disabled."
    }
} catch {
    Write-Host "❌ Unable to determine Secure Boot status: $($_.Exception.Message)"
}

# --- Final Summary ---
Write-Host "`n✅ Remediation complete. Please reboot and recheck VBS status via msinfo32 or systeminfo."
Write-Host "If VBS is still active, remaining triggers may include:"
Write-Host "- Secure Boot or TPM (BIOS-level)"
Write-Host "- Kernel isolation via ELAM or boot drivers"
Write-Host "- UEFI firmware variables enforcing trusted boot path"
Write-Host "- Consider MBR-based reinstall with Legacy Boot for full VBS deactivation"