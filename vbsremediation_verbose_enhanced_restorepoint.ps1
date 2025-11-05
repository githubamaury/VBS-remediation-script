Write-Host "`n🧨 VBS Auto-Remediation Script — Full Verbose Mode"

Write-Host "`n🛡️ Creating System Restore Point..."
try {
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "Pre-VBS Remediation Restore Point" -RestorePointType "MODIFY_SETTINGS"
    Write-Host "✅ System Restore Point created successfully."
} catch {
    Write-Host "❌ Failed to create restore point: $($_.Exception.Message)"
    Write-Host "⚠️ You may need to run this script as Administrator and ensure System Protection is enabled."
}

# System profiling

Write-Host "`n🧠 Installed Windows Version:"
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    Write-Host "Edition: $($os.Caption)"
    Write-Host "Version: $($os.Version)"
    Write-Host "Build Number: $($os.BuildNumber)"
    Write-Host "Architecture: $($os.OSArchitecture)"
} catch {
    Write-Host "❌ Failed to retrieve Windows version: $($_.Exception.Message)"
}

Write-Host "`n🧪 VMware Workstation Pro Detection (25H2-aware):"

# Try legacy registry path
$legacyKey = "HKLM:\SOFTWARE\VMware, Inc.\VMware Workstation"
$altKey = "HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation"

function Get-VMwareVersionFromKey($keyPath) {
    if (Test-Path $keyPath) {
        try {
            $version = Get-ItemProperty -Path $keyPath -Name "ProductVersion" -ErrorAction Stop
            return $version.ProductVersion
        } catch {
            return $null
        }
    }
    return $null
}

$vmVersion = Get-VMwareVersionFromKey $legacyKey
if (-not $vmVersion) {
    $vmVersion = Get-VMwareVersionFromKey $altKey
}

if ($vmVersion) {
    Write-Host "✅ VMware Workstation Pro Version Detected: $vmVersion"
} else {
    # Fallback: check install path
    $installPath = "C:\Program Files (x86)\VMware\VMware Workstation"
    $exePath = Join-Path $installPath "vmware.exe"
    if (Test-Path $exePath) {
        try {
            $fileVersion = (Get-Item $exePath).VersionInfo.ProductVersion
            Write-Host "✅ VMware Workstation Pro detected via executable: $fileVersion"
        } catch {
            Write-Host "⚠️ VMware executable found but version info unavailable."
        }
    } else {
        Write-Host "❌ VMware Workstation Pro not detected in registry or default install path."
    }
}

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

# Group Policy override
try {
    $gpKey = "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    if (-not (Test-Path $gpKey)) {
        New-Item -Path $gpKey -Force | Out-Null
        Write-Host "✅ Created System policy key."
    }
    Set-ItemProperty -Path $gpKey -Name "EnableVirtualizationBasedSecurity" -Value 0 -ErrorAction Stop
    Write-Host "✅ VBS Group Policy override applied."
} catch {
    Write-Host "❌ Failed to apply VBS Group Policy override: $($_.Exception.Message)"
}

# Core Isolation UI flag
try {
    Set-ItemProperty -Path $hvciKey -Name "WasEnabledBy" -Value 0 -ErrorAction SilentlyContinue
    Write-Host "✅ Core Isolation UI flag reset."
} catch {
    Write-Host "❌ Failed to reset Core Isolation UI flag: $($_.Exception.Message)"
}

# ELAM Driver Policy
Write-Host "`n🧬 ELAM Driver Policy..."
try {
    $elamKey = "Registry::HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
    if (-not (Test-Path $elamKey)) {
        New-Item -Path $elamKey -Force | Out-Null
        Write-Host "✅ Created ELAM policy key."
    }
    Set-ItemProperty -Path $elamKey -Name "DriverLoadPolicy" -Value 8 -ErrorAction Stop
    Write-Host "✅ ELAM DriverLoadPolicy set to '8' (All drivers allowed)."
} catch {
    Write-Host "❌ Failed to configure ELAM policy: $($_.Exception.Message)"
}

# Cleanup audit flags
Write-Host "`n🧼 Cleanup — removing VBS audit traces..."
try {
    Remove-Item -Path "$hvciKey\AuditFlags" -Force -ErrorAction SilentlyContinue
    Write-Host "✅ VBS audit flags removed."
} catch {
    Write-Host "⚠️ Audit flags not present or already removed."
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
    if ($null -ne $tpm) {
        Write-Host "TPM Manufacturer: $($tpm.ManufacturerID)"
        Write-Host "TPM Version: $($tpm.SpecVersion)"
        try {
            Write-Host "TPM Enabled: $($tpm.IsEnabled())"
            Write-Host "TPM Activated: $($tpm.IsActivated())"
            Write-Host "TPM Ready: $($tpm.IsReady())"
        } catch {
            Write-Host "⚠️ TPM methods not available — limited status reported."
        }
        Write-Host "⚠️ TPM must be disabled manually in BIOS."
    } else {
        Write-Host "⚠️ TPM not present on this system."
    }
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

# --- Additional Policy Keys ---
Write-Host "`n🧩 Additional Registry Policies — LSA hardening..."
try {
    $lsaKey = "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    if (-not (Test-Path $lsaKey)) {
        New-Item -Path $lsaKey -Force | Out-Null
        Write-Host "✅ Created LSA policy key."
    }
    Set-ItemProperty -Path $lsaKey -Name "LsaCfgFlags" -Value 0 -ErrorAction Stop
    Write-Host "✅ LsaCfgFlags set to 0 (Credential Guard disabled)."
} catch {
    Write-Host "❌ Failed to configure LSA policy: $($_.Exception.Message)"
}

# --- Audit: AvailableSecurityProperties ---
Write-Host "`n🧪 Auditing AvailableSecurityProperties from Win32_DeviceGuard..."
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction Stop
    if ($dg -and $dg.AvailableSecurityProperties) {
        Write-Host "🔍 Detected AvailableSecurityProperties:" -ForegroundColor Yellow
        foreach ($p in $dg.AvailableSecurityProperties) {
            switch ($p) {
                0 { Write-Host "  [0] Base Virtualization Support" }
                1 { Write-Host "  [1] Secure Boot" }
                2 { Write-Host "  [2] DMA Protection" }
                3 { Write-Host "  [3] UEFI Code Readonly" }
                4 { Write-Host "  [4] SMM Security Mitigations 1.0" }
                5 { Write-Host "  [5] Mode Based Execution Control (MBEC)" }
                default { Write-Host "  [$p] Unknown Property" }
            }
        }
    } else {
        Write-Host "✅ No AvailableSecurityProperties reported." -ForegroundColor Green
    }
} catch {
    Write-Host "⚠️ Win32_DeviceGuard class not available — skipping capability audit." -ForegroundColor DarkYellow
}

# --- Final Summary ---
Write-Host "`n✅ Remediation complete. Please reboot and recheck VBS status via msinfo32 or systeminfo."
Write-Host "If VBS is still active, remaining triggers may include:"
Write-Host "- Secure Boot or TPM (BIOS-level)"
Write-Host "- Kernel isolation via ELAM or boot drivers"
Write-Host "- UEFI firmware variables enforcing trusted boot path"
Write-Host "- Consider MBR-based reinstall with Legacy Boot for full VBS deactivation"