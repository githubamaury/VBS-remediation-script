# 🛡️ VBS Remediation Reversal Script — Safe Restore Mode
Write-Host "`n🔄 Starting restoration of VBS-related settings..."

function Ensure-KeyAndSetValue {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value
    )
    $regPath = "Registry::$Path"
    if (-not (Test-Path $regPath)) {
        try {
            New-Item -Path $regPath -Force | Out-Null
            Write-Host "✅ Created missing key: $regPath"
        } catch {
            Write-Host "❌ Failed to create key:" , $regPath , $_.Exception.Message
            return
        }
    }
    try {
        Set-ItemProperty -Path $regPath -Name $Name -Value $Value -ErrorAction Stop
        Write-Host "🔄 Restored $Name to $Value in $regPath"
    } catch {
        Write-Host "❌ Failed to set $Name in ${regPath}:" , $_.Exception.Message
    }
}

# --- Registry Restorations ---
Ensure-KeyAndSetValue "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled" 1
Ensure-KeyAndSetValue "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity" 1
Ensure-KeyAndSetValue "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "RequirePlatformSecurityFeatures" 1
Ensure-KeyAndSetValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LsaCfgFlags" 1
Ensure-KeyAndSetValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "EnableCredentialGuard" 1
Ensure-KeyAndSetValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "EnableVirtualizationBasedSecurity" 1
Ensure-KeyAndSetValue "HKLM\SYSTEM\CurrentControlSet\Control" "HypervisorLaunchType" "Auto"
Ensure-KeyAndSetValue "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State" "UEFISecureBootEnabled" 1
Ensure-KeyAndSetValue "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy" 3

# --- BCD Boot Configuration ---
Write-Host "`n📦 Restoring BCD hypervisor launch setting..."
try {
    bcdedit /set hypervisorlaunchtype auto
    Write-Host "✅ BCD hypervisorlaunchtype set to auto."
} catch {
    Write-Host "❌ Failed to update BCD:" , $_.Exception.Message
}

# --- Optional Features ---
Write-Host "`n🧰 Re-enabling Hyper-V platform features..."
$features = @("Microsoft-Hyper-V-All", "HypervisorPlatform", "VirtualMachinePlatform")
foreach ($feature in $features) {
    try {
        $state = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction Stop
        if ($state.State -ne "Enabled") {
            Enable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop
            Write-Host "✅ $feature re-enabled."
        } else {
            Write-Host "✅ $feature already enabled."
        }
    } catch {
        Write-Host "❌ Failed to enable ${feature}:" , $_.Exception.Message
    }
}

Write-Host "`n✅ Restoration complete. A reboot is recommended to apply all changes."