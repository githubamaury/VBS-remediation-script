# Mount-And-Configure-ESP-Interactive.ps1
# Safely mounts the EFI System Partition (ESP), allows user to choose drive letter,
# backs up and copies SecConfig.efi, runs BCDEdit setup, and unmounts when done.
# Must be run as Administrator.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "`n=== Mount and Configure EFI System Partition (Interactive Mode) ===`n"

# ------------------------------
# Step 1: Locate the EFI Partition
# ------------------------------
$esp = Get-Partition | Where-Object { $_.GptType -eq '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}' }

if (-not $esp) {
    Write-Host "❌ No EFI System Partition found."
    exit 1
}

# ------------------------------
# Step 2: Ask user for desired drive letter
# ------------------------------
$drive = Read-Host "Enter the drive letter you want to assign to the EFI partition (e.g. W)"
$drive = $drive.TrimEnd(':').ToUpper()

if ($drive.Length -ne 1 -or $drive -notmatch '^[A-Z]$') {
    Write-Host "❌ Invalid drive letter input."
    exit 1
}

# Verify availability
if (Get-Volume -DriveLetter $drive -ErrorAction SilentlyContinue) {
    Write-Host "⚠️  Drive $drive`: is already in use. Please pick another letter."
    exit 1
}

# ------------------------------
# Step 3: Mount the ESP
# ------------------------------
$esp | Set-Partition -NewDriveLetter $drive
Write-Host "✅ EFI System Partition mounted as $drive`:\" -ForegroundColor Green

# ------------------------------
# Step 4: Backup SecConfig.efi
# ------------------------------
$src = "C:\Windows\System32\SecConfig.efi"
$backupDir = "C:\Windows\System32\SecConfig_Backup"
$backupFile = Join-Path $backupDir ("SecConfig_Backup_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".efi")

if (-not (Test-Path $src)) {
    Write-Host "❌ Original SecConfig.efi not found at $src"
    goto Cleanup
}

Write-Host "`nAbout to create a backup of the original SecConfig.efi:"
Write-Host "  From: $src"
Write-Host "  To:   $backupFile"

$confirmBackup = Read-Host "`nType 'Y' to confirm backup"
if ($confirmBackup -ne "Y") {
    Write-Host "⚠️  Backup cancelled by user."
} else {
    New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
    Copy-Item -Path $src -Destination $backupFile -Force
    Write-Host "✅ Backup created successfully: $backupFile" -ForegroundColor Green
}

# ------------------------------
# Step 5: Copy SecConfig.efi to ESP
# ------------------------------
$dst = "$drive`:\EFI\Microsoft\Boot\SecConfig.efi"
Write-Host "`nAbout to copy SecConfig.efi to EFI partition:"
Write-Host "  From: $src"
Write-Host "  To:   $dst"
$confirmCopy = Read-Host "`nType 'Y' to confirm copy"
if ($confirmCopy -ne "Y") {
    Write-Host "❌ Copy cancelled."
    goto Cleanup
}

New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
Copy-Item -Path $src -Destination $dst -Force
Write-Host "✅ File copied successfully to $dst" -ForegroundColor Green

# ------------------------------
# Step 6: Configure BCD Entries (Safe & Dynamic)
# ------------------------------
Write-Host "`n=== Configuring BCD Entries ===`n"

$bcdId = "{0cb3b571-2f2e-4343-a879-d86a476d7215}"

# Check if entry already exists
$bcdExists = bcdedit /enum all | Select-String -Quiet $bcdId

if (-not $bcdExists) {
    Write-Host "Creating new BCD entry $bcdId ..."
    bcdedit /create $bcdId /d "DebugTool" /application osloader
} else {
    Write-Host "⚠️  BCD entry $bcdId already exists, skipping create."
}

# Apply settings dynamically
bcdedit /set "$bcdId" path "\EFI\Microsoft\Boot\SecConfig.efi"
bcdedit /set "{bootmgr}" bootsequence "$bcdId"
bcdedit /set "$bcdId" loadoptions "DISABLE-LSA-ISO,DISABLE-VBS"
bcdedit /set "$bcdId" device partition=$drive`:
bcdedit /set vsmlaunchtype off

Write-Host "`nUnmounting $drive`: ..."
mountvol "$drive`:" /d

Write-Host "`n✅ BCD configuration complete." -ForegroundColor Green
