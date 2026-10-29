$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# sentinel-srp-audit.ps1 — Phase 1: baseline all executables for SRP allowlisting.
# Run this BEFORE sentinel-srp-enforce.ps1. Scans running processes, installed apps,
# AppX packages, service images, and all .exe/.dll/.scr/.com under standard directories.
# Output: C:\ProgramData\SentinelRemoteAssist\srp-baseline.json
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File sentinel-srp-audit.ps1
#   powershell -ExecutionPolicy Bypass -File sentinel-srp-audit.ps1 -BaselinePath "C:\Custom\path.json"

param(
    [string]$BaselinePath = "C:\ProgramData\SentinelRemoteAssist\srp-baseline.json"
)

$markerDir = Split-Path $BaselinePath -Parent
if (-not (Test-Path $markerDir)) { New-Item -Path $markerDir -ItemType Directory -Force | Out-Null }

$hashes = @{}
$allPaths = @()
$errors = @()

function Add-Hash($path) {
    if (-not $path -or -not (Test-Path $path)) { return }
    try {
        $path = (Resolve-Path $path).Path
        if ($hashes.ContainsKey($path)) { return }
        $hash = Get-FileHash -Path $path -Algorithm SHA1
        $hash256 = Get-FileHash -Path $path -Algorithm SHA256
        $size = (Get-Item $path).Length
        $hashes[$path] = @{
            sha1 = $hash.Hash.ToLower()
            sha256 = $hash256.Hash.ToLower()
            size = $size
        }
        $allPaths += $path
    } catch {
        $errors += "hash: $path — $($_.Exception.Message)"
    }
}

function Scan-Directory($dir, $pattern) {
    if (-not (Test-Path $dir)) { return }
    try {
        Get-ChildItem -Path $dir -Filter $pattern -Recurse -ErrorAction SilentlyContinue -Force |
            Where-Object { -not $_.PsIsContainer } |
            ForEach-Object { Add-Hash $_.FullName }
    } catch {
        $errors += "scan: $dir\$pattern — $($_.Exception.Message)"
    }
}

Write-Host "=== SentinelMDM SRP Audit Phase 1 ==="
Write-Host "Baseline: $BaselinePath"

# ── 1. Running processes ─────────────────────────────────────────────────────
Write-Host "[1/7] Enumerating running processes..."
Get-Process | Where-Object { $_.Path } | ForEach-Object { Add-Hash $_.Path }

# ── 2. Services ──────────────────────────────────────────────────────────────
Write-Host "[2/7] Enumerating services..."
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.PathName } |
    ForEach-Object {
        $path = ($_.PathName -split '"' | Where-Object { $_ -and $_ -notmatch '^/' })[0]
        if (-not $path) { $path = ($_.PathName -split ' ')[0] }
        if ($path) { Add-Hash $path.Trim() }
    }

# ── 3. Installed software (registry Uninstall keys) ──────────────────────────
Write-Host "[3/7] Enumerating installed software from registry..."
$uninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach ($regPath in $uninstallPaths) {
    Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -or $_.InstallLocation } |
        ForEach-Object {
            $loc = $_.InstallLocation
            if ($loc -and (Test-Path $loc)) {
                Scan-Directory $loc '*.exe'
                Scan-Directory $loc '*.dll'
            }
        }
}

# ── 4. AppX packages ─────────────────────────────────────────────────────────
Write-Host "[4/7] Enumerating AppX packages..."
Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
    ForEach-Object { $_.InstallLocation } |
    Where-Object { $_ -and (Test-Path $_) } |
    ForEach-Object { Scan-Directory $_ '*.exe'; Scan-Directory $_ '*.dll' }

# ── 5. Well-known directories — recursive scan ───────────────────────────────
Write-Host "[5/7] Scanning well-known directories (including all user profiles)..."
$scanDirs = @(
    "$env:SystemRoot\System32",
    "$env:SystemRoot\SysWOW64",
    "$env:ProgramFiles",
    "${env:ProgramFiles(x86)}",
    "$env:ProgramData",
    "$env:LOCALAPPDATA",
    "$env:SystemDrive\Users"
)
foreach ($dir in $scanDirs) {
    if (Test-Path $dir) {
        Write-Host "  Scanning $dir ..."
        Scan-Directory $dir '*.exe'
        Scan-Directory $dir '*.dll'
        Scan-Directory $dir '*.scr'
        Scan-Directory $dir '*.com'
    }
}

# ── 6. Start Menu / known user-scoped executable paths ───────────────────────
Write-Host "[6/7] Scanning Start Menu and user-scoped paths..."
$userPaths = @(
    [Environment]::GetFolderPath('CommonStartMenu'),
    [Environment]::GetFolderPath('StartMenu'),
    [Environment]::GetFolderPath('CommonDesktopDirectory'),
    [Environment]::GetFolderPath('DesktopDirectory')
)
foreach ($dir in $userPaths) {
    if (Test-Path $dir) { Scan-Directory $dir '*.lnk' }
}
# Resolve all .lnk targets
Get-ChildItem -Path $userPaths -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($_.FullName)
            if ($shortcut.TargetPath) { Add-Hash $shortcut.TargetPath }
        } catch { }
    }

# ── 7. Certificate info for all hashed files ─────────────────────────────────
Write-Host "[7/7] Collecting Authenticode signing info..."
$certInfo = @{}
$signedCount = 0
foreach ($path in $allPaths) {
    try {
        $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
        if ($sig -and $sig.SignerCertificate) {
            $certInfo[$path] = @{
                subject      = $sig.SignerCertificate.Subject
                issuer       = $sig.SignerCertificate.Issuer
                thumbprint   = $sig.SignerCertificate.Thumbprint
                serial       = $sig.SignerCertificate.SerialNumber
                notAfter     = $sig.SignerCertificate.NotAfter.ToString('o')
            }
            $signedCount++
        }
    } catch { }
}

# ── 8. Previous allowlist (from last SRP deploy) ────────────────────────────
Write-Host "[8/8] Reading previous SRP allowlist and blocked events..."
$previousAllowlist = @()
$approvedFile = "C:\ProgramData\SentinelRemoteAssist\srp-approved.json"
if (Test-Path $approvedFile) {
    try {
        $previousAllowlist = (Get-Content $approvedFile -Raw -ErrorAction Stop) | ConvertFrom-Json
    } catch { }
}

# ── 9. SRP block events from Application event log (Event ID 865 = blocked, 866 = would-block) ──
$blockedEvents = @()
try {
    $events = Get-WinEvent -LogName "Application" -FilterXPath "*[System[(EventID=865 or EventID=866)]]" -MaxEvents 100 -ErrorAction SilentlyContinue |
        Sort-Object TimeCreated -Descending
    foreach ($event in $events) {
        $path = ""
        $msg = $event.Message
        # Parse path from message — typically after "Software:" or within the description
        if ($msg -match '(?im)Software:\s*(.+?)(?:\r?\n|$)') { $path = $matches[1].Trim() }
        elseif ($msg -match '(?im)Path:\s*(.+?)(?:\r?\n|$)') { $path = $matches[1].Trim() }
        elseif ($msg -match '(?im)([A-Z]:\\.+?\.\w{3})') { $path = $matches[1] }
        $blockedEvents += @{
            timestamp = $event.TimeCreated.ToString('o')
            eventId   = $event.Id
            path      = $path
            message   = $msg -replace '"', "'" -replace "`r`n", " " -replace "`n", " "
        }
    }
} catch { }

# ── Build baseline ───────────────────────────────────────────────────────────
Write-Host "Building baseline..."
$baseline = @{
    generatedAt = (Get-Date).ToString('o')
    hostname    = $env:COMPUTERNAME
    osVersion   = (Get-CimInstance Win32_OperatingSystem).Caption
    totalFiles  = $hashes.Count
    signedFiles = $signedCount
    files       = @($allPaths | ForEach-Object {
        $h = $hashes[$_]
        @{
            path   = $_
            sha1   = $h.sha1
            sha256 = $h.sha256
            size   = $h.size
            cert   = $certInfo[$_]
        }
    })
    previousAllowlist = @($previousAllowlist)
    blockedEvents     = @($blockedEvents)
    scanErrors  = $errors
}

$json = $baseline | ConvertTo-Json -Depth 4 -Compress
[System.IO.File]::WriteAllText($BaselinePath, $json, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "=== Audit Complete ==="
Write-Host "  Files hashed:       $($hashes.Count)"
Write-Host "  Signed files:       $signedCount"
Write-Host "  Previous approved:  $($previousAllowlist.Count)"
Write-Host "  Blocked attempts:   $($blockedEvents.Count)"
Write-Host "  Scan errors:        $($errors.Count)"
Write-Host "  Baseline:           $BaselinePath"
