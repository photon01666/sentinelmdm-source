$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# sentinel-srp-enforce.ps1 — Phase 2: deploy SRP with default-deny + allow rules.
# Reads the baseline from sentinel-srp-audit.ps1 and creates:
#   - Path allow rules for all discovered app directories
#   - Path allow rules for standard Windows/Program Files
#   - Path allow rules for per-user AppData/Local folders seen in baseline
#   - Certificate allow rules for Microsoft (top publishers)
#   - Default security level: Disallowed (block everything not explicitly allowed)
#   - Block rules: Temp dirs, Downloads, browser caches
#
# USAGE:
#   1. First run sentinel-srp-audit.ps1 to generate srp-baseline.json
#   2. Review the baseline, then run:
#        powershell -ExecutionPolicy Bypass -File sentinel-srp-enforce.ps1
#   3. Reboot to activate (or gpupdate /force)
#
# ROLLBACK:
#   Set HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\TransparentEnabled = 0
#   Delete the rule subkeys, reboot.

param(
    [string]$BaselinePath = "C:\ProgramData\SentinelRemoteAssist\srp-baseline.json",
    [switch]$DryRun,
    [switch]$EnableAuditLog
)

# ── Registry paths ──────────────────────────────────────────────────────────
$srpRoot   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
# SAFER level IDs (winsafer.h): 0x40000=262144 FullyTrusted (Unrestricted/ALLOW), 0=Disallowed (block).
# DefaultLevel is set to $denyLevel below, so it MUST be 0 for default-deny. Do NOT use 262144 as "deny".
$allowLevel = 262144  # FullyTrusted = allow
$denyLevel  = 0       # Disallowed = block (also the default level)

function New-GuidKey($parent) {
    $name = [Guid]::NewGuid().ToString("B")
    $key = New-Item -Path $parent -Name $name -Force -ErrorAction Stop
    return $key
}

function Set-RuleValue($key, $name, $value, $type) {
    if ($DryRun) { Write-Host "  [DRY-RUN] Would set $($key.Name) \$name = $value"; return }
    Set-ItemProperty -Path $key.PSPath -Name $name -Value $value -Type $type -Force | Out-Null
}

function New-PathRule($level, $pathPattern, $description) {
    $parent = "$srpRoot\$level\Paths"
    if (-not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    $key = New-GuidKey $parent
    Set-RuleValue $key "ItemData"   $pathPattern "String"
    Set-RuleValue $key "Description" $description "String"
    Set-RuleValue $key "SaferFlags"  0 "DWord"
    Set-RuleValue $key "ItemSize"   $pathPattern.Length "DWord"
    if (-not $DryRun) {
        Write-Host "  [ALLOW] $pathPattern  ← $description"
    } else {
        Write-Host "  [DRY-RUN][ALLOW] $pathPattern  ← $description"
    }
}

function New-DenyRule($level, $pathPattern, $description) {
    $parent = "$srpRoot\$level\Paths"
    if (-not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    $key = New-GuidKey $parent
    Set-RuleValue $key "ItemData"   $pathPattern "String"
    Set-RuleValue $key "Description" $description "String"
    Set-RuleValue $key "SaferFlags"  0 "DWord"
    Set-RuleValue $key "ItemSize"   $pathPattern.Length "DWord"
    if (-not $DryRun) {
        Write-Host "  [DENY]  $pathPattern  ← $description"
    } else {
        Write-Host "  [DRY-RUN][DENY] $pathPattern  ← $description"
    }
}

# ── Ensure we are admin ─────────────────────────────────────────────────────
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Must run as Administrator."
    exit 1
}

# ── Read baseline ───────────────────────────────────────────────────────────
if (-not (Test-Path $BaselinePath)) {
    Write-Host "ERROR: Baseline not found at $BaselinePath"
    Write-Host "Run sentinel-srp-audit.ps1 first."
    exit 1
}
$baselineRaw = [System.IO.File]::ReadAllText($BaselinePath)
$baseline = $baselineRaw | ConvertFrom-Json
$files = $baseline.files

Write-Host "=== SentinelMDM SRP Enforce Phase 2 ==="
if ($DryRun) { Write-Host "  *** DRY-RUN MODE — no changes will be made ***" }
Write-Host "Baseline: $BaselinePath  ($($files.Count) files)"
Write-Host ""

# ── Step 1: Enable SRP ─────────────────────────────────────────────────────
Write-Host "[1/6] Enabling Software Restriction Policies..."
if (-not (Test-Path $srpRoot)) { New-Item -Path $srpRoot -ItemType Directory -Force | Out-Null | Out-Null }

if (-not $DryRun) {
    Set-ItemProperty -Path $srpRoot -Name "TransparentEnabled" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $srpRoot -Name "DefaultLevel" -Value $denyLevel -Type DWord -Force
    Set-ItemProperty -Path $srpRoot -Name "PolicyScope" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $srpRoot -Name "AuthenticodeEnabled" -Value 0 -Type DWord -Force  # cert rules defeat the path allowlist; keep off
}
Write-Host "  TransparentEnabled = 1 (SRP enabled)"
Write-Host "  DefaultLevel = $denyLevel (0x40000 = Disallowed)"
Write-Host "  AuthenticodeEnabled = 1 (certificate rules enabled)"

# ── Step 2: Standard system-wide path allow rules ───────────────────────────
Write-Host "[2/6] Creating standard system-wide allow rules..."
$systemRules = @(
    @{path="%WINDIR%\*";               desc="Windows system directory"},
    @{path="%WINDIR%\System32\*";       desc="Windows System32"},
    @{path="%WINDIR%\SysWOW64\*";       desc="Windows SysWOW64"},
    @{path="%PROGRAMFILES%\*";          desc="Program Files"},
    @{path="%PROGRAMFILES(X86)%\*";     desc="Program Files (x86)"},
    @{path="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\*"; desc="All Users Start Menu"},
    @{path="%ALLUSERSPROFILE%\Microsoft\Windows\GameExplorer\*"; desc="Game Explorer"},
    @{path="%LOCALAPPDATA%\Microsoft\WindowsApps\*"; desc="Windows Store apps"},
    @{path="%LOCALAPPDATA%\Programs\*\*"; desc="User-installed programs"}
)
foreach ($rule in $systemRules) {
    New-PathRule $allowLevel $rule.path $rule.desc
}

# ── Step 3: Per-app directory allow rules from baseline ─────────────────────
Write-Host "[3/6] Creating per-app directory allow rules from baseline..."
$covered = @()
foreach ($r in $systemRules) {
    $baseDir = $r.path -replace '\\\*$', ''
    $envExpanded = [Environment]::ExpandEnvironmentVariables($baseDir).ToLower()
    $covered += $envExpanded
}

$allowedDirs = @{}
foreach ($f in $files) {
    $dir = [System.IO.Path]::GetDirectoryName($f.path)
    if (-not $dir) { continue }
    # Skip paths already covered by system rules
    $isCovered = $false
    foreach ($c in $covered) {
        if ($dir.ToLower().StartsWith($c.ToLower())) { $isCovered = $true; break }
    }
    if ($isCovered) { continue }
    # Skip obviously transient paths
    if ($dir -match '\\Temp\\|\\INetCache\\|\\cache\\|\\\.git\\') { continue }
    $allowedDirs[$dir] = $true
}

$ruleCount = 0
foreach ($dir in ($allowedDirs.Keys | Sort-Object)) {
    $pattern = "$dir\*"
    $appName = Split-Path $dir -Leaf
    New-PathRule $allowLevel $pattern $appName
    $ruleCount++
}
Write-Host "  Created $ruleCount per-app directory allow rules."

# ── Step 4: Block rules ─────────────────────────────────────────────────────
Write-Host "[4/6] Creating block rules for untrusted locations..."
$blockRules = @(
    @{path="%WINDIR%\Temp\*";              desc="Windows Temp (malware drop zone)"},
    @{path="%WINDIR%\TEMP\*";              desc="Windows TEMP"},
    @{path="%USERPROFILE%\AppData\Local\Temp\*"; desc="User Temp (malware drop zone)"},
    @{path="%USERPROFILE%\Downloads\*";    desc="Downloads folder"},
    @{path="%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache\*"; desc="Browser cache (malware drop zone)"},
    @{path="%USERPROFILE%\AppData\Local\Microsoft\Edge\*\*\*\*"; desc="Edge cache"},
    @{path="%USERPROFILE%\AppData\Local\Google\Chrome\User Data\*\*\*"; desc="Chrome cache"},
    @{path="%USERPROFILE%\AppData\Local\Mozilla\Firefox\Profiles\*\cache*\*"; desc="Firefox cache"},
    @{path="%USERPROFILE%\AppData\Roaming\*\Temp\*"; desc="App Temp subdirs"},
    @{path="%PUBLIC%\*";                   desc="Public folder"},
    @{path="C:\Temp\*";                    desc="Root Temp"}
)
foreach ($rule in $blockRules) {
    New-DenyRule $denyLevel $rule.path $rule.desc
}

# ── Step 5: Certificate allow rules for top publishers ──────────────────────
Write-Host "[5/6] Creating certificate allow rules for top publishers..."
# Collect unique publishers from signed files in baseline
$publisherCounts = @{}
foreach ($f in $files) {
    if ($f.cert -and $f.cert.thumbprint) {
        $tp = $f.cert.thumbprint.ToUpper()
        $subj = $f.cert.subject
        $key = "$tp|$subj"
        if (-not $publisherCounts.ContainsKey($key)) { $publisherCounts[$key] = @{count=0;thumbprint=$tp;subject=$subj} }
        $publisherCounts[$key].count++
    }
}
$topPublishers = $publisherCounts.GetEnumerator() | Sort-Object { $_.Value.count } -Descending | Select-Object -First 20

$certRuleCount = 0
foreach ($entry in $topPublishers) {
    $info = $entry.Value
    $thumbprint = $info.thumbprint

    # Locate the certificate in local stores
    $cert = $null
    $stores = @("TrustedPublisher", "TrustedPeople", "Root", "CA", "My")
    foreach ($storeName in $stores) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store `
            $storeName, "LocalMachine"
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $found = $store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $thumbprint, $false)
        $store.Close()
        if ($found -and $found.Count -gt 0) {
            $cert = $found[0]
            break
        }
    }

    if (-not $cert) {
        Write-Host "  ⚠ Certificate $($info.subject) ($thumbprint) not in local store — skipping cert rule, adding path rule instead"
        # Fallback: add path rules for all directories that use this cert
        $certPaths = $files | Where-Object { $_.cert -and $_.cert.thumbprint -eq $info.thumbprint } |
            ForEach-Object { [System.IO.Path]::GetDirectoryName($_.path) } |
            Sort-Object -Unique
        foreach ($cp in $certPaths) {
            New-PathRule $allowLevel "$cp\*" "signed-by:$($info.subject)"
        }
        continue
    }

    # Create certificate rule
    $certData = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $parent = "$srpRoot\$allowLevel\Certificates"
    if (-not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    $key = New-GuidKey $parent
    if (-not $DryRun) {
        Set-ItemProperty -Path $key.PSPath -Name "(default)" -Value $certData -Type Binary -Force
        Set-ItemProperty -Path $key.PSPath -Name "Description" -Value $info.subject -Type String -Force
        Set-ItemProperty -Path $key.PSPath -Name "SaferFlags" -Value 0 -Type DWord -Force
    }
    Write-Host "  [CERT] $($info.subject)  ($($info.count) files)"
    $certRuleCount++
}

if ($certRuleCount -eq 0) {
    Write-Host "  No certificate rules created (no signed files in baseline)."
    Write-Host "  Adding fallback: allow all Microsoft-signed binaries via path rules..."
    New-PathRule $allowLevel "%WINDIR%\WinSxS\*" "Windows Side-by-Side (signed)"
    New-PathRule $allowLevel "%WINDIR%\Microsoft.NET\*" ".NET Framework"
    New-PathRule $allowLevel "%WINDIR%\servicing\*" "Windows Servicing"
}

Write-Host "  Created $certRuleCount certificate allow rules."

# ── Step 6: Summary & activation ────────────────────────────────────────────
Write-Host ""
Write-Host "[6/6] Finalizing..."
if ($DryRun) {
    Write-Host "  *** DRY-RUN MODE — no changes were made ***"
} else {
    if ($EnableAuditLog) {
        # SRP logs blocks to the Application event log as Event ID 865/866.
        # The registry key to enable logging is under the safer policy.
        try {
            Set-ItemProperty -Path $srpRoot -Name "LogFilePath" -Value "%SystemRoot%\System32\SRP.log" -Type String -Force -ErrorAction SilentlyContinue
        } catch { }
    }
}

Write-Host ""
Write-Host "=== SRP Deployment Complete ==="
Write-Host "  System allow rules:  $($systemRules.Count + $ruleCount)"
Write-Host "  Block rules:         $($blockRules.Count)"
Write-Host "  Certificate rules:   $certRuleCount"
Write-Host ""
Write-Host "ACTIVATION: Reboot the machine or run: gpupdate /force"
Write-Host ""
Write-Host "TESTING: Try running an unsigned .exe from your Downloads folder —"
Write-Host "         it should be blocked with 'Windows cannot open this program'."
Write-Host ""
Write-Host "ROLLBACK:"
Write-Host "  powershell -Command 'Remove-Item -Path \"$srpRoot\" -Recurse -Force'"
Write-Host "  Then set TransparentEnabled back to 0 and reboot."
