$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

<#
.SYNOPSIS
    Phase 2 of SRP deployment — applies Software Restriction Policies with a
    per-app allowlist. Designed to be executed via Hop-2 SSH on a remote Windows
    machine managed by SentinelRemoteAssist.

.PARAMETER AllowListPath
    Path to JSON file containing an array of allowed path globs:
    ["C:\\Program Files\\Mozilla Firefox\\*", "C:\\Program Files\\Discord\\*", ...]

    These are the user-facing apps that will be ALLOWED. System directories
    (Windows, Program Files, etc.) are always allowed regardless.

.DESCRIPTION
    Configures SRP with:
    - Default security level: Disallowed (0x40000)
    - System allow path rules: %WINDIR%\*, %PROGRAMFILES%\*, etc.
    - Per-app allow rules from the allowlist
    - Block rules: Temp, Downloads, browser caches, Public
    - Certificate rules: top publishers from the local machine's Trusted Publisher store

    Outputs a JSON status line at the end for programmatic parsing.
#>

param(
    [string]$AllowListPath = "",
    [switch]$DryRun
)

$srpRoot = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
# SAFER level IDs (winsafer.h): 0x40000=262144 FullyTrusted (Unrestricted/ALLOW), 0=Disallowed (block),
# 0x20000=131072 NormalUser (restricted token, NOT a full allow). DefaultLevel is set to $denyLevel below,
# so it MUST be 0 (Disallowed) for default-deny. 262144 is NOT "Disallowed" — using it allows everything.
$allowLevel = 262144  # FullyTrusted = allow
$denyLevel = 0        # Disallowed = block (also the default level)

# ── Guard: admin ────────────────────────────────────────────────────────────
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "ERROR: Must run as Administrator."
    exit 1
}

# ── Read allowlist ──────────────────────────────────────────────────────────
$allowedPaths = @()
if ($AllowListPath -and (Test-Path $AllowListPath)) {
    $raw = [System.IO.File]::ReadAllText($AllowListPath) -replace "`r`n", "`n"
    $allowedPaths = $raw | ConvertFrom-Json
}

$systemRulesCount = 0
$appRulesCount = 0
$blockRulesCount = 0

function New-RuleKey($parent) {
    $name = [Guid]::NewGuid().ToString("B")
    $key = New-Item -Path $parent -Name $name -Force -ErrorAction Stop
    return $key
}

function Set-RuleValue($key, $name, $value, $type) {
    if ($DryRun) { return }
    Set-ItemProperty -Path $key.PSPath -Name $name -Value $value -Type $type -Force | Out-Null
}

function Add-PathRule($level, $pathPattern, $description) {
    $parent = "$srpRoot\$level\Paths"
    if (-not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    $key = New-RuleKey $parent
    Set-RuleValue $key "ItemData"   $pathPattern "String"
    Set-RuleValue $key "Description" $description "String"
    Set-RuleValue $key "SaferFlags"  0 "DWord"
    Set-RuleValue $key "ItemSize"   $pathPattern.Length "DWord"
}

# ── Step 1: Clear any existing SRP rules ────────────────────────────────────
if (Test-Path $srpRoot) {
    Get-ChildItem $srpRoot -Recurse | Where-Object { $_.PSChildName -match '^\{' } |
        ForEach-Object { Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue }
}

# ── Step 2: Enable SRP + set default to Disallowed ──────────────────────────
if (-not (Test-Path $srpRoot)) { New-Item -Path $srpRoot -ItemType Directory -Force | Out-Null }
Set-ItemProperty -Path $srpRoot -Name "TransparentEnabled" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $srpRoot -Name "DefaultLevel" -Value $denyLevel -Type DWord -Force
Set-ItemProperty -Path $srpRoot -Name "PolicyScope" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $srpRoot -Name "AuthenticodeEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $srpRoot -Name "SaferFlags" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $srpRoot -Name "LogFileName" -Value "%SystemRoot%\System32\SRP.log" -Type String -Force -ErrorAction SilentlyContinue

# ── Step 3: System-wide path allow rules ─────────────────────────────────────
$infraRules = @(
    @{path="%PROGRAMDATA%\SentinelRemoteAssist\*";                    desc="Remote Assist agent"},
    @{path="%PROGRAMDATA%\SentinelRemoteAssist\OpenSSH-Win64\*";      desc="RA bundled sshd"},
    @{path="%PROGRAMDATA%\SentinelRemoteAssist\xray\*";               desc="RA xray proxy"}
)
$systemRules = @(
    @{path="%WINDIR%\*";                  desc="Windows directory"},
    @{path="%PROGRAMFILES%\*";            desc="Program Files"},
    @{path="%PROGRAMFILES(X86)%\*";       desc="Program Files (x86)"},
    @{path="%LOCALAPPDATA%\Microsoft\WindowsApps\*"; desc="Windows Store apps"}
) + $infraRules
foreach ($rule in $systemRules) {
    Add-PathRule $allowLevel $rule.path $rule.desc
    $systemRulesCount++
}

# ── Step 4: Per-app allow rules from allowlist ──────────────────────────────
foreach ($pattern in $allowedPaths) {
    $pattern = $pattern.Trim()
    if (-not $pattern) { continue }
    $name = Split-Path ($pattern -replace '\\\*$', '') -Leaf
    if (-not $name) { $name = $pattern }

    # Check if already covered by system rules
    $envExpanded = [Environment]::ExpandEnvironmentVariables($pattern -replace '\\\*$', '').ToLower()
    $covered = $false
    foreach ($sr in $systemRules) {
        $sysPath = [Environment]::ExpandEnvironmentVariables($sr.path -replace '\\\*$', '').ToLower()
        if ($envExpanded.StartsWith($sysPath)) { $covered = $true; break }
    }
    if ($covered) { continue }

    Add-PathRule $allowLevel $pattern $name
    $appRulesCount++
}

# Use an expandable counter for the fallback in case there's nothing extra

# ── Step 5: Block rules for untrusted locations ─────────────────────────────
$blockRules = @(
    @{path="%WINDIR%\Temp\*";                       desc="Windows Temp"},
    @{path="%WINDIR%\TEMP\*";                       desc="Windows TEMP"},
    @{path="%USERPROFILE%\AppData\Local\Temp\*";    desc="User Temp"},
    @{path="%USERPROFILE%\Downloads\*";             desc="Downloads"},
    @{path="%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache\*"; desc="IE/Edge cache"},
    @{path="%USERPROFILE%\AppData\Local\Google\Chrome\User Data\*\Cache\*"; desc="Chrome cache"},
    @{path="%USERPROFILE%\AppData\Local\Mozilla\Firefox\Profiles\*\cache*\*"; desc="Firefox cache"},
    @{path="%USERPROFILE%\AppData\Roaming\*\Temp\*"; desc="App Roaming Temp"},
    @{path="%PUBLIC%\*";                            desc="Public folder"},
    @{path="C:\Temp\*";                             desc="Root Temp"},
    @{path="%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\*\*\*"; desc="Edge cache"}
)
foreach ($rule in $blockRules) {
    Add-PathRule $denyLevel $rule.path $rule.desc
    $blockRulesCount++
}

# ── Step 6: (removed) Certificate allow rules ────────────────────────────────
# Intentionally NO certificate allow rules. An SRP publisher-cert allow rule
# (e.g. O=Discord/Zoom/TeamViewer/AnyDesk) permits ANY binary signed by that
# vendor to execute from ANY location, and certificate rules OUTRANK path rules
# in SRP precedence — so a cert rule overrides both the Downloads/Temp deny rules
# and the default-deny. That silently defeats the per-app allowlist: unchecking
# an app in the dashboard could never actually block it (Discord kept installing
# from Downloads and running from %LOCALAPPDATA%\DiscordPTB). Path rules only.
# Do NOT reintroduce a hardcoded publisher certificate allowlist here.
$certRuleCount = 0

# ── Step 7: Save approved paths for future differential audits ──────────────
$approvedFile = "C:\ProgramData\SentinelRemoteAssist\srp-approved.json"
$approvedDir = Split-Path $approvedFile -Parent
if (-not (Test-Path $approvedDir)) { New-Item -Path $approvedDir -ItemType Directory -Force | Out-Null }
$mergedPaths = @($allowedPaths)
if (Test-Path $approvedFile) { try { $existing = (Get-Content $approvedFile -Raw -ErrorAction Stop) | ConvertFrom-Json; foreach ($ep in @($existing)) { $eps = ("" + $ep).Trim(); if ($eps -and $mergedPaths -notcontains $eps) { $mergedPaths += $eps } } } catch { } }
$approvedJson = ($mergedPaths | ConvertTo-Json -Compress)
[System.IO.File]::WriteAllText($approvedFile, $approvedJson, [System.Text.UTF8Encoding]::new($false))

# Enable SRP logging so blocked attempts are recorded for the next audit
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" `
        -Name "LogFileName" -Value "%SystemRoot%\System32\SRP.log" -Type String -Force -ErrorAction SilentlyContinue
} catch { }

# ── Output status ───────────────────────────────────────────────────────────
$status = @{
    ok = $true
    dryRun = [bool]$DryRun
    systemRules = $systemRulesCount
    appRules = $appRulesCount
    blockRules = $blockRulesCount
    certRules = $certRuleCount
    totalAllowRules = ($systemRulesCount + $appRulesCount + $certRuleCount)
    totalBlockRules = $blockRulesCount
    allowedPaths = $mergedPaths.Count
    approvedSavedTo = $approvedFile
}
Write-Output ($status | ConvertTo-Json -Compress)
exit 0
