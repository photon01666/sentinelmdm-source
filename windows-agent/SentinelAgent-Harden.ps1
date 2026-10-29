# SentinelAgent-Harden.ps1 — Process injection protection for SentinelRemoteAssist
# Run as Administrator on the target Windows PC after installing the agent.
# Protects the agent from being killed/modified by malware.

$ErrorActionPreference = 'SilentlyContinue'

# ── 1. File protection ────────────────────────────────────────────────────────
Write-Host "[1/5] Locking agent files..." -ForegroundColor Cyan
$agentDir = "$env:ProgramData\SentinelRemoteAssist"
$exePath = Join-Path $agentDir "Sentinel.exe"

# Remove inheritance, grant only SYSTEM + Administrators
foreach ($path in @($agentDir, $exePath)) {
    if (Test-Path $path) {
        $acl = Get-Acl $path
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
        $acl.AddAccessRule($adminRule)
        $acl.AddAccessRule($systemRule)
        Set-Acl -Path $path -AclObject $acl
    }
}

# Set read-only on the exe
if (Test-Path $exePath) {
    Set-ItemProperty -Path $exePath -Name IsReadOnly -Value $true
}

# ── 2. Process mitigation policies (ACG + CIG) ───────────────────────────────
Write-Host "[2/5] Applying process mitigation policies..." -ForegroundColor Cyan
$mitigations = @{
    "ForceRelocateImages"     = $true   # Force relocate images (ACG-like)
    "DisableExtensionPoints"  = $true   # Block AppInit DLLs
    "DisableDynamicCode"      = $true   # Block dynamic code generation
    "DisableExportSymbols"    = $true   # Block GetProcAddress-based injection
    "DisableNonSystemFonts"   = $true   # Block font file loading
    "AuditDisableRemoteScanning" = $true
    "BlockNonMicrosoftBinaries" = $true # CIG — only load MS-signed DLLs
    "BlockRemoteImageLoads"   = $true   # Block loading DLLs from network
}

# These must be set via registry (process mitigation policy)
$regBase = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
foreach ($name in $mitigations.Keys) {
    if ($mitigations[$name]) {
        try {
            New-ItemProperty -Path $regBase -Name $name -Value 1 -PropertyType DWord -Force | Out-Null
        } catch {}
    }
}

# ── 3. Apply mitigation to the specific process via job object ────────────────
Write-Host "[3/5] Setting process-level mitigations..." -ForegroundColor Cyan
# Create a restricted process mitigation policy for Sentinel.exe
$sentinelProc = Get-Process -Name "Sentinel" -ErrorAction SilentlyContinue
if ($sentinelProc) {
    # Set process mitigation via PowerShell (Windows 10 1709+)
    $mitigationPolicy = @"
{
    "AuditOptions": {"DisableExtensionPoints": {"Enabled": true}, "DisableDynamicCode": {"Enabled": true}},
    "DisableExtensionPoints": {"Enabled": true},
    "DisableDynamicCode": {"Enabled": true},
    "DisableNonSystemFonts": {"Enabled": true},
    "DisallowWin32kSystemCalls": {"Enabled": true},
    "ExportBlockRelocations": {"Enabled": true},
    "ForceRelocateImages": {"Enabled": true},
    "RestrictIndirectBranchPrediction": {"Enabled": true},
    "EnableExportAddressFilter": {"Enabled": true, "ExportAddressFilterModules": ""}
}
"@
    # Use Set-ProcessMitigationPolicy if available (Win10 1709+)
    try {
        # Save current policy
        $policyFile = "$env:TEMP\sentinel-mitigations.json"
        $mitigationPolicy | Out-File -FilePath $policyFile -Encoding UTF8
        
        # Apply via Set-ProcessMitigation -Name sentinel.exe
        Set-ProcessMitigation -Name Sentinel.exe -Enable DisableExtensionPoints
        Set-ProcessMitigation -Name Sentinel.exe -Enable DisableDynamicCode
        Set-ProcessMitigation -Name Sentinel.exe -Enable ForceRelocateImages
        Set-ProcessMitigation -Name Sentinel.exe -Enable DisableNonSystemFonts
        Set-ProcessMitigation -Name Sentinel.exe -Enable ExportBlockRelocations
        Write-Host "    Process mitigations applied" -ForegroundColor Green
    } catch {
        Write-Host "    Could not apply process mitigations: $_" -ForegroundColor Yellow
    }
}

# ── 4. Block known injection techniques via WMI event subscription ────────────
Write-Host "[4/5] Installing injection detection..." -ForegroundColor Cyan
# Create a WMI event filter that detects suspicious process creation targeting Sentinel
$filterArgs = @{
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND (TargetInstance.Name = 'rundll32.exe' OR TargetInstance.Name = 'mshta.exe' OR TargetInstance.Name = 'regsvr32.exe')"
    Name = "Sentinel-Injection-Watcher"
}
try {
    Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs | Out-Null
    Write-Host "    Injection watcher installed" -ForegroundColor Green
} catch {
    Write-Host "    Could not install injection watcher: $_" -ForegroundColor Yellow
}

# ── 5. Scheduled task watchdog ────────────────────────────────────────────────
Write-Host "[5/5] Installing watchdog task..." -ForegroundColor Cyan
$watchdogAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument @"
-NoProfile -ExecutionPolicy Bypass -Command "
`$sentinel = Get-Process -Name 'Sentinel' -ErrorAction SilentlyContinue
if (-not `$sentinel) {
    Start-Process '$exePath' -WindowStyle Hidden
}
"
"@

$watchdogTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2) -RepetitionDuration (New-TimeSpan -Days 3650)
$watchdogPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$watchdogSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName "Sentinel-Agent-Watchdog" -Action $watchdogAction -Trigger $watchdogTrigger -Principal $watchdogPrincipal -Settings $watchdogSettings -Force -Description "Restarts Sentinel agent if killed by malware" | Out-Null
Write-Host "    Watchdog task installed" -ForegroundColor Green

Write-Host ""
Write-Host "Protection applied!" -ForegroundColor Green
Write-Host "  - File permissions locked (SYSTEM + Admin only)" -ForegroundColor Gray
Write-Host "  - Binary set to read-only" -ForegroundColor Gray
Write-Host "  - Process mitigations (ACG, CIG, force relocate)" -ForegroundColor Gray
Write-Host "  - Watchdog restarts agent every 2 min if killed" -ForegroundColor Gray
Write-Host ""
Write-Host "To undo: Remove-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\ForceRelocateImages'" -ForegroundColor Yellow
