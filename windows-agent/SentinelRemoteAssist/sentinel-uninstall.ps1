$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Step($msg) { Write-Output "==> $msg" }
function Write-Verify($msg) { Write-Output "VERIFY: $msg" }

$script:VerifyFailures = 0
function Assert-Gone($name, [scriptblock]$test) {
    try {
        if (& $test) {
            Write-Verify "FAIL — still present: $name"
            $script:VerifyFailures++
        } else {
            Write-Verify "OK — removed: $name"
        }
    } catch {
        Write-Verify "OK — removed: $name (query error treated as gone: $($_.Exception.Message))"
    }
}

try {

# 1. Remove ONLY this tool's key from administrators_authorized_keys  -  leave any other lines
#    a customer may have added there for their own unrelated reasons untouched.
$adminKeysPath = 'C:\ProgramData\ssh\administrators_authorized_keys'
if (Test-Path $adminKeysPath) {
    Write-Step "Removing support key from administrators_authorized_keys..."
    $pubkey = '__ADMIN_PUBKEY__'
    $remaining = @(Get-Content $adminKeysPath | Where-Object { $_ -notlike "*$pubkey*" })
    Set-Content -Path $adminKeysPath -Value $remaining
}

# 2. Remove the local admin account and its hidden-from-logon-screen registry entry.
$acct = Get-LocalUser -Name '__ACCOUNT__' -ErrorAction SilentlyContinue
if ($acct) {
    Write-Step "Removing local account '__ACCOUNT__'..."
    Remove-LocalUser -Name '__ACCOUNT__'
}
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" `
    -Name '__ACCOUNT__' -ErrorAction SilentlyContinue

# 3. sshd service / config teardown  -  careful when the customer already had OpenSSH before us.
#    Markers written by SetupRunner under C:\ProgramData\SentinelRemoteAssist\:
#      sshd-installed-by-us.marker  -> we ran install-sshd.ps1; stop+disable is safe
#      sshd-preexisted.marker      -> leave the service running; restore pre-edit config if backed up
$markerDir = "C:\ProgramData\SentinelRemoteAssist"
$weInstalledMarker = Join-Path $markerDir "sshd-installed-by-us.marker"
$preexistedMarker  = Join-Path $markerDir "sshd-preexisted.marker"
$sshdConfigBackup  = Join-Path $markerDir "sshd_config.pre-sentinel.bak"
$sshdConfig        = 'C:\ProgramData\ssh\sshd_config'
$weInstalledSshd   = Test-Path $weInstalledMarker

if ($weInstalledSshd) {
    if (Get-Service sshd -ErrorAction SilentlyContinue) {
        Write-Step "Stopping and disabling sshd (we installed it for this session)..."
        Stop-Service sshd -ErrorAction SilentlyContinue
        Set-Service -Name sshd -StartupType Disabled
    }
} elseif (Test-Path $preexistedMarker) {
    Write-Step "OpenSSH pre-existed on this machine  -  leaving the sshd service running."
    if ((Test-Path $sshdConfigBackup) -and (Test-Path $sshdConfig)) {
        Write-Step "Restoring pre-session sshd_config from backup..."
        Copy-Item $sshdConfigBackup $sshdConfig -Force
        if (Get-Service sshd -ErrorAction SilentlyContinue) {
            # Reload config; don't change StartupType.
            Restart-Service sshd -ErrorAction SilentlyContinue
        }
    }
} else {
    # Unknown provenance (partial install / older build)  -  safest default: stop+disable so we
    # don't leave a listening sshd with our Hop-2 key already stripped but a hardened config.
    if (Get-Service sshd -ErrorAction SilentlyContinue) {
        Write-Step "Stopping and disabling sshd (provenance unknown  -  safe default)..."
        Stop-Service sshd -ErrorAction SilentlyContinue
        Set-Service -Name sshd -StartupType Disabled
    }
}

# 3b. Firewall rules  -  SetupRunner does not intentionally create any, but the bundled
#     install-sshd.ps1 (when WE installed OpenSSH) typically registers OpenSSH-Server-In-* rules.
#     Only remove those when weInstalledSshd so we never strip a customer's pre-existing OpenSSH rules.
if ($weInstalledSshd) {
    Write-Step "Removing OpenSSH firewall rules created by our install (if any)..."
    try {
        Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like 'OpenSSH*' -or $_.Name -like 'OpenSSH*' } |
            ForEach-Object {
                Write-Step "  Removing firewall rule: $($_.DisplayName) ($($_.Name))"
                Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
            }
    } catch {
        # Fallback for hosts without the NetSecurity module.
        netsh advfirewall firewall delete rule name="OpenSSH SSH Server (sshd)" 2>$null | Out-Null
        netsh advfirewall firewall delete rule name=all program="C:\ProgramData\SentinelRemoteAssist\OpenSSH-Win64\sshd.exe" 2>$null | Out-Null
    }
} else {
    Write-Step "Skipping OpenSSH firewall rule removal (sshd pre-existed or provenance unknown)."
}

# 4. Unregister ALL scheduled tasks this tool creates  -  watchdog (ephemeral) AND any leftover
#    AutoSetup / Tunnel tasks (should already be gone if Start-auto was never used, but a partial
#    install or a Connect->Start-auto handoff that failed mid-way can leave residue).
Write-Step "Unregistering scheduled tasks..."
foreach ($tn in @('__WATCHDOG_TASKNAME__', '__AUTOSETUP_TASKNAME__', '__TUNNEL_TASKNAME__')) {
    Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
    schtasks /Delete /TN $tn /F 2>$null | Out-Null
}

# 5. Kill any leftover unattended-tunnel process (should not exist in pure ephemeral mode).
Write-Step "Stopping any leftover unattended-tunnel processes..."
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*--unattended-tunnel*' } |
    ForEach-Object {
        Write-Step "  Terminating PID $($_.ProcessId)"
        Invoke-CimMethod -InputObject $_ -MethodName Terminate -ErrorAction SilentlyContinue | Out-Null
    }

# 6. VERIFICATION  -  prove to the customer (and our cleanup report) that residue is gone.
Write-Step "Verifying clean uninstall..."
Assert-Gone "local account '__ACCOUNT__'" {
    $null -ne (Get-LocalUser -Name '__ACCOUNT__' -ErrorAction SilentlyContinue)
}
Assert-Gone "scheduled task '__WATCHDOG_TASKNAME__'" {
    $null -ne (Get-ScheduledTask -TaskName '__WATCHDOG_TASKNAME__' -ErrorAction SilentlyContinue)
}
Assert-Gone "scheduled task '__AUTOSETUP_TASKNAME__'" {
    $null -ne (Get-ScheduledTask -TaskName '__AUTOSETUP_TASKNAME__' -ErrorAction SilentlyContinue)
}
Assert-Gone "scheduled task '__TUNNEL_TASKNAME__'" {
    $null -ne (Get-ScheduledTask -TaskName '__TUNNEL_TASKNAME__' -ErrorAction SilentlyContinue)
}
Assert-Gone "support key in administrators_authorized_keys" {
    if (-not (Test-Path $adminKeysPath)) { return $false }
    $content = Get-Content $adminKeysPath -Raw -ErrorAction SilentlyContinue
    return ($content -like '*__ADMIN_PUBKEY__*')
}
if ($weInstalledSshd) {
    Assert-Gone "sshd service Running (we installed it)" {
        $svc = Get-Service sshd -ErrorAction SilentlyContinue
        return ($null -ne $svc -and $svc.Status -eq 'Running')
    }
    # Disabled is the expected end state when we installed it.
    $svc = Get-Service sshd -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        if ($svc.StartType -eq 'Disabled' -or $svc.Status -ne 'Running') {
            Write-Verify "OK — sshd not running / disabled (we installed it)"
        } else {
            Write-Verify "FAIL — sshd still Running after we installed it"
            $script:VerifyFailures++
        }
    } else {
        Write-Verify "OK — sshd service not present"
    }
}

if ($script:VerifyFailures -gt 0) {
    Write-Step "Uninstall finished WITH $($script:VerifyFailures) verification failure(s) — see VERIFY lines above."
    exit 2
}

Write-Step "Uninstall complete — all checks passed."
} catch {
    Write-Output "==> FAILED: $($_.Exception.Message)"
    Write-Output ($_.ScriptStackTrace)
    exit 1
}
exit 0
