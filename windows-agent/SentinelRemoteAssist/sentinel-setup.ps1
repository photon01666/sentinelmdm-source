$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # suppress progress-bar records (Add-WindowsCapability
                                            # is otherwise noisy enough on this stream to risk
                                            # filling the redirected-output pipe buffer)

function Write-Step($msg) { Write-Output "==> $msg" }

try {

# 2.0.4 diagnostic: record whether THIS setup run is elevated (and the full admin group state) —
# a non-elevated run cannot configure services, and the very first symptom of that on a clean box
# was "Access is denied" on Set-Service sshd (found live 2026-08-03). If this line says False,
# the caller (--ap-install's UAC relaunch or the SYSTEM tunnel task) did not actually elevate.
$who = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($who)
Write-Step ("setup running elevated: " + $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) + " (user: " + $who.Name + ")")

# 1. Bundled OpenSSH Server
# Marker files under ProgramData tell UninstallRunner whether WE installed sshd (safe to
# stop+disable on teardown) vs the customer already had it (leave the service running, only
# strip our key/account, and restore the pre-edit sshd_config from the backup we take below).
$markerDir = "C:\ProgramData\SentinelRemoteAssist"
$weInstalledMarker = Join-Path $markerDir "sshd-installed-by-us.marker"
$preexistedMarker  = Join-Path $markerDir "sshd-preexisted.marker"
$sshdConfigBackup  = Join-Path $markerDir "sshd_config.pre-sentinel.bak"

$sshDir = "C:\ProgramData\SentinelRemoteAssist\OpenSSH-Win64"
$sshdAlreadyPresent = [bool](Get-Service sshd -ErrorAction SilentlyContinue)
if (-not $sshdAlreadyPresent) {
    Write-Step "Installing bundled OpenSSH Server..."
    & "$sshDir\install-sshd.ps1" | Out-Null
    New-Item -Path $weInstalledMarker -ItemType File -Force | Out-Null
    if (Test-Path $preexistedMarker) { Remove-Item $preexistedMarker -Force -ErrorAction SilentlyContinue }
} else {
    Write-Step "OpenSSH Server already installed (will leave it running on uninstall)."
    New-Item -Path $preexistedMarker -ItemType File -Force | Out-Null
    if (Test-Path $weInstalledMarker) { Remove-Item $weInstalledMarker -Force -ErrorAction SilentlyContinue }
}

Write-Step "Starting sshd and setting it to auto-start..."
# StartupType MUST be set to Automatic BEFORE Start-Service, not after  -  UninstallRunner leaves
# the service StartupType Disabled on the way out, and Start-Service unconditionally REFUSES to
# start a Disabled service regardless of anything else ("Cannot start service... Cannot start
# service sshd on computer '.'."). This only breaks on a SECOND setup pass, after a prior
# uninstall  -  the very first setup on a machine finds no service disabled yet, so this bug is
# invisible until the ephemeral lifecycle's close-then-reopen path is actually exercised (found
# live, 2026-07-09).
#
# 2.0.4: this whole block is NON-FATAL. Found live 2026-08-03 on a clean-snapshot Windows 11 box
# (stock OpenSSH Server already present): Set-Service -StartupType failed with "Access is denied"
# even from an elevated context, and with $ErrorActionPreference="Stop" the ENTIRE setup aborted
# right here — the sentinel-support account, the hardened sshd_config, the Hop-2 authorized_keys and the
# scheduled tasks never got created, so the box enrolled and brought up Hop-1 but every Hop-2
# feature failed with "Permission denied (publickey)". The service-startup tweak is a convenience;
# the steps after it are load-bearing. Warn + continue on failure (the box's sshd may already be
# running/auto-start as shipped), never abort.
try {
    Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction Stop
} catch {
    Write-Step "WARNING: could not set sshd to auto-start ($($_.Exception.Message)) — continuing (sshd may already be running/auto)"
}
try {
    Start-Service sshd -ErrorAction Stop
} catch {
    Write-Step "WARNING: could not start sshd ($($_.Exception.Message)) — continuing"
}

Write-Step "Setting PowerShell as the default SSH shell..."
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
    -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force | Out-Null

# 2. Local admin account, key-only  -  NO usable password is ever stored.
$acct = Get-LocalUser -Name '__ACCOUNT__' -ErrorAction SilentlyContinue
if (-not $acct) {
    Write-Step "Creating local admin account '__ACCOUNT__' (throwaway password, key-only auth)..."
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $throwaway = [Convert]::ToBase64String($bytes) + "aA1!"
    $secure = ConvertTo-SecureString $throwaway -AsPlainText -Force
    New-LocalUser -Name '__ACCOUNT__' -Password $secure -PasswordNeverExpires -AccountNeverExpires | Out-Null
    Add-LocalGroupMember -Group 'Administrators' -Member '__ACCOUNT__' | Out-Null
    Write-Step "Hiding account '__ACCOUNT__' from the logon screen..."
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name '__ACCOUNT__' -Value 0 -PropertyType DWord -Force | Out-Null
    Remove-Variable throwaway, secure, bytes
} else {
    Write-Step "Local account '__ACCOUNT__' already exists — ensuring a non-blank password."
    # Ensure the account has a password even if it was recreated externally with none.
    # Windows LSA policy LimitBlankPasswordUse blocks ALL network logons (SSH included)
    # for accounts with a blank password, regardless of key-only auth in sshd_config.
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $throwaway = [Convert]::ToBase64String($bytes) + "aA1!"
    net user __ACCOUNT__ $throwaway 2>&1 | Out-Null
    Remove-Variable throwaway, bytes
}

# 3. sshd_config: loopback-only, key-only auth. No inbound firewall rule is created at all  - 
#    nothing needs to reach this box's sshd from the network; only the local ssh.exe client
#    (talking to its own loopback) ever connects to it, via the reverse tunnel.
#    The zip ships `sshd_config_default`, not `sshd_config`  -  always target the live
#    C:\ProgramData\ssh\sshd_config that the Windows service actually reads.
$sshdConfig = 'C:\ProgramData\ssh\sshd_config'
if (-not (Test-Path $sshdConfig)) {
    # Fresh install: seed from the bundled default if the service hasn't written one yet.
    $bundledDefault = Join-Path $sshDir "sshd_config_default"
    if (Test-Path $bundledDefault) {
        New-Item -Path (Split-Path $sshdConfig) -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        Copy-Item $bundledDefault $sshdConfig -Force
    }
}
if (Test-Path $sshdConfig) {
    # One-time backup so UninstallRunner can restore a pre-existing customer's config.
    if (-not (Test-Path $sshdConfigBackup)) {
        Copy-Item $sshdConfig $sshdConfigBackup -Force
        Write-Step "Backed up original sshd_config to $sshdConfigBackup"
    }
    # Write a complete, known-good sshd_config — do not try to surgically edit the existing one,
    # which may have unknown directives that silently break Hop-2 (e.g. Missing "Match Group
    # administrators" block means keys written to administrators_authorized_keys are ignored;
    # "PermitRootLogin no" blocks all admin accounts on Windows).
    $content = @"
ListenAddress 127.0.0.1
Port 22
PermitEmptyPasswords yes
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin yes
ChallengeResponseAuthentication no
Subsystem sftp sftp-server.exe
Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
"@
    Set-Content -Path $sshdConfig -Value $content
    Write-Step "Wrote hardened sshd_config (loopback-only, key-only auth, admin Match block)"
} else {
    Write-Step "WARNING: no sshd_config found at $sshdConfig — sshd may not be installed."
    $changed = $false
}

# 4. Admin's Hop-2 public key -> administrators_authorized_keys (the special file Windows OpenSSH
#    requires for accounts in the local Administrators group  -  a per-user ~\.ssh\authorized_keys
#    is silently IGNORED for admin accounts).
#
#    SentinelMDM dashboard integration: on a ZK-owned (public-user-claimed) device,
#    __EXCLUDE_ADMIN_KEY__ is "1"  -  the standing shared operator key below is skipped entirely,
#    not merely access-control-denied, so the operator has no cryptographic path into this
#    session's Hop-2 account at all. The per-session-key placeholder assigned to $extraPubkey
#    below (when non-empty) carries key(s) generated in the requesting dashboard user's own
#    browser, pushed here fresh on every setup re-run  -  see RemoteAssistSocket.cs's
#    "remote_assist_ssh_key" handler.
#
# ⚠️ 2.0.9 — do NOT write the literal placeholder token anywhere in this file except its single
#    assignment below, not even inside a comment. SetupRunner.BuildScript() does a blind
#    String.Replace of EVERY occurrence, and since 2.0.6 the substituted value is MULTI-LINE (one
#    pushed key per line). A token sitting in a `#` comment therefore stops being a comment after
#    the first line: the remaining keys land as bare code and the trailing prose is parsed as a
#    command. Found live 2026-08-03 — this exact comment broke setup with
#    "The term 'when' is not recognized ... line 151", aborting BEFORE the key-install block, so
#    administrators_authorized_keys still never got written. Same applies to any future
#    placeholder whose value could ever contain a newline.
$adminKeysPath = 'C:\ProgramData\ssh\administrators_authorized_keys'
$pubkey = '__ADMIN_PUBKEY__'
$excludeAdminKey = '__EXCLUDE_ADMIN_KEY__' -eq '1'
$extraPubkey = '__EXTRA_PUBKEY__'

# 2.1.1 — back up a PRE-EXISTING administrators_authorized_keys before our first write, so the
# total nuke (NukeRunner.DeleteOwnedAuthorizedKeys) can restore it and drop only OUR keys. Same
# backup pattern as sshd_config above; only taken when the file pre-exists and no backup yet.
$authKeysBackup = 'C:\ProgramData\ssh\administrators_authorized_keys.pre-sentinel.bak'
if ((Test-Path $adminKeysPath) -and -not (Test-Path $authKeysBackup)) {
    Copy-Item $adminKeysPath $authKeysBackup -Force -ErrorAction SilentlyContinue
}

# Read existing keys (if any), normalising line endings.  Also handles the case where
# earlier broken writes (UTF-16LE / missing newlines) concatenated multiple keys on one
# line — split each raw line on "ssh-" prefix boundaries so individual keys are
# correctly identified.  Without this, one giant concatenated blob matches no single
# key in a -contains check, and every setup re-run duplicates keys forever.
$existing = if (Test-Path $adminKeysPath) { (Get-Content $adminKeysPath -Raw) -replace "`r`n", "`n" } else { '' }
$rawLines = if ($existing) { $existing -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' } } else { @() }
$lines = @()
foreach ($raw in $rawLines) {
    $parts = $raw -split '(?=ssh-(?:ed25519|rsa|dss|ecdsa))' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    $lines += $parts
}

# Always rebuild the file atomically with proper UTF-8 encoding — NEVER use PowerShell's
# Add-Content / Set-Content on this file: both default to UTF-16LE with BOM on PowerShell 5.1,
# which Windows OpenSSH CANNOT read (see docs/ARCHITECTURE.md "SentinelRemoteAssist — Hop-2 SSH
# Troubleshooting" section 4). The file MUST stay valid UTF-8 without BOM.
function Write-AuthKeys($path, $lines) {
    $content = ($lines -join "`n") + "`n"
    [System.IO.File]::WriteAllText($path, $content, [System.Text.UTF8Encoding]::new($false))
}

$changed = $false

if ($pubkey -and $pubkey.Trim()) {
    if ($excludeAdminKey) {
        # ZK-owned device — remove the standing operator key entirely.
        if ($lines -contains $pubkey.Trim()) {
            Write-Step "ZK-owned device: removing the standing operator key from administrators_authorized_keys..."
            $lines = $lines | Where-Object { $_ -ne $pubkey.Trim() }
            $changed = $true
        }
    } else {
        # Non-ZK device — ensure the admin support key is present.
        if ($lines -notcontains $pubkey.Trim()) {
            Write-Step "Installing the admin's support key into administrators_authorized_keys..."
            $lines += $pubkey.Trim()
            $changed = $true
        }
    }
}

# Append every pushed session key not already present.
#
# $extraPubkey is NEWLINE-SEPARATED (one key per line) as of 2.0.6 — the server pushes the browser
# session key and the bastion standing support key back to back, and the agent now accumulates both
# instead of letting the second overwrite the first. Splitting here is what makes the browser key
# actually land; before this, the admin key (already present) was the only value that survived, so
# this whole block no-op'd and the customer's connect.sh failed at Hop-2 forever.
$extraKeys = @()
if ($extraPubkey) {
    $extraKeys = $extraPubkey -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
}
$installedCount = 0
foreach ($k in $extraKeys) {
    if ($lines -notcontains $k) {
        Write-Step "Installing a SentinelMDM session key into administrators_authorized_keys..."
        $lines += $k
        $changed = $true
        $installedCount++
    }
}

# Make a no-op LOUD. Previously an empty/already-present key set produced zero output and the log
# still ended with "Setup complete." — indistinguishable from a successful install, which is why
# this bug survived four Regen Private Key cycles before anyone could see it was doing nothing.
if ($extraKeys.Count -eq 0) {
    Write-Step "WARNING: no session key was supplied to this setup run - administrators_authorized_keys NOT updated (dashboard Regen Private Key will not work until a key push arrives)."
} elseif ($installedCount -eq 0) {
    Write-Step "All $($extraKeys.Count) pushed session key(s) were already present - administrators_authorized_keys unchanged."
} else {
    Write-Step "Installed $installedCount of $($extraKeys.Count) pushed session key(s)."
}

if ($changed) {
    Write-AuthKeys $adminKeysPath $lines
}

# Auto-provisioning first run (2.0.3): no key material exists yet (the server pushes the Hop-2
# key only AFTER the device enrolls), so $changed stays false and the file would never be created
# — the unconditional takeown/icacls below then error with "The system cannot find the file
# specified" (found live 2026-08-03 on a clean box). Create an empty file so sshd has a valid
# AuthorizedKeysFile target and the ACL steps run cleanly; the server's key push fills it in.
if (-not (Test-Path $adminKeysPath)) {
    Write-AuthKeys $adminKeysPath @()
}

takeown /F $adminKeysPath /A | Out-Null
icacls $adminKeysPath /setowner 'NT AUTHORITY\SYSTEM' | Out-Null
icacls $adminKeysPath /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null

if ($changed) {
    Write-Step "Restarting sshd to apply config changes..."
    Restart-Service sshd
}

# 5. Unattended cleanup watchdog: runs as SYSTEM once a minute (no interactive UAC needed) and only
#    acts if this app's own PID marker (app.pid, written at every normal launch) points at a
#    process that is no longer running  -  i.e. the app was killed/crashed instead of closed
#    normally, so MainForm's FormClosing never got to remove '__ACCOUNT__' itself. See
#    WatchdogRunner.cs / Program.cs "--watchdog-check". Re-registering on every setup is
#    intentional (idempotent via -Force) since setup itself now reruns on every fresh launch.
#
# Register-ScheduledTask (not raw `schtasks /Create ... /TR "<quoted string>"`) deliberately  - 
# -Execute/-Argument take the exe path and its args as SEPARATE parameters, so the module builds
# the task's command line internally instead of us hand-concatenating embedded quotes into one
# string. That hand-built form broke in the field (2026-07-09): Windows PowerShell 5.1's
# native-command argument marshalling mangled the embedded quotes before schtasks.exe ever saw
# them, so it validated a garbled path and failed with "ERROR: The system cannot find the file
# specified."  -  a `$ErrorActionPreference="Stop"` PowerShell exception, not a native-command exit
# code, which is why it surfaced through our own catch block with a ScriptStackTrace.
#
# -RepetitionDuration ([TimeSpan]::MaxValue) ALSO broke in the field (2026-07-09, same day): Task
# Scheduler's XML schema caps how large a duration value can be, and MaxValue (~10.6 million days)
# serializes to "P99999999DT23H59M59S", which exceeds that cap  -  "The task XML contains a value
# which is incorrectly formatted or out of range." 10 years is comfortably past any realistic
# session length and gets re-registered fresh on every setup run anyway (via -Force below), so
# there's no real difference from "forever" in practice  -  just don't reach for MaxValue here.
Write-Step "Registering cleanup watchdog task..."
$exePath = '__EXE_PATH__'

# Common settings for every SYSTEM task: -Hidden keeps them out of casual view, -StartWhenAvailable
# runs a missed trigger as soon as possible, and -MultipleInstances IgnoreNew avoids stacking a
# second instance if one is already running. The unattended-tunnel is a SINGLE process that runs
# FOREVER (Program.cs Thread.Sleep(Infinite)), so it MUST override the default 3-day
# ExecutionTimeLimit  -  otherwise Task Scheduler kills the live tunnel after 72 hours. A zero
# TimeSpan is the documented "no limit" sentinel (distinct from RepetitionDuration, where a too-large
# value is what breaks  -  see the note above; here zero disables the cap entirely).
$commonSettings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew
# -RestartCount/-RestartInterval (2026-07-11, found live): without this, killing or crashing the
# --unattended-tunnel process leaves its ssh.exe child ORPHANED (no Job Object ties its lifetime to
# the parent) but UNSUPERVISED  -  TunnelRunner.RunLoopAsync()'s reconnect/backoff loop lives in the
# .NET process that just died, so the orphan keeps the tunnel alive purely by accident and will NOT
# reconnect if it ever drops on its own (network blip, bastion redeploy, ServerAliveInterval
# timeout, ...). Since AtStartup only fires once per boot, that meant "unattended access" silently
# stayed down until a physical reboot. 1-minute interval matches the watchdog task's own cadence
# elsewhere in this script; 999 is the practical max Task Scheduler accepts. This alone is
# sufficient to self-heal  -  TunnelRunner.Start() already calls KillTrackedSsh() at the top of
# every run (reads ssh-tunnel.pid, kills any leftover "ssh"-named process), so the freshly
# restarted instance cleans up the old orphan itself before spawning its own ssh.exe; no Job Object
# needed. (Task Scheduler treats a killed/crashed process as a failed run and applies this same as
# a non-zero exit code  -  verified against Microsoft's documented RestartCount/RestartInterval
# semantics, not just an exit-code-triggered path.)
$tunnelSettings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

$watchdogAction = New-ScheduledTaskAction -Execute $exePath -Argument '--watchdog-check'
$watchdogTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
$watchdogPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName '__WATCHDOG_TASKNAME__' -Action $watchdogAction -Trigger $watchdogTrigger `
    -Principal $watchdogPrincipal -Settings $commonSettings -Force | Out-Null

# 6. Unattended / reboot-survive support (checkbox only — normal CONNECT does not use this).
#    When enabled: SYSTEM AtLogOn auto-setup (silent account/sshd re-setup, no UAC) + SYSTEM
#    AtStartup --unattended-tunnel (the real reverse tunnel, Session 0, pre-login). There is NO
#    HKLM Run / Task Manager Startup apps entry — that was redundant (hidden UI, no tunnel).
#    When OFF: unregister both tasks so nothing silently recreates the account after reboot.
$autoSetupTaskName = '__AUTOSETUP_TASKNAME__'
$unattendedTunnelTaskName = '__AUTOSETUP_TASKNAME___Tunnel'
$trayLaunchTaskName = '__AUTOSETUP_TASKNAME___TrayLaunch'
if ('__REGISTER_AUTOSETUP__' -eq '1') {
    Write-Step "Registering silent auto-setup-at-login task (auto-connect is enabled)..."
    $autoSetupAction = New-ScheduledTaskAction -Execute $exePath -Argument '--setup'
    $autoSetupTrigger = New-ScheduledTaskTrigger -AtLogOn
    $autoSetupPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $autoSetupTaskName -Action $autoSetupAction -Trigger $autoSetupTrigger `
        -Principal $autoSetupPrincipal -Settings $commonSettings -Force | Out-Null

    Write-Step "Registering silent unattended-tunnel task (connects before login)..."
    $tunnelAction = New-ScheduledTaskAction -Execute $exePath -Argument '--unattended-tunnel'
    $tunnelTrigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName $unattendedTunnelTaskName -Action $tunnelAction -Trigger $tunnelTrigger `
        -Principal $autoSetupPrincipal -Settings $tunnelSettings -Force | Out-Null

    # Start the tunnel RIGHT NOW so the customer does not need to click CONNECT first (and does
    # not need to reboot). Log failures clearly; AutoStartManager.EnsureUnattendedTunnelRunning
    # is a second-chance fallback after this script returns.
    Write-Step "Starting unattended tunnel now (Connect is not required)..."
    try {
        Start-ScheduledTask -TaskName $unattendedTunnelTaskName -ErrorAction Stop
        Write-Step "Scheduled task started: $unattendedTunnelTaskName"
    } catch {
        Write-Step "Start-ScheduledTask failed: $($_.Exception.Message) - launching tunnel process directly..."
        Start-Process -FilePath $exePath -ArgumentList '--unattended-tunnel' -WindowStyle Hidden
    }
    Start-Sleep -Seconds 3
    $pidFile = 'C:\ProgramData\SentinelRemoteAssist\unattended-tunnel.pid'
    if (Test-Path $pidFile) {
        Write-Step "Unattended tunnel is up (pid marker: $(Get-Content $pidFile -ErrorAction SilentlyContinue))."
    } else {
        Write-Step "Unattended tunnel pid marker not yet present - C# fallback will re-kick if needed."
    }

    # AI Live Chat tray helper — runs the PLAIN interactive exe (--autostart, so the window starts
    # hidden per MainForm's _startHidden path) in WHICHEVER user's desktop session logs on, purely
    # so the tray icon has a process to live in. Group principal (not a specific -UserId) because
    # we don't know the customer's account name in advance -- Task Scheduler resolves an
    # Interactive-logon-type task with a group principal to "the session of whoever just logged on".
    # Safe alongside the unattended tunnel above: MainForm's own Load handler already special-cases
    # AutoStartManager.IsEnabled + IsPreviouslyEnrolled to be status-only and never opens a
    # competing RemoteAssistSocket (see MainForm.cs's Load handler comment) -- so this never takes
    # the control-channel mutex away from the SYSTEM tunnel task above. The tray icon itself
    # self-hides when AI Chat isn't enabled for this device (AccountLinkedSession.AiChatEnabled),
    # so registering this unconditionally here is harmless even for devices that never turn chat on.
    Write-Step "Registering tray-launch-at-logon task (AI Live Chat)..."
    $trayLaunchAction = New-ScheduledTaskAction -Execute $exePath -Argument '--autostart'
    $trayLaunchTrigger = New-ScheduledTaskTrigger -AtLogOn
    $trayLaunchPrincipal = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users' -RunLevel Limited
    Register-ScheduledTask -TaskName $trayLaunchTaskName -Action $trayLaunchAction -Trigger $trayLaunchTrigger `
        -Principal $trayLaunchPrincipal -Settings $commonSettings -Force | Out-Null
    # Start it now too, so the tray icon appears immediately without waiting for the next logon —
    # Task Scheduler resolves a group-principal Interactive task to whichever user is currently
    # logged on when started this way, same as the AtLogOn trigger would at actual logon time.
    # BUT ONLY if no tray/UI instance is already alive — this whole setup script re-runs on EVERY
    # remote_assist_ssh_key push (RemoteAssistSocket.cs calls SetupRunner.RunElevatedSetup()
    # unconditionally on every key regen, not just once), so an unconditional Start-ScheduledTask
    # here used to spawn a brand-new --autostart process on every single re-run. --autostart isn't
    # one of Program.cs's recognized elevated-helper args, so it falls into the normal UI path and
    # collides with SingleInstance's UI mutex (already held by the running instance) — popping
    # "Sentinel Remote Assist is already running" on the customer's desktop on every regen, found
    # live 2026-07-21. Exclude the CURRENTLY-RUNNING elevated --setup process itself (this script
    # is literally running inside it right now) and the other elevated-helper argument shapes from
    # the check — only a plain (no-arg) or --autostart launch actually takes the UI mutex, so those
    # are the only ones that count as "already up" here.
    $uiAlreadyRunning = $false
    try {
        $uiAlreadyRunning = @(Get-CimInstance Win32_Process -Filter "Name='Sentinel.exe'" |
            Where-Object { $_.CommandLine -notmatch '--setup|--uninstall|--watchdog-check|--unattended-tunnel|--set-autostart|--unregister-autosetup|--appcontrol-watch|--edr-watch' }
        ).Count -gt 0
    } catch { }
    if (-not $uiAlreadyRunning) {
        try {
            Start-ScheduledTask -TaskName $trayLaunchTaskName -ErrorAction Stop
            Write-Step "Scheduled task started: $trayLaunchTaskName"
        } catch {
            Write-Step "Start-ScheduledTask failed for tray launch: $($_.Exception.Message) (non-fatal — it will still fire at next logon)"
        }
    } else {
        Write-Step "Tray-launch skipped — a SentinelRemoteAssist UI/tray instance is already running."
    }
} else {
    Unregister-ScheduledTask -TaskName $autoSetupTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $unattendedTunnelTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $trayLaunchTaskName -Confirm:$false -ErrorAction SilentlyContinue
    # Kill any unattended tunnel process that might be running
    Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%--unattended-tunnel%'" | Invoke-CimMethod -MethodName Terminate | Out-Null
    # Kill any tray-launch process too (the plain --autostart instance) — EDR mode is turning off.
    Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%--autostart%'" | Invoke-CimMethod -MethodName Terminate | Out-Null
}

Write-Step "Setup complete."
} catch {
    Write-Output "==> FAILED: $($_.Exception.Message)"
    Write-Output ($_.ScriptStackTrace)
    exit 1
}
exit 0
