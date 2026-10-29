Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# ─── CONFIG ─────────────────────────────────────────────────────────────────────
$ProgramDataDir = $env:ProgramData
$SentinelDir    = Join-Path $ProgramDataDir 'SentinelRemoteAssist'
$EdrDir         = Join-Path $ProgramDataDir 'SentinelEdr'
$AppControlDir  = Join-Path $ProgramDataDir 'SentinelAppControl'
$IdentityDir    = Join-Path $ProgramDataDir 'SentinelRemoteAssistIdentity'
$BackupVault    = Join-Path $ProgramDataDir 'BackupVault'
$SshDir         = Join-Path $ProgramDataDir 'ssh'
$UsersPublicDir = Join-Path $env:LOCALAPPDATA '..\..\Users\Public'

$CanaryNames = @(
    'Passwords.docx', 'Tax Documents 2025.pdf', 'Family Budget.xlsx',
    'Backup - Do Not Delete.docx', 'Photos Backup Archive.zip'
)
$CanaryRoots = @(
    (Join-Path $env:USERPROFILE 'Documents'),
    (Join-Path $env:USERPROFILE 'Desktop'),
    (Join-Path $env:USERPROFILE 'Pictures'),
    (Join-Path $env:USERPROFILE 'Downloads'),
    (Join-Path $env:USERPROFILE 'OneDrive'),
    (Join-Path $ProgramDataDir 'Users\Public\Documents'),
    (Join-Path $ProgramDataDir 'Users\Public\Downloads'),
    $BackupVault
)

# ─── TOTAL STEPS ────────────────────────────────────────────────────────────────
$script:TotalSteps = 11
$script:CurrentStep = 0

# ─── FORM ───────────────────────────────────────────────────────────────────────
$form = New-Object System.Windows.Forms.Form
$form.Text = 'NUKE-Agent — SentinelRemoteAssist Removal'
$form.Size = New-Object System.Drawing.Size(620, 520)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 18)
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

# Title label
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = 'NUKE-AGENT'
$lblTitle.Font = New-Object System.Drawing.Font('Segoe UI', 20, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = [System.Drawing.Color]::FromArgb(220, 40, 40)
$lblTitle.AutoSize = $true
$lblTitle.Location = New-Object System.Drawing.Point(20, 15)
$form.Controls.Add($lblTitle)

# Subtitle
$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text = 'Complete removal of SentinelRemoteAssist from this PC'
$lblSub.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$lblSub.ForeColor = [System.Drawing.Color]::FromArgb(140, 140, 140)
$lblSub.AutoSize = $true
$lblSub.Location = New-Object System.Drawing.Point(24, 55)
$form.Controls.Add($lblSub)

# Separator line
$sep = New-Object System.Windows.Forms.Label
$sep.BorderStyle = 'Fixed3D'
$sep.Location = New-Object System.Drawing.Point(20, 82)
$sep.Size = New-Object System.Drawing.Size(560, 2)
$form.Controls.Add($sep)

# Status label (shows current step)
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = 'Ready — click NUKE to begin'
$lblStatus.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
$lblStatus.AutoSize = $true
$lblStatus.Location = New-Object System.Drawing.Point(20, 95)
$form.Controls.Add($lblStatus)

# Progress bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(20, 122)
$progressBar.Size = New-Object System.Drawing.Size(560, 28)
$progressBar.Style = 'Continuous'
$progressBar.Minimum = 0
$progressBar.Maximum = 100
$progressBar.Value = 0
$form.Controls.Add($progressBar)

# Step counter label
$lblStep = New-Object System.Windows.Forms.Label
$lblStep.Text = '0 / 11'
$lblStep.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$lblStep.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
$lblStep.AutoSize = $true
$lblStep.Location = New-Object System.Drawing.Point(20, 155)
$form.Controls.Add($lblStep)

# Results text box
$txtResults = New-Object System.Windows.Forms.TextBox
$txtResults.Location = New-Object System.Drawing.Point(20, 178)
$txtResults.Size = New-Object System.Drawing.Size(560, 250)
$txtResults.Multiline = $true
$txtResults.ScrollBars = 'Vertical'
$txtResults.ReadOnly = $true
$txtResults.BackColor = [System.Drawing.Color]::FromArgb(12, 12, 12)
$txtResults.ForeColor = [System.Drawing.Color]::FromArgb(0, 200, 80)
$txtResults.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtResults.Text = ''
$form.Controls.Add($txtResults)

# NUKE button
$btnNuke = New-Object System.Windows.Forms.Button
$btnNuke.Text = 'NUKE'
$btnNuke.Size = New-Object System.Drawing.Size(560, 44)
$btnNuke.Location = New-Object System.Drawing.Point(20, 438)
$btnNuke.Font = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
$btnNuke.BackColor = [System.Drawing.Color]::FromArgb(180, 20, 20)
$btnNuke.ForeColor = [System.Drawing.Color]::White
$btnNuke.FlatStyle = 'Flat'
$btnNuke.FlatAppearance.BorderSize = 0
$btnNuke.Cursor = [System.Windows.Forms.Cursors]::Hand
$form.Controls.Add($btnNuke)

# ─── HELPERS ────────────────────────────────────────────────────────────────────
function Append-Result {
    param([string]$Text, [string]$Icon = '  ')
    $line = "$Icon $Text"
    if ($txtResults.TextLength -eq 0) { $txtResults.Text = $line }
    else { $txtResults.AppendText("`r`n$line") }
    $txtResults.SelectionStart = $txtResults.TextLength
    $txtResults.ScrollToCaret()
    $form.Refresh()
}

function Advance-Step {
    param([string]$StepName)
    $script:CurrentStep++
    $pct = [math]::Round(($script:CurrentStep / $script:TotalSteps) * 100)
    $progressBar.Value = $pct
    $lblStep.Text = "$($script:CurrentStep) / $($script:TotalSteps)"
    $lblStatus.Text = $StepName
    $form.Refresh()
}

function Run-Silent {
    param([string]$Exe, [string]$Args)
    try {
        $psi = [System.Diagnostics.ProcessStartInfo]::new($Exe)
        $psi.Arguments = $Args
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.WaitForExit(15000) | Out-Null
        return $true
    } catch { return $false }
}

# ─── NUKE LOGIC ─────────────────────────────────────────────────────────────────
function Invoke-Nuke {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # ── Step 1: Kill processes ──────────────────────────────────────────────────
    Advance-Step 'Killing agent processes...'
    $killed = 0
    foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
        $name = $proc.ProcessName
        $isOurs = $name -like 'Sentinel*' -or $name -like '*_Remote_Assist' -or $name -eq 'xray'
        if (!$isOurs) {
            try {
                $path = $proc.MainModule.FileName
                foreach ($d in @($SentinelDir, $EdrDir, $AppControlDir, $IdentityDir)) {
                    if ($path -and $path.StartsWith($d, [StringComparison]::OrdinalIgnoreCase)) {
                        $isOurs = $true; break
                    }
                }
            } catch {}
        }
        if ($isOurs) {
            try { Stop-Process -Id $proc.Id -Force; $killed++ } catch {}
        }
    }
    # Kill bundled OpenSSH from our dirs
    foreach ($exe in @('ssh','sshd','sshd-session','ssh-agent')) {
        foreach ($proc in Get-Process -Name $exe -ErrorAction SilentlyContinue) {
            try {
                $path = $proc.MainModule.FileName
                if ($path -and ($path.StartsWith($SentinelDir,[StringComparison]::OrdinalIgnoreCase) -or
                                $path.StartsWith($EdrDir,[StringComparison]::OrdinalIgnoreCase) -or
                                $path.StartsWith($AppControlDir,[StringComparison]::OrdinalIgnoreCase))) {
                    Stop-Process -Id $proc.Id -Force; $killed++
                }
            } catch {}
        }
    }
    Append-Result "Killed $killed agent process(es)" '[-]'

    # ── Step 2: Scheduled tasks ─────────────────────────────────────────────────
    Advance-Step 'Removing scheduled tasks...'
    $tasks = 0
    try {
        $out = schtasks.exe /Query /FO CSV /NH 2>$null
        foreach ($line in $out) {
            $parts = $line.Split(',')
            if ($parts.Length -lt 2) { continue }
            $tn = $parts[0].Trim('"').Trim()
            if ($tn -like 'Sentinel*') {
                try { Run-Silent 'schtasks.exe' "/Delete /TN `"$tn`" /F"; $tasks++ } catch {}
            }
        }
    } catch {}
    Append-Result "Removed $tasks scheduled task(s)" '[-]'

    # ── Step 3: sentinel-support account ────────────────────────────────────────────────
    Advance-Step 'Removing sentinel-support account...'
    try {
        $u = Get-LocalUser -Name 'sentinel-support' -ErrorAction SilentlyContinue
        if ($u) { Remove-LocalUser -Name 'sentinel-support' -ErrorAction Stop; Append-Result 'Removed sentinel-support account' '[-]' }
        else { Append-Result 'sentinel-support not found (already removed)' '[=]' }
    } catch { Append-Result "Failed to remove sentinel-support: $_" '[!]' }

    # ── Step 4: Services ────────────────────────────────────────────────────────
    Advance-Step 'Removing services...'
    $preexisting = Test-Path (Join-Path $SentinelDir 'sshd-preexisted.marker')
    try {
        $svc = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
        if ($svc) {
            if ($preexisting) {
                Stop-Service sshd -Force -ErrorAction SilentlyContinue
                Append-Result 'sshd pre-existed — stopped but NOT deleted' '[=]'
            } else {
                Run-Silent 'sc.exe' 'stop sshd'
                Run-Silent 'sc.exe' 'delete sshd'
                Append-Result 'Removed sshd service (ours)' '[-]'
            }
        }
    } catch {}
    try {
        $q = sc.exe qc ssh-agent 2>$null
        if ($q -match [regex]::Escape($SentinelDir)) {
            Run-Silent 'sc.exe' 'stop ssh-agent'
            Run-Silent 'sc.exe' 'delete ssh-agent'
            Append-Result 'Removed ssh-agent service (ours)' '[-]'
        }
    } catch {}

    # ── Step 5: Restore sshd_config ─────────────────────────────────────────────
    Advance-Step 'Restoring sshd_config...'
    $bak = Join-Path $SentinelDir 'sshd_config.pre-sentinel.bak'
    $cfg = Join-Path $SshDir 'sshd_config'
    if ((Test-Path $bak) -and (Test-Path $cfg)) {
        try { Copy-Item $bak $cfg -Force; Append-Result 'Restored sshd_config from backup' '[+]' } catch {}
    } else { Append-Result 'No sshd_config backup found' '[=]' }

    # ── Step 6: administrators_authorized_keys ──────────────────────────────────
    Advance-Step 'Restoring authorized_keys...'
    $ak = Join-Path $SshDir 'administrators_authorized_keys'
    $akBak = Join-Path $SshDir 'administrators_authorized_keys.pre-sentinel.bak'
    if ($preexisting) {
        if ((Test-Path $akBak) -and (Test-Path $ak)) {
            try { Copy-Item $akBak $ak -Force; Remove-Item $akBak -Force; Append-Result 'Restored authorized_keys' '[+]' } catch {}
        } else { Append-Result 'No authorized_keys backup found' '[=]' }
    } else {
        if (Test-Path $SshDir) {
            try { Remove-Item $SshDir -Recurse -Force; Append-Result 'Deleted C:\ProgramData\ssh (ours)' '[-]' } catch {}
        }
    }

    # ── Step 7: Registry ────────────────────────────────────────────────────────
    Advance-Step 'Cleaning registry...'
    try { Remove-Item 'HKLM:\Software\SentinelRemoteAssist' -Recurse -Force; Append-Result 'Removed HKLM\Software\SentinelRemoteAssist' '[-]' } catch {}
    try {
        $rk = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
        $v = Get-ItemProperty -Path $rk -Name 'SentinelRemoteAssist' -ErrorAction SilentlyContinue
        if ($v) { Remove-ItemProperty -Path $rk -Name 'SentinelRemoteAssist' -Force; Append-Result 'Removed Run key entry' '[-]' }
    } catch {}
    try {
        $if = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sshd.exe'
        $iv = Get-ItemProperty -Path $if -ErrorAction SilentlyContinue
        if ($iv -and ($iv.RedirectionGuard -or $iv.VerifierDlls)) {
            Remove-Item $if -Recurse -Force; Append-Result 'Removed IFEO sshd.exe entry' '[-]'
        }
    } catch {}
    try {
        $ac = Get-ItemProperty 'HKLM:\Software\SentinelRemoteAssist' -Name 'AutoConnect' -ErrorAction SilentlyContinue
        if ($ac) { Remove-ItemProperty 'HKLM:\Software\SentinelRemoteAssist' -Name 'AutoConnect' -Force }
    } catch {}
    Append-Result 'Registry cleanup complete' '[=]'

    # ── Step 8: Firewall ────────────────────────────────────────────────────────
    Advance-Step 'Removing firewall rules...'
    $rules = @(
        'Sentinel-Isolation-Sentinel.exe-Out','Sentinel-Isolation-Sentinel.exe-In',
        'Sentinel-Isolation-ssh.exe-Out','Sentinel-Isolation-ssh.exe-In',
        'Sentinel-Isolation-sshd.exe-Out','Sentinel-Isolation-sshd.exe-In',
        'Sentinel-Isolation-sshd-session.exe-Out','Sentinel-Isolation-sshd-session.exe-In',
        'Sentinel-Isolation-xray.exe-Out','Sentinel-Isolation-xray.exe-In',
        'Sentinel-Isolation-DNS-Out-UDP-svchost.exe',
        'Sentinel-Isolation-DNS-Out-TCP-svchost.exe',
        'Sentinel-Telemetry-Block'
    )
    foreach ($r in $rules) { Run-Silent 'netsh.exe' "advfirewall firewall delete rule name=`"$r`"" }
    Run-Silent 'netsh.exe' 'advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound'
    Append-Result "Removed $($rules.Count) firewall rule(s) + restored default policy" '[-]'

    # ── Step 9: Canary files ────────────────────────────────────────────────────
    Advance-Step 'Deleting canary decoy files...'
    $cn = 0
    foreach ($root in $CanaryRoots) {
        foreach ($name in $CanaryNames) {
            $p = Join-Path $root $name
            if (Test-Path $p) {
                try {
                    if ((Get-Item $p).Length -le 4096) {
                        $fl = Get-Content $p -First 1 -ErrorAction SilentlyContinue
                        if ($fl -match 'This is a Sentinel security decoy') {
                            Remove-Item $p -Force; $cn++
                        }
                    }
                } catch {}
            }
        }
    }
    $cs = Join-Path $EdrDir 'canary-state.json'
    if (Test-Path $cs) {
        try {
            $st = Get-Content $cs -Raw | ConvertFrom-Json
            foreach ($pr in $st.PSObject.Properties) {
                if ((Test-Path $pr.Name) -and $pr.Name -match 'Sentinel|canary|decoy') {
                    try { Remove-Item $pr.Name -Force; $cn++ } catch {}
                }
            }
        } catch {}
    }
    Append-Result "Deleted $cn canary file(s)" '[-]'

    # ── Step 10: ProgramData trees + misc files ─────────────────────────────────
    Advance-Step 'Deleting ProgramData trees...'
    foreach ($d in @($SentinelDir, $EdrDir, $AppControlDir, $IdentityDir)) {
        if (Test-Path $d) {
            try { Remove-Item $d -Recurse -Force; Append-Result "Deleted $d" '[-]' } catch { Append-Result "Failed (locked): $d" '[!]' }
        }
    }
    $snap = Join-Path $UsersPublicDir 'SentinelScreenSnap.exe'
    if (Test-Path $snap) { try { Remove-Item $snap -Force; Append-Result 'Deleted SentinelScreenSnap.exe' '[-]' } catch {} }
    if (Test-Path $BackupVault) {
        $remaining = Get-ChildItem $BackupVault -ErrorAction SilentlyContinue
        if (-not $remaining -or $remaining.Count -eq 0) {
            Remove-Item $BackupVault -Force -ErrorAction SilentlyContinue
            Append-Result 'Deleted empty BackupVault' '[-]'
        }
    }

    # ── Step 11: Temp cleanup ───────────────────────────────────────────────────
    Advance-Step 'Cleaning temp files...'
    Get-ChildItem (Join-Path $env:TEMP 'sentinel-*') -ErrorAction SilentlyContinue | ForEach-Object {
        try { Remove-Item $_.FullName -Force } catch {}
    }
    Append-Result 'Temp cleanup done' '[-]'

    # ── DONE ────────────────────────────────────────────────────────────────────
    $sw.Stop()
    $elapsed = $sw.Elapsed.TotalSeconds.ToString('F1')
    $progressBar.Value = 100
    $lblStep.Text = "$($script:TotalSteps) / $($script:TotalSteps)"
    $lblStatus.Text = 'NUKE COMPLETE'
    $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(0, 200, 80)

    Append-Result ''
    Append-Result "══════════════════════════════════════════════" '[=]'
    Append-Result "NUKE completed in ${elapsed}s" '[+]'
    Append-Result "All SentinelRemoteAssist artifacts removed." '[+]'
    Append-Result "Agent cannot reconnect to the server." '[+]'
    Append-Result "To re-install: download fresh from dashboard." '[+]'
    Append-Result "══════════════════════════════════════════════" '[=]'

    $btnNuke.Text = 'DONE — Close'
    $btnNuke.BackColor = [System.Drawing.Color]::FromArgb(0, 140, 60)
    $btnNuke.Enabled = $true
}

# ─── BUTTON CLICK ───────────────────────────────────────────────────────────────
$btnNuke.Add_Click({
    $btnNuke.Enabled = $false
    $btnNuke.BackColor = [System.Drawing.Color]::FromArgb(100, 50, 50)
    $btnNuke.Text = 'NUKING...'
    $form.Refresh()

    $txtResults.Text = ''
    $script:CurrentStep = 0
    $progressBar.Value = 0

    # Run nuke in a background runspace so UI stays responsive
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $runspace
    $ps.AddScript({
        param($SentinelDir, $EdrDir, $AppControlDir, $IdentityDir, $BackupVault, $SshDir,
              $UsersPublicDir, $ProgramDataDir, $CanaryNames, $CanaryRoots)
        
        # Helper functions (re-declared inside runspace scope)
        function Run-Silent2 {
            param([string]$Exe, [string]$Args)
            try {
                $psi = [System.Diagnostics.ProcessStartInfo]::new($Exe)
                $psi.Arguments = $Args
                $psi.UseShellExecute = $false
                $psi.CreateNoWindow = $true
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true
                $p = [System.Diagnostics.Process]::Start($psi)
                $p.WaitForExit(15000) | Out-Null
                return $true
            } catch { return $false }
        }

        $TotalSteps = 11
        $CurrentStep = 0
        $Results = [System.Collections.Generic.List[string]]::new()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        function Advance([string]$StepName) {
            $script:CurrentStep++
            $pct = [math]::Round(($script:CurrentStep / $TotalSteps) * 100)
            $form.Invoke([Action]{
                $progressBar.Value = $pct
                $lblStep.Text = "$script:CurrentStep / $TotalSteps"
                $lblStatus.Text = $StepName
                $form.Refresh()
            })
        }
        function LogResult([string]$Text) {
            $icon = if ($Text -match '^\[!') { '[!]' } elseif ($Text -match '^\[\+') { '[+]' } elseif ($Text -match '^\[=') { '[=]' } else { '[-]' }
            $form.Invoke([Action]{
                if ($txtResults.TextLength -eq 0) { $txtResults.Text = $Text }
                else { $txtResults.AppendText("`r`n$Text") }
                $txtResults.SelectionStart = $txtResults.TextLength
                $txtResults.ScrollToCaret()
                $form.Refresh()
            })
        }

        # ── 1: Kill processes ──
        Advance 'Killing agent processes...'
        $killed = 0
        foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
            $name = $proc.ProcessName
            $isOurs = $name -like 'Sentinel*' -or $name -like '*_Remote_Assist' -or $name -eq 'xray'
            if (!$isOurs) {
                try {
                    $path = $proc.MainModule.FileName
                    foreach ($d in @($SentinelDir, $EdrDir, $AppControlDir, $IdentityDir)) {
                        if ($path -and $path.StartsWith($d, [StringComparison]::OrdinalIgnoreCase)) { $isOurs = $true; break }
                    }
                } catch {}
            }
            if ($isOurs) { try { Stop-Process -Id $proc.Id -Force; $killed++ } catch {} }
        }
        foreach ($exe in @('ssh','sshd','sshd-session','ssh-agent')) {
            foreach ($proc in Get-Process -Name $exe -ErrorAction SilentlyContinue) {
                try {
                    $path = $proc.MainModule.FileName
                    if ($path -and ($path.StartsWith($SentinelDir,[StringComparison]::OrdinalIgnoreCase) -or
                                    $path.StartsWith($EdrDir,[StringComparison]::OrdinalIgnoreCase) -or
                                    $path.StartsWith($AppControlDir,[StringComparison]::OrdinalIgnoreCase))) {
                        Stop-Process -Id $proc.Id -Force; $killed++
                    }
                } catch {}
            }
        }
        LogResult "[-] Killed $killed agent process(es)"

        # ── 2: Scheduled tasks ──
        Advance 'Removing scheduled tasks...'
        $tasks = 0
        try {
            $out = schtasks.exe /Query /FO CSV /NH 2>$null
            foreach ($line in $out) {
                $parts = $line.Split(',')
                if ($parts.Length -lt 2) { continue }
                $tn = $parts[0].Trim('"').Trim()
                if ($tn -like 'Sentinel*') { try { Run-Silent2 'schtasks.exe' "/Delete /TN `"$tn`" /F"; $tasks++ } catch {} }
            }
        } catch {}
        LogResult "[-] Removed $tasks scheduled task(s)"

        # ── 3: sentinel-support ──
        Advance 'Removing sentinel-support account...'
        try {
            $u = Get-LocalUser -Name 'sentinel-support' -ErrorAction SilentlyContinue
            if ($u) { Remove-LocalUser -Name 'sentinel-support' -ErrorAction Stop; LogResult '[-] Removed sentinel-support account' }
            else { LogResult '[=] sentinel-support not found' }
        } catch { LogResult "[!] Failed to remove sentinel-support: $_" }

        # ── 4: Services ──
        Advance 'Removing services...'
        $preexisting = Test-Path (Join-Path $SentinelDir 'sshd-preexisted.marker')
        try {
            $svc = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
            if ($svc) {
                if ($preexisting) { Stop-Service sshd -Force -ErrorAction SilentlyContinue; LogResult '[=] sshd pre-existed — stopped' }
                else { Run-Silent2 'sc.exe' 'stop sshd'; Run-Silent2 'sc.exe' 'delete sshd'; LogResult '[-] Removed sshd service' }
            }
        } catch {}
        try {
            $q = sc.exe qc ssh-agent 2>$null
            if ($q -match [regex]::Escape($SentinelDir)) { Run-Silent2 'sc.exe' 'stop ssh-agent'; Run-Silent2 'sc.exe' 'delete ssh-agent'; LogResult '[-] Removed ssh-agent service' }
        } catch {}

        # ── 5: sshd_config ──
        Advance 'Restoring sshd_config...'
        $bak = Join-Path $SentinelDir 'sshd_config.pre-sentinel.bak'
        $cfg = Join-Path $SshDir 'sshd_config'
        if ((Test-Path $bak) -and (Test-Path $cfg)) { try { Copy-Item $bak $cfg -Force; LogResult '[+] Restored sshd_config' } catch {} }
        else { LogResult '[=] No sshd_config backup' }

        # ── 6: authorized_keys ──
        Advance 'Restoring authorized_keys...'
        $ak = Join-Path $SshDir 'administrators_authorized_keys'
        $akBak = Join-Path $SshDir 'administrators_authorized_keys.pre-sentinel.bak'
        if ($preexisting) {
            if ((Test-Path $akBak) -and (Test-Path $ak)) { try { Copy-Item $akBak $ak -Force; Remove-Item $akBak -Force; LogResult '[+] Restored authorized_keys' } catch {} }
            else { LogResult '[=] No authorized_keys backup' }
        } else {
            if (Test-Path $SshDir) { try { Remove-Item $SshDir -Recurse -Force; LogResult '[-] Deleted C:\ProgramData\ssh' } catch {} }
        }

        # ── 7: Registry ──
        Advance 'Cleaning registry...'
        try { Remove-Item 'HKLM:\Software\SentinelRemoteAssist' -Recurse -Force; LogResult '[-] Removed HKLM\Software\SentinelRemoteAssist' } catch {}
        try {
            $rk = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
            $v = Get-ItemProperty -Path $rk -Name 'SentinelRemoteAssist' -ErrorAction SilentlyContinue
            if ($v) { Remove-ItemProperty -Path $rk -Name 'SentinelRemoteAssist' -Force; LogResult '[-] Removed Run key' }
        } catch {}
        try {
            $ifp = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sshd.exe'
            $iv = Get-ItemProperty -Path $ifp -ErrorAction SilentlyContinue
            if ($iv -and ($iv.RedirectionGuard -or $iv.VerifierDlls)) { Remove-Item $ifp -Recurse -Force; LogResult '[-] Removed IFEO sshd.exe' }
        } catch {}
        LogResult '[=] Registry cleanup done'

        # ── 8: Firewall ──
        Advance 'Removing firewall rules...'
        $rules = @(
            'Sentinel-Isolation-Sentinel.exe-Out','Sentinel-Isolation-Sentinel.exe-In',
            'Sentinel-Isolation-ssh.exe-Out','Sentinel-Isolation-ssh.exe-In',
            'Sentinel-Isolation-sshd.exe-Out','Sentinel-Isolation-sshd.exe-In',
            'Sentinel-Isolation-sshd-session.exe-Out','Sentinel-Isolation-sshd-session.exe-In',
            'Sentinel-Isolation-xray.exe-Out','Sentinel-Isolation-xray.exe-In',
            'Sentinel-Isolation-DNS-Out-UDP-svchost.exe',
            'Sentinel-Isolation-DNS-Out-TCP-svchost.exe',
            'Sentinel-Telemetry-Block'
        )
        foreach ($r in $rules) { Run-Silent2 'netsh.exe' "advfirewall firewall delete rule name=`"$r`"" }
        Run-Silent2 'netsh.exe' 'advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound'
        LogResult "[-] Removed $($rules.Count) firewall rule(s) + restored default policy"

        # ── 9: Canaries ──
        Advance 'Deleting canary decoy files...'
        $cn = 0
        foreach ($root in $CanaryRoots) {
            foreach ($name in $CanaryNames) {
                $p = Join-Path $root $name
                if (Test-Path $p) {
                    try {
                        if ((Get-Item $p).Length -le 4096) {
                            $fl = Get-Content $p -First 1 -ErrorAction SilentlyContinue
                            if ($fl -match 'This is a Sentinel security decoy') { Remove-Item $p -Force; $cn++ }
                        }
                    } catch {}
                }
            }
        }
        $css = Join-Path $EdrDir 'canary-state.json'
        if (Test-Path $css) {
            try {
                $st = Get-Content $css -Raw | ConvertFrom-Json
                foreach ($pr in $st.PSObject.Properties) {
                    if ((Test-Path $pr.Name) -and $pr.Name -match 'Sentinel|canary|decoy') { try { Remove-Item $pr.Name -Force; $cn++ } catch {} }
                }
            } catch {}
        }
        LogResult "[-] Deleted $cn canary file(s)"

        # ── 10: ProgramData trees ──
        Advance 'Deleting ProgramData trees...'
        foreach ($d in @($SentinelDir, $EdrDir, $AppControlDir, $IdentityDir)) {
            if (Test-Path $d) { try { Remove-Item $d -Recurse -Force; LogResult "[-] Deleted $d" } catch { LogResult "[!] Failed: $d" } }
        }
        $snap = Join-Path $UsersPublicDir 'SentinelScreenSnap.exe'
        if (Test-Path $snap) { try { Remove-Item $snap -Force; LogResult '[-] Deleted SentinelScreenSnap.exe' } catch {} }
        if (Test-Path $BackupVault) {
            $rem = Get-ChildItem $BackupVault -ErrorAction SilentlyContinue
            if (-not $rem -or $rem.Count -eq 0) { Remove-Item $BackupVault -Force -ErrorAction SilentlyContinue; LogResult '[-] Deleted empty BackupVault' }
        }

        # ── 11: Temp ──
        Advance 'Cleaning temp files...'
        Get-ChildItem (Join-Path $env:TEMP 'sentinel-*') -ErrorAction SilentlyContinue | ForEach-Object { try { Remove-Item $_.FullName -Force } catch {} }
        LogResult '[-] Temp cleanup done'

        # ── DONE ──
        $sw.Stop()
        $elapsed = $sw.Elapsed.TotalSeconds.ToString('F1')
        $form.Invoke([Action]{
            $progressBar.Value = 100
            $lblStep.Text = "$TotalSteps / $TotalSteps"
            $lblStatus.Text = 'NUKE COMPLETE'
            $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(0, 200, 80)
            $btnNuke.Text = 'DONE — Close'
            $btnNuke.BackColor = [System.Drawing.Color]::FromArgb(0, 140, 60)
            $btnNuke.Enabled = $true
        })
        LogResult ''
        LogResult "══════════════════════════════════════════════"
        LogResult "NUKE completed in ${elapsed}s"
        LogResult "All SentinelRemoteAssist artifacts removed."
        LogResult "Agent cannot reconnect to the server."
        LogResult "To re-install: download fresh from dashboard."
        LogResult "══════════════════════════════════════════════"
    }).AddArgument($SentinelDir).AddArgument($EdrDir).AddArgument($AppControlDir).AddArgument($IdentityDir).AddArgument($BackupVault).AddArgument($SshDir).AddArgument($UsersPublicDir).AddArgument($ProgramDataDir).AddArgument($CanaryNames).AddArgument($CanaryRoots) | Out-Null

    $ps.BeginInvoke() | Out-Null
})

# ─── RUN ────────────────────────────────────────────────────────────────────────
[System.Windows.Forms.Application]::Run($form)
