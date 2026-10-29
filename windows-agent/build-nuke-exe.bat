@echo off
REM ═══════════════════════════════════════════════════════════════════════════════
REM  build-nuke-exe.bat — Converts NUKE-Agent.ps1 to NUKE-Agent.exe
REM  
REM  Usage: Double-click this file on a Windows PC, or run from elevated cmd.
REM  Prerequisites: PowerShell 5.1+ (ships with Windows 10/11)
REM ═══════════════════════════════════════════════════════════════════════════════
echo.
echo  Building NUKE-Agent.exe from NUKE-Agent.ps1...
echo.

REM Check for admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  ERROR: Must run as Administrator!
    echo  Right-click this file and select "Run as administrator"
    pause
    exit /b 1
)

REM Install ps2exe module if not present
echo  Checking/installing ps2exe module...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "if (-not (Get-Module -ListAvailable -Name ps2exe)) { Install-Module ps2exe -Force -Scope CurrentUser -SkipPublisherCheck }"

REM Build the exe
echo  Compiling NUKE-Agent.exe...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Import-Module ps2exe; " ^
    "ps2exe -InputFile '%~dp0NUKE-Agent.ps1' -OutputFile '%~dp0NUKE-Agent.exe' " ^
    "-Title 'NUKE-Agent' " ^
    "-Description 'Complete removal of SentinelRemoteAssist agent from Windows' " ^
    "-Version '1.0.0' " ^
    "-Copyright 'SentinelMDM' " ^
    "-RequireAdmin " ^
    "-NoOutput " ^
    "-SupportsElevation " ^
    "-IconFile '%~dp0icon.ico' 2>$null; " ^
    "if (-not (Test-Path '%~dp0NUKE-Agent.exe')) { " ^
    "  ps2exe -InputFile '%~dp0NUKE-Agent.ps1' -OutputFile '%~dp0NUKE-Agent.exe' " ^
    "  -Title 'NUKE-Agent' -Version '1.0.0' -RequireAdmin -NoOutput -SupportsElevation }"

if %errorlevel% equ 0 (
    echo.
    echo  ================================================================
    echo           NUKE-Agent.exe built successfully!
    echo  ================================================================
    echo.
    echo  Location: %~dp0NUKE-Agent.exe
    echo.
    echo  To use:
    echo    1. Copy NUKE-Agent.exe to the target Windows PC
    echo    2. Right-click - Run as administrator
    echo    3. Click the NUKE button
    echo.
    echo  The exe requires admin elevation. It will prompt if not elevated.
    echo.
) else (
    echo.
    echo  Build failed. You can still run the PS1 directly:
    echo    powershell -ExecutionPolicy Bypass -File NUKE-Agent.ps1
    echo.
)

pause
