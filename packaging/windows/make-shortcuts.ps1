<#
Create two pass-mgr shortcuts on the Windows Desktop:

    "pass-mgr (View)"  -> pass-mgr-gui.exe            (locked vault icon)
    "pass-mgr (Edit)"  -> pass-mgr-gui.exe --write    (unlocked vault icon)

Both point at the SAME windowed binary (no console window); only the --write flag
and the icon differ.

Usage (PowerShell, in the folder where you put the files):

    powershell -ExecutionPolicy Bypass -File make-shortcuts.ps1 `
        -InstallDir "C:\Program Files\pass-mgr"

-InstallDir must contain pass-mgr-gui.exe and an `icons` subfolder with
pass-mgr-locked.ico and pass-mgr-unlocked.ico (copy them from packaging\icons).
If omitted, the script's own folder is used.
#>

param(
    [string]$InstallDir = $PSScriptRoot
)

$ErrorActionPreference = "Stop"

$exe        = Join-Path $InstallDir "pass-mgr-gui.exe"
$lockedIco  = Join-Path $InstallDir "icons\pass-mgr-locked.ico"
$unlockIco  = Join-Path $InstallDir "icons\pass-mgr-unlocked.ico"

foreach ($p in @($exe, $lockedIco, $unlockIco)) {
    if (-not (Test-Path $p)) { throw "missing: $p" }
}

$desktop = [Environment]::GetFolderPath("Desktop")
$shell   = New-Object -ComObject WScript.Shell

function New-PMShortcut($name, $arguments, $icon) {
    $lnk = $shell.CreateShortcut((Join-Path $desktop "$name.lnk"))
    $lnk.TargetPath       = $exe
    $lnk.Arguments        = $arguments
    $lnk.WorkingDirectory = $InstallDir
    $lnk.IconLocation     = $icon
    $lnk.Description       = "pass-mgr encrypted estate vault"
    $lnk.Save()
    Write-Host "created: $name.lnk"
}

New-PMShortcut "pass-mgr (View)" ""        $lockedIco
New-PMShortcut "pass-mgr (Edit)" "--write" $unlockIco
Write-Host "Done. Two shortcuts are on your Desktop."
