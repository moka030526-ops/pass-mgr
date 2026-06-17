<#
Create two pass-mgr shortcuts on the Windows Desktop:

    "pass-mgr (View)"  -> pass-mgr-gui.exe            (locked vault icon)
    "pass-mgr (Edit)"  -> pass-mgr-gui.exe --write    (unlocked vault icon)

Both point at the SAME windowed binary (no console window); only the --write flag
and the icon differ.

NOTE: pass-mgr-gui.exe is a BUILD ARTIFACT and is NOT shipped in the repo. Build it
first (`cargo build --release` -> target\release\pass-mgr-gui.exe), or copy it
somewhere and point this script at it.

Usage (PowerShell):

  # Simplest: after building in the repo. Auto-finds target\release\pass-mgr-gui.exe
  # (then target\debug, then the windows-gnu cross target, then your PATH) and the
  # committed icons in packaging\icons:
  powershell -ExecutionPolicy Bypass -File make-shortcuts.ps1

  # Point at the exe explicitly:
  powershell -ExecutionPolicy Bypass -File make-shortcuts.ps1 -Exe "C:\apps\pass-mgr\pass-mgr-gui.exe"

  # Deployed install (exe + the icons copied into ONE folder):
  powershell -ExecutionPolicy Bypass -File make-shortcuts.ps1 -InstallDir "C:\Program Files\pass-mgr"
#>

param(
    [string]$Exe = "",          # path to pass-mgr-gui.exe (auto-detected if empty)
    [string]$IconDir = "",      # folder holding the two .ico files (defaults to repo icons)
    [string]$InstallDir = ""    # a folder containing the exe (+ icons) for a deployed install
)

$ErrorActionPreference = "Stop"

# repo root = two levels up from packaging\windows\
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# --- locate the binary -------------------------------------------------------
if (-not $Exe) {
    if ($InstallDir) {
        $Exe = Join-Path $InstallDir "pass-mgr-gui.exe"
    } else {
        $candidates = @(
            (Join-Path $repo "target\release\pass-mgr-gui.exe"),
            (Join-Path $repo "target\debug\pass-mgr-gui.exe"),
            (Join-Path $repo "target\x86_64-pc-windows-gnu\release\pass-mgr-gui.exe")
        )
        foreach ($c in $candidates) { if (Test-Path $c) { $Exe = $c; break } }
        if (-not $Exe) {
            $onPath = Get-Command pass-mgr-gui.exe -ErrorAction SilentlyContinue
            if ($onPath) { $Exe = $onPath.Source }
        }
    }
}

if (-not $Exe -or -not (Test-Path $Exe)) {
    Write-Host ""
    Write-Host "Could not find pass-mgr-gui.exe." -ForegroundColor Yellow
    Write-Host "It is a build artifact, not part of the repo. Do one of:"
    Write-Host "  * build it:   cargo build --release      (-> target\release\pass-mgr-gui.exe)"
    Write-Host "  * pass it:    make-shortcuts.ps1 -Exe `"C:\path\to\pass-mgr-gui.exe`""
    Write-Host "  * deploy it:  copy the exe + the packaging\icons folder into one directory,"
    Write-Host "                then: make-shortcuts.ps1 -InstallDir `"C:\that\directory`""
    exit 1
}
$Exe = (Resolve-Path $Exe).Path

# --- locate the icons --------------------------------------------------------
if (-not $IconDir) {
    if ($InstallDir -and (Test-Path (Join-Path $InstallDir "pass-mgr-locked.ico"))) {
        $IconDir = $InstallDir
    } elseif ($InstallDir -and (Test-Path (Join-Path $InstallDir "icons\pass-mgr-locked.ico"))) {
        $IconDir = Join-Path $InstallDir "icons"
    } else {
        $IconDir = Join-Path $repo "packaging\icons"
    }
}
$lockedIco = Join-Path $IconDir "pass-mgr-locked.ico"
$unlockIco = Join-Path $IconDir "pass-mgr-unlocked.ico"
foreach ($p in @($lockedIco, $unlockIco)) {
    if (-not (Test-Path $p)) {
        throw "missing icon: $p  (generate with packaging\icons\make_icons.py, or pass -IconDir)"
    }
}
$lockedIco = (Resolve-Path $lockedIco).Path
$unlockIco = (Resolve-Path $unlockIco).Path

# --- create the shortcuts ----------------------------------------------------
$workDir = Split-Path -Parent $Exe
$desktop = [Environment]::GetFolderPath("Desktop")
$shell   = New-Object -ComObject WScript.Shell

function New-PMShortcut($name, $arguments, $icon) {
    $lnk = $shell.CreateShortcut((Join-Path $desktop "$name.lnk"))
    $lnk.TargetPath       = $Exe
    $lnk.Arguments        = $arguments
    $lnk.WorkingDirectory = $workDir
    $lnk.IconLocation     = "$icon,0"
    $lnk.Description       = "pass-mgr encrypted estate vault"
    $lnk.Save()
    Write-Host "created: $name.lnk"
}

New-PMShortcut "pass-mgr (View)" ""        $lockedIco
New-PMShortcut "pass-mgr (Edit)" "--write" $unlockIco
Write-Host ""
Write-Host "Done. Two shortcuts are on your Desktop:"
Write-Host "  pass-mgr (View)  - read-only  (locked vault icon)"
Write-Host "  pass-mgr (Edit)  - edit mode  (unlocked vault icon)"
Write-Host "exe:   $Exe"
Write-Host "icons: $IconDir"
