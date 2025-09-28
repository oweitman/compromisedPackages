# compromised-singleurl-debug.ps1
# Requires -Version 5.1
<#
  Single-URL compromised package scanner with debug output
  - Uses one URL (set in $ListUrl)
  - Detects HTML responses and rejects them
  - Caches downloaded list to %TEMP%\compromised-packages.txt
  - Shows progress via Write-Progress while scanning lockfiles
  - When $ShowContent is $true prints the downloaded file (first N lines)
#>

$ErrorActionPreference = 'Stop'

# === Konfiguration ===
# Use jsDelivr (CDN) to avoid raw.githubusercontent redirect issues, or set your working raw URL here.
$ListUrl = 'https://cdn.jsdelivr.net/gh/oweitman/compromisedPackages@main/compromised-packages.txt'
$Cache = Join-Path $env:TEMP 'compromised-packages.txt'

# Debug: set to $true to print the downloaded file (first $ShowLines lines)
$ShowContent = $true
$ShowLines = 200

Write-Host ""
Write-Host "Lade Kompromittiertenliste von: $ListUrl" -ForegroundColor Cyan

# === Download (single URL) ===
$downloaded = $false
try {
    Invoke-WebRequest -Uri $ListUrl -UseBasicParsing -OutFile "$Cache.tmp" -ErrorAction Stop
    # Quick sanity-check: read first few lines to detect HTML pages
    $firstLines = Get-Content "$Cache.tmp" -TotalCount 6
    $firstText = ($firstLines -join "`n")
    if ($firstText -match '<!doctype|<html|<head') {
        Write-Warning "Downloaded content looks like HTML (redirect/login/preview page). Will not use it."
        Remove-Item "$Cache.tmp" -ErrorAction SilentlyContinue
        $downloaded = $false
    } else {
        Move-Item -Force "$Cache.tmp" $Cache
        Write-Host "Liste erfolgreich heruntergeladen und zwischengespeichert: $Cache"
        $downloaded = $true
    }
} catch {
    Write-Warning "Download failed from $ListUrl : $($_.Exception.Message)"
    if (Test-Path "$Cache.tmp") { Remove-Item "$Cache.tmp" -ErrorAction SilentlyContinue }
    $downloaded = $false
}

if (-not $downloaded) {
    if (Test-Path $Cache) {
        Write-Warning "Verwende lokale Cache-Datei: $Cache"
    } else {
        Write-Error "Konnte die Liste nicht laden und kein Cache gefunden. Abbruch."
        exit 2
    }
}

# Optionally print the file for debugging
<# if ($ShowContent) {
    Write-Host "`n--- Inhalt der genutzten Datei (erste $ShowLines Zeilen) ---`n"
    Get-Content $Cache | Select-Object -First $ShowLines | ForEach-Object { Write-Host "  $_" }
    Write-Host "`n--- Ende (gegebenenfalls nur Kopf der Datei gezeigt) ---`n"
} #>

# === Parsen in Hashtable: $compromised["pkg"] = @("v1","v2",...) ===
$raw = Get-Content $Cache -Raw
$compromised = @{}
$raw -split "`n" | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith('#')) { return }
    $idx = $line.IndexOf(':')
    if ($idx -lt 0) { return }
    $pkg = $line.Substring(0, $idx).Trim()
    $vers = $line.Substring($idx + 1).Trim() -split '\s+'
    if ($pkg -and $vers.Count -gt 0) {
        $compromised[$pkg] = $vers
    }
}

if ($compromised.Keys.Count -eq 0) {
    Write-Warning "Keine Pakete aus der Liste geparst. Bitte überprüfe die Datei: $Cache"
    exit 1
}

Write-Host ""
Write-Host 'Searching for compromised NPM packages in lockfiles...' -ForegroundColor Cyan

# Lockfiles suchen
$lockfiles = Get-ChildItem -Recurse -File | Where-Object {
    $_.Name -in @('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml')
}
if (-not $lockfiles) {
    Write-Host "No lockfiles found in $(Get-Location)." -ForegroundColor Yellow
    exit 0
}

# -------- Pattern vorbereiten --------
$patterns = New-Object System.Collections.Generic.List[string]
foreach ($pkg in $compromised.Keys) {
    foreach ($ver in $compromised[$pkg]) {
        $pkgEsc = [regex]::Escape($pkg)
        $verEsc = [regex]::Escape($ver)
        # JSON form: "pkg": "....ver...."
        $patterns.Add('"' + $pkgEsc + '"\s*:\s*".*' + $verEsc + '"')
        # yarn.lock form: ^pkg@ver\b
        $patterns.Add('^' + $pkgEsc + '@' + $verEsc + '\b')
    }
}
$bigPattern = ($patterns -join "|")

# Progress vars
$totalFiles   = $lockfiles.Count
$currentFile  = 0
$lastProgress = -1
$found = $false

foreach ($file in $lockfiles) {
    $currentFile++
    $percent = [math]::Floor(($currentFile / $totalFiles) * 100)
    if ($percent -ge $lastProgress + 1 -and $percent -le 100) {
        Write-Progress -Activity "Checking lockfiles for compromised packages..." `
                       -Status "$percent% completed" `
                       -PercentComplete $percent
        $lastProgress = $percent
    }

    $matches = Select-String -Path $file.FullName -Pattern $bigPattern -AllMatches
    if ($matches) {
        Write-Host ""
        Write-Host "[!] Found in: $($file.FullName)" -ForegroundColor Red
        foreach ($m in $matches) {
            Write-Host $m.Line -ForegroundColor Yellow
        }
        $found = $true
    } else {
        Write-Host "No matches in $($file.Name)"
    }
}

Write-Progress -Activity "Checking lockfiles for compromised packages..." -Status "100% completed" -PercentComplete 100

if (-not $found) {
    Write-Host ""
    Write-Host 'No compromised packages found in lockfiles.' -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host 'Please remove the affected packages and regenerate the lockfiles!' -ForegroundColor Magenta
}

# End of script
