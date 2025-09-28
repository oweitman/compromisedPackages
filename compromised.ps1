#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

# === Konfiguration ===
$ListUrl = 'https://raw.githubusercontent.com/DEIN_ORG/DEIN_REPO/main/compromised-packages.txt'

Write-Host ""
Write-Host "⬇️  Lade Kompromittiertenliste von: $ListUrl" -ForegroundColor Cyan
try {
    $raw = (Invoke-WebRequest -Uri $ListUrl -UseBasicParsing).Content
} catch {
    Write-Host "❌ Konnte Liste nicht laden: $ListUrl" -ForegroundColor Red
    exit 2
}

# === Parsen in Hashtable: $compromised["pkg"] = @("v1","v2",...) ===
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

Write-Host ""
Write-Host 'Searching for compromised NPM packages in lockfiles...' -ForegroundColor Cyan

# Lockfiles suchen
$lockfiles = Get-ChildItem -Recurse -File | Where-Object {
    $_.Name -in @('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml')
}
if (-not $lockfiles) {
    Write-Host "No lockfiles found." -ForegroundColor Yellow
    exit
}

# -------- Pattern vorbereiten --------
$patterns = New-Object System.Collections.Generic.List[string]
foreach ($pkg in $compromised.Keys) {
    foreach ($ver in $compromised[$pkg]) {
        $pkgEsc = [regex]::Escape($pkg)
        $verEsc = [regex]::Escape($ver)
        # JSON
        $patterns.Add('"' + $pkgEsc + '"\s*:\s*".*' + $verEsc + '"')
        # yarn.lock
        $patterns.Add('^' + $pkgEsc + '@' + $verEsc + '\b')
    }
}
$bigPattern = ($patterns -join "|")

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
    }
}

Write-Progress -Activity "Checking lockfiles for compromised packages..." -Status "100% completed" -PercentComplete 100

if (-not $found) {
    Write-Host ""
    Write-Host '✅ No compromised packages found in lockfiles.' -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host '⚠️ Please remove the affected packages and regenerate the lockfiles!' -ForegroundColor Magenta
}
