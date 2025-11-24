param(
    [Parameter(Mandatory = $true)]
    [string]$CsvFile,        # neue CSV-Liste (wie im Beispiel)

    [Parameter(Mandatory = $true)]
    [string]$ExistingFile,   # bestehende Datei im Zielformat

    [string]$OutputFile      # optional: Ziel-Datei (sonst Ausgabe in Konsole)
)

# Hashtable: Package -> [string[]] Versionen
$packages = @{}

function Add-Version {
    param(
        [hashtable]$Table,
        [string]$Name,
        [string]$Version
    )

    if (-not $Name -or -not $Version) { return }

    if (-not $Table.ContainsKey($Name)) {
        $Table[$Name] = @()
    }

    # nur hinzufügen, wenn noch nicht vorhanden
    if (-not ($Table[$Name] -contains $Version)) {
        $Table[$Name] += $Version
    }
}

# --- 1. Vorhandene Zielformat-Datei einlesen --------------------------------
# Format pro Zeile: <Package>: <version1> <version2> ...
# Beispiel: @art-ws/di: 2.0.28 2.0.32

Get-Content -Path $ExistingFile -ErrorAction Stop | ForEach-Object {
    $line = $_.Trim()
    if (-not $line) { return }
    if ($line.StartsWith('#')) { return }

    $parts = $line -split ':', 2
    if ($parts.Count -lt 2) { return }

    $name = $parts[0].Trim()
    $versionPart = $parts[1].Trim()
    if (-not $name) { return }

    # Versionen sind durch Spaces getrennt
    $versions = $versionPart -split '\s+'
    foreach ($v in $versions) {
        $vTrim = $v.Trim()
        if ($vTrim) {
            Add-Version -Table $packages -Name $name -Version $vTrim
        }
    }
}

# --- 2. Neue CSV-Datei einlesen und hinzufügen --------------------------------
# CSV-Format:
# Package,Version
# @alexcolls/nuxt-socket.io,= 0.0.7 || = 0.0.8

Get-Content -Path $CsvFile -ErrorAction Stop | Select-Object -Skip 1 | ForEach-Object {
    $line = $_.Trim()
    if (-not $line) { return }

    # In Package und Versionsteil splitten (nur am ersten Komma)
    $parts = $line -split ',', 2
    if ($parts.Count -lt 2) { return }

    $name = $parts[0].Trim()
    $versionRaw = $parts[1].Trim()
    if (-not $name) { return }

    # Versionen können "||" getrennt sein, z.B. "= 1.0.1 || = 1.0.2"
    $versionChunks = $versionRaw -split '\|\|'

    foreach ($chunk in $versionChunks) {
        # "= 0.0.7" -> "0.0.7"
        $v = ($chunk.Trim() -replace '^= *', '').Trim()
        if ($v) {
            Add-Version -Table $packages -Name $name -Version $v
        }
    }
}

# --- 3. Zusammengeführte Ausgabe erzeugen -------------------------------------

$outLines = foreach ($pkg in ($packages.Keys | Sort-Object)) {
    # Egal ob String oder Array – Sort-Object -Unique kümmert sich
    $vers = $packages[$pkg] | Sort-Object -Unique
    "${pkg}: " + ($vers -join ' ')
}

if ($OutputFile) {
    $outLines | Set-Content -Path $OutputFile -Encoding UTF8
    Write-Host "Zusammengeführte Liste wurde nach '$OutputFile' geschrieben."
} else {
    $outLines
}
