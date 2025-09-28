#Requires -Version 5.1
<#
  compromised.ps1
  Scans ONLY the current directory for lockfiles and reports compromised packages.

  Behaviour change: the script will *pause before exit* by default (so you keep the
  output visible and can press ENTER to return to the calling shell). If you want
  the script to automatically exit (e.g. in CI / GitHub Actions), pass the
  -AutoExit switch.

  Parameters:
    -ListUrl     : URL of the compromised package list
    -Cache       : optional cache file path for the list
    -ShowContent : switch to print first lines of the list
    -ShowLines   : number of lines to print with -ShowContent (default 200)
    -AutoExit    : switch; if present the script will not pause and exits immediately
#>

[CmdletBinding()]
param(
  [string]$ListUrl = 'https://raw.githubusercontent.com/oweitman/compromisedPackages/main/compromised-packages.txt',
  [string]$Cache,
  [switch]$ShowContent,
  [int]$ShowLines = 200,
  [switch]$AutoExit
)

$ErrorActionPreference = 'Stop'

# ---------------- Helpers ----------------

function Write-ProgressPercent {
  param([int]$Percent)
  if ($Percent -lt 0) { $Percent = 0 }
  if ($Percent -gt 100) { $Percent = 100 }
  Write-Progress -Activity "[Progress]" -Status ("{0}% complete" -f $Percent) -PercentComplete $Percent
}

function Test-IsHtmlPreview {
  param([string[]]$HeadLines)
  $joined = ($HeadLines -join "`n")
  return ($joined -match '<!doctype|<html|<head')
}

# normalize a file:// URL to a local path
function Convert-FileUrlToLocalPath {
  param([string]$Url)
  # strip scheme
  $local = $Url -replace '^[Ff][Ii][Ll][Ee]:\\/\\/\\/?', ''
  # decode %-escapes
  try {
    $local = [System.Uri]::UnescapeDataString($local)
  } catch {
    # ignore decode errors
  }
  # On Windows, convert forward slashes to backslashes for Test-Path friendly path
  if ($IsWindows) { $local = $local -replace '/', '\\' }
  return $local
}

function Get-ListLines {
  param(
    [string]$Url,
    [string]$CacheFile
  )

  Write-Host ("Downloading compromised package list from: {0}" -f $Url)

  # If the URL is a local file URL (file://), treat it specially
  if ($Url -match '^[Ff][Ii][Ll][Ee]:\\/\\/\\/?') {
    $localPath = Convert-FileUrlToLocalPath -Url $Url
    if (-not (Test-Path -LiteralPath $localPath)) {
      throw "Local list file not found: $localPath"
    }

    # If a cache path is requested, copy into the cache (keeps behavior consistent)
    if ($CacheFile) {
      try {
        Copy-Item -LiteralPath $localPath -Destination $CacheFile -Force
        Write-Host ("List copied from local file to cache at: {0}" -f $CacheFile)
        $lines = Get-Content -LiteralPath $CacheFile -ErrorAction Stop
      } catch {
        throw "Failed to copy local list to cache: $_"
      }
    } else {
      # read directly
      try {
        $lines = Get-Content -LiteralPath $localPath -ErrorAction Stop
      } catch {
        throw "Failed to read local list file: $_"
      }
    }

    if ($ShowContent) {
      Write-Host ""
      Write-Host ("--- First {0} lines of the list ---" -f $ShowLines)
      ($lines | Select-Object -First $ShowLines) | ForEach-Object { Write-Host $_ }
      Write-Host "--- End ---`n"
    }

    return $lines
  }

  # Non-file URL: use HTTP(S) download and optionally cache
  $lines = $null
  if ($CacheFile) {
    $tmp = "$CacheFile.tmp"
    try {
      # Use Invoke-WebRequest for HTTP/HTTPS
      Invoke-WebRequest -Uri $Url -OutFile $tmp -ErrorAction Stop
      $head = Get-Content -LiteralPath $tmp -TotalCount 6 -ErrorAction Stop
      if (Test-IsHtmlPreview $head) {
        Write-Warning "Download looks like HTML/Preview."
        Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
        if (Test-Path $CacheFile) {
          try {
            $lines = Get-Content -LiteralPath $CacheFile -ErrorAction Stop
            Write-Warning ("Using existing cache file: {0}" -f $CacheFile)
          } catch {
            throw "Failed to load list from URL and cache."
          }
        } else {
          throw "No valid content and no cache available."
        }
      } else {
        Move-Item -Force -LiteralPath $tmp -Destination $CacheFile
        $lines = Get-Content -LiteralPath $CacheFile -ErrorAction Stop
        Write-Host ("List successfully downloaded and cached at: {0}" -f $CacheFile)
      }
    } catch {
      if (Test-Path $tmp) { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
      if (-not $lines) {
        if (Test-Path $CacheFile) {
          try {
            $lines = Get-Content -LiteralPath $CacheFile -ErrorAction Stop
            Write-Warning ("Using existing cache file: {0}" -f $CacheFile)
          } catch {
            throw "Failed to load list from URL and cache."
          }
        } else {
          throw ("Failed to load list: {0}" -f $Url)
        }
      }
    }
  } else {
    # no cache specified: download to tmp and return
    $tmp = New-TemporaryFile
    try {
      Invoke-WebRequest -Uri $Url -OutFile $tmp -ErrorAction Stop
      $head = Get-Content -LiteralPath $tmp -TotalCount 6 -ErrorAction Stop
      if (Test-IsHtmlPreview $head) {
        Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
        throw "Download looks like HTML/Preview. Aborting."
      }
      $lines = Get-Content -LiteralPath $tmp -ErrorAction Stop
      Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    } catch {
      if (Test-Path $tmp) { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
      throw
    }
  }

  if ($ShowContent) {
    Write-Host ""
    Write-Host ("--- First {0} lines of the list ---" -f $ShowLines)
    ($lines | Select-Object -First $ShowLines) | ForEach-Object { Write-Host $_ }
    Write-Host "--- End ---`n"
  }

  return $lines
}

function Parse-CompromisedList {
  param([string[]]$Lines)
  $dict = @{}
  $nonComment = 0
  foreach ($raw in $Lines) {
    $line = $raw.Trim()
    if (-not $line) { continue }
    if ($line.StartsWith('#')) { continue }
    $nonComment++

    $idx = $line.IndexOf(':')
    if ($idx -lt 0) { continue }
    $pkg = $line.Substring(0, $idx).Trim()
    $versPart = $line.Substring($idx + 1).Trim()
    if (-not $pkg -or -not $versPart) { continue }

    $versions = $versPart -split '\\s+' | Where-Object { $_ -ne '' }
    if ($versions.Count -gt 0) {
      $dict[$pkg] = $versions
    }
  }
  Write-Host ("Info: {0} non-comment lines; {1} package(s) parsed." -f $nonComment, $dict.Keys.Count)
  return $dict
}

function Get-LockfilesCurrentDir {
  $files = @()
  foreach ($name in @('package-lock.json','yarn.lock','pnpm-lock.yaml')) {
    $p = Join-Path (Get-Location) $name
    if (Test-Path $p) { $files += $p }
  }
  return $files
}

# Escape for regex literal
function Escape-Regex([string]$s) {
  return [regex]::Escape($s)
}

# (A) Flat key:   "pkg" : "ver"   (line-based)
function Test-FlatJsonMatch {
  param([string]$Text, [string]$Pkg, [string]$Ver)
  $pkgRe = Escape-Regex $Pkg
  $verRe = Escape-Regex $Ver
  # allow optional trailing comma or whitespace (tolerant)
  $pattern = ('"{0}"\s*:\s*"{1}"(?:\s*,|\s*)\r?$' -f $pkgRe, $verRe)
  return [regex]::IsMatch($Text, $pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
}

# (B) dependencies block: "pkg": { ... "version": "ver" ... }  (multi-line)
function Test-DependenciesBlock {
  param([string]$Text, [string]$Pkg, [string]$Ver)
  $pkgRe = Escape-Regex $Pkg
  $verRe = Escape-Regex $Ver
  # Use Singleline to span across newlines
  $pattern = ('"{0}"\s*:\s*{{[^}}]*"version"\s*:\s*"{1}"' -f $pkgRe, $verRe)
  return [regex]::IsMatch($Text, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
}

# (C) packages block: "node_modules/pkg": { ... "version": "ver" ... }  (multi-line)
function Test-PackagesBlock {
  param([string]$Text, [string]$Pkg, [string]$Ver)
  $pkgRe = Escape-Regex $Pkg
  $verRe = Escape-Regex $Ver
  $pattern = ('"node_modules/{0}"\s*:\s*{{[^}}]*"version"\s*:\s*"{1}"' -f $pkgRe, $verRe)
  return [regex]::IsMatch($Text, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
}

# (D) yarn header:  ^pkg@(^|~)?ver(:|\b)
function Test-YarnHeader {
  param([string]$Text, [string]$Pkg, [string]$Ver)
  $pkgRe = Escape-Regex $Pkg
  $verRe = Escape-Regex $Ver
  $pattern = ('^{0}@(\^|~)?{1}(:|\b)' -f $pkgRe, $verRe)
  return [regex]::IsMatch($Text, $pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
}

# ---------------- Main flow ----------------

# 1) Load list
$listLines = Get-ListLines -Url $ListUrl -CacheFile $Cache

# 2) Parse list
$compromised = Parse-CompromisedList -Lines $listLines
if ($compromised.Keys.Count -eq 0) {
  Write-Host "Nothing to check (empty list)."
  exit 0
}

# 3) Lockfiles in current dir
Write-Host ("Scanning lockfiles in: {0} (current directory only)..." -f (Get-Location).Path)
$lockfiles = Get-LockfilesCurrentDir
Write-Host ("Info: {0} lockfile(s) found." -f $lockfiles.Count)
foreach ($f in $lockfiles) {
  try { $len = (Get-Item $f).Length } catch { $len = 0 }
  Write-Host (" - {0} ({1} bytes)" -f $f, $len)
}
if ($lockfiles.Count -eq 0) { Write-Host "No lockfiles found."; exit 0 }

# 4) Workload
$totalVersions = 0
foreach ($pkg in $compromised.Keys) { $totalVersions += ($compromised[$pkg]).Count }
$totalChecks = $totalVersions * $lockfiles.Count
if ($totalChecks -le 0) {
  Write-Host ("Nothing to check. (total_versions={0}, lockfiles={1})" -f $totalVersions, $lockfiles.Count)
  exit 0
}

# 5) Scan (dedup + aggregation)
$hitMap = New-Object 'System.Collections.Generic.HashSet[string]'
$perFileCounts = @{}
$done = 0
$lastShown = -1

# Cache file contents for faster matching
$fileTexts = @{}
foreach ($file in $lockfiles) {
  $fileTexts[$file] = Get-Content -LiteralPath $file -Raw
}

Write-ProgressPercent 0

foreach ($file in $lockfiles) {
  $text = $fileTexts[$file]

  foreach ($pkg in $compromised.Keys) {
    $versions = $compromised[$pkg]
    foreach ($ver in $versions) {
      $done++
      $percent = [int][Math]::Floor(($done / $totalChecks) * 100)
      if ($percent -gt $lastShown) { Write-ProgressPercent $percent; $lastShown = $percent }

      $key = ("{0}|{1}@{2}" -f $file, $pkg, $ver)
      if ($hitMap.Contains($key)) { continue }

      $hit = $false
      if (-not $hit) { $hit = Test-FlatJsonMatch     -Text $text -Pkg $pkg -Ver $ver }
      if (-not $hit) { $hit = Test-DependenciesBlock -Text $text -Pkg $pkg -Ver $ver }
      if (-not $hit) { $hit = Test-PackagesBlock     -Text $text -Pkg $pkg -Ver $ver }
      if (-not $hit) { $hit = Test-YarnHeader        -Text $text -Pkg $pkg -Ver $ver }

      if ($hit) {
        $null = $hitMap.Add($key)
        if (-not $perFileCounts.ContainsKey($file)) { $perFileCounts[$file] = 0 }
        $perFileCounts[$file]++
      }
    }
  }
}

Write-ProgressPercent 100

# 6) Aggregated output
if ($hitMap.Count -eq 0) {
  Write-Host "OK: No compromised packages found in lockfiles."
} else {
  Write-Host ""
  Write-Host "Results (aggregated):"
  $totalHits = 0
  foreach ($f in $lockfiles) {
    $count = 0
    if ($perFileCounts.ContainsKey($f)) { $count = $perFileCounts[$f] }
    if ($count -le 0) { continue }
    Write-Host ("- {0}  --  {1} match(es)" -f $f, $count)

    $hitsForFile =
      $hitMap |
      Where-Object { $_.StartsWith("$f|") } |
      Sort-Object

    foreach ($kv in $hitsForFile) {
      $pkgver = $kv.Substring($f.Length + 1)
      Write-Host ("   * {0}" -f $pkgver)
      $totalHits++
    }
  }

  Write-Host ""
  Write-Host ("Total: {0} match(es) in {1} file(s)." -f $totalHits, $lockfiles.Count)
  Write-Host "Action: Please update/remove the affected packages and regenerate your lockfiles."
}

# ---------------- Final behaviour: pause unless AutoExit or non-interactive ----------------
# Determine whether we have a console available (try/catch because [Console] may throw when no host)
$hasConsole = $false
try {
  # Accessing KeyAvailable throws if no console
  $null = [System.Console]::KeyAvailable
  $hasConsole = $true
} catch {
  $hasConsole = $false
}

# Decide: auto-exit if -AutoExit passed OR running in CI OR no console detected
$shouldAutoExit = $AutoExit.IsPresent -or [bool]$env:CI -or (-not $hasConsole)

if ($shouldAutoExit) {
  # Explicitly return to caller (script ends)
  return
} else {
  # Interactive: wait for user to press ENTER so output remains visible
  try {
    Write-Host ""
    Write-Host "Press ENTER to return to shell..."
    [void][System.Console]::ReadLine()
  } catch {
    # Fallback if Console.ReadLine not available
    try { Read-Host -Prompt 'Press ENTER to return to shell...' } catch { }
  }
  return
}
