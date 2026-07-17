<#
.SYNOPSIS
  Aegis engine (Windows) — the "bolt-on Wazuh app".

  Reads THIS machine's Wazuh agent label `aegis.role` to self-identify, maps the
  role to a policy (roles.json), then runs patch-windows.ps1 with the right scope +
  reboot behavior. Client-agnostic: NO client data lives here — identity comes from
  Wazuh. Optional `aegis.pin` label adds per-machine line-of-business pins.

  DRY RUN by default. Pass -Apply to actually patch. Writes a JSON app-log line to
  C:\ProgramData\Aegis\aegis-app.log for Wazuh to ship + monitor.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File aegis.ps1                 # detect role, dry-run
  powershell -ExecutionPolicy Bypass -File aegis.ps1 -Apply          # patch per role policy
  powershell -ExecutionPolicy Bypass -File aegis.ps1 -Role personal  # test with an override role
#>
[CmdletBinding()]
param(
  [switch]$Apply,                                  # actually patch (default: dry run)
  [string]$Role,                                   # override the detected role (testing)
  [string]$AgentDir = "${env:ProgramFiles(x86)}\ossec-agent",
  [string]$RolesFile,
  [string]$LogDir = "$env:ProgramData\Aegis"
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $RolesFile) { $RolesFile = Join-Path $here "roles.json" }
$start = Get-Date

function Write-AppLog($obj) {
  # NOT Add-Content: once the Wazuh logcollector tails this file it holds a handle
  # that denies write sharing, so a plain append fails forever. Open with
  # FileShare ReadWrite|Delete (+ retry) so logger and collector coexist.
  try {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    $line = ($obj | ConvertTo-Json -Compress -Depth 6)
    $path = Join-Path $LogDir "aegis-app.log"
    for ($i = 0; $i -lt 5; $i++) {
      try {
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write,
              ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        try { $sw = New-Object System.IO.StreamWriter($fs); $sw.WriteLine($line); $sw.Flush(); $sw.Close() }
        finally { $fs.Dispose() }
        return
      } catch { Start-Sleep -Milliseconds 200 }
    }
    Write-Warning "Aegis: could not write app log after retries"
  } catch { }
}

# --- read a Wazuh agent label from local config (ossec.conf / shared merged config) ---
function Get-AgentLabel($key) {
  $paths = @((Join-Path $AgentDir "ossec.conf"),
             (Join-Path $AgentDir "shared\merged.mg"),
             (Join-Path $AgentDir "shared\agent.conf"))
  foreach ($p in $paths) {
    if (Test-Path $p) {
      $txt = Get-Content $p -Raw -ErrorAction SilentlyContinue
      if (-not $txt) { continue }
      $m = [regex]::Match($txt, "<label key=""$([regex]::Escape($key))""[^>]*>([^<]+)</label>")
      if ($m.Success) { return $m.Groups[1].Value.Trim() }
    }
  }
  return $null
}

$result = [ordered]@{
  timestamp = $start.ToUniversalTime().ToString("o"); tool = "aegis"; app = "engine"
  host = $env:COMPUTERNAME; os = "windows"; role = $null; source = $null
  dry_run = (-not $Apply); reboot = $null; pins = @(); status = "ok"; note = $null
}

try {
  # 1. role: explicit override > Wazuh label (authoritative) > local role file
  #    (written by bootstrap's install-time picker) > refuse to patch blind
  if ($Role) { $result.role = $Role; $result.source = "override" }
  else {
    $result.role = Get-AgentLabel "aegis.role"; $result.source = "wazuh-label"
    if (-not $result.role) {
      $roleFile = Join-Path $LogDir "role"
      if (Test-Path $roleFile) {
        $v = (Get-Content $roleFile -TotalCount 1 -ErrorAction SilentlyContinue)
        if ($v) { $result.role = $v.Trim(); $result.source = "local-file" }
      }
    }
  }
  if (-not $result.role) { throw "no role: no 'aegis.role' Wazuh label and no local role file - refusing to patch blind" }

  # 2. policy from roles.json
  $roles = Get-Content $RolesFile -Raw | ConvertFrom-Json
  $pol = $roles.$($result.role)
  if (-not $pol) { throw "role '$($result.role)' not defined in roles.json" }
  $result.reboot = $pol.reboot

  # 3. pins: role base + optional per-machine aegis.pin label
  $pins = @()
  if ($pol.pins) { $pins += $pol.pins }
  $pinLabel = Get-AgentLabel "aegis.pin"
  if ($pinLabel) { $pins += ($pinLabel -split "[,;]" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
  $result.pins = $pins

  # 4. temp exclusion file for patch-windows.ps1 (keyed by role)
  $exFile = Join-Path $env:TEMP "aegis-exclusions-$($result.role).json"
  @{ $($result.role) = @{ winget = $pins } } | ConvertTo-Json -Depth 5 | Set-Content -Path $exFile

  # 5. build patch-windows.ps1 args from the policy
  $patch = Join-Path $here "patch-windows.ps1"
  if (-not (Test-Path $patch)) { throw "patch-windows.ps1 not found next to the engine" }
  $pargs = @("-Group", $result.role, "-ExclusionFile", $exFile)
  if (-not $Apply) { $pargs += "-DryRun" }
  if ($pol.reboot -eq "auto" -and $Apply) { $pargs += "-AllowReboot" }
  if ($pol.os -eq "none") { $pargs += "-SkipOS" }

  Write-Output ("Aegis: role={0} (via {1}) | reboot={2} | os={3} | pins={4} | dry_run={5}" -f `
    $result.role, $result.source, $pol.reboot, $pol.os, ($pins -join ","), (-not $Apply))
  & powershell -NoProfile -ExecutionPolicy Bypass -File $patch @pargs
}
catch {
  $result.status = "error"; $result.note = "$($_.Exception.Message)"
  Write-Warning "Aegis: $($_.Exception.Message)"
}
finally {
  $result.duration_sec = [int]((Get-Date) - $start).TotalSeconds
  Write-AppLog $result
  Write-Output ($result | ConvertTo-Json -Depth 6)
}
