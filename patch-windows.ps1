<#
.SYNOPSIS
  Aegis — Windows patch runner. Apps via winget, OS via PSWindowsUpdate.
  SYSTEM-context safe. Pins protect line-of-business apps. Writes a JSON audit
  line the Wazuh agent ships. Never reboots unless -AllowReboot.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File patch-windows.ps1 -DryRun
  powershell -ExecutionPolicy Bypass -File patch-windows.ps1 -ExclusionFile exclusions.json -Group clinical
#>
[CmdletBinding()]
param(
  [switch]$DryRun,                              # list only, change nothing
  [switch]$AllowReboot,                         # permit reboot if updates require it
  [switch]$SkipOS,                              # apps only, skip Windows Update
  [string]$ExclusionFile,                       # JSON: { "<group>": { "winget": ["Id",...] } }
  [string]$Group = "personal",
  [string]$LogDir = "$env:ProgramData\Aegis"
)

$ErrorActionPreference = "Stop"
$start = Get-Date
$result = [ordered]@{
  timestamp = $start.ToUniversalTime().ToString("o"); tool = "aegis"
  host = $env:COMPUTERNAME; os = "windows"; group = $Group; dry_run = [bool]$DryRun
  apps_updated = @(); apps_excluded = @(); os_updates = 0
  reboot_required = $false; reboot_performed = $false; errors = @(); status = "success"
}

function Write-AegisLog {
  param($obj)
  try {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    ($obj | ConvertTo-Json -Compress -Depth 6) | Add-Content -Path (Join-Path $LogDir "aegis-patch.log")
  } catch { Write-Warning "Aegis: could not write log: $_" }
}

# --- resolve winget under SYSTEM (per-user shim is invisible to LocalSystem) ---
function Resolve-Winget {
  $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $p = Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" `
        -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
  if ($p) { return $p.FullName }
  return $null
}

try {
  # --- load exclusions for this group ---
  $excluded = @()
  if ($ExclusionFile -and (Test-Path $ExclusionFile)) {
    $cfg = Get-Content $ExclusionFile -Raw | ConvertFrom-Json
    if ($cfg.$Group -and $cfg.$Group.winget) { $excluded = @($cfg.$Group.winget) }
  }
  $result.apps_excluded = $excluded

  # --- apps: winget ---
  $winget = Resolve-Winget
  if (-not $winget) { throw "winget.exe not found (App Installer missing?)" }

  # pin exclusions so --all can never touch LOB apps (idempotent, persistent)
  foreach ($id in $excluded) {
    if (-not $DryRun) {
      & $winget pin add --id $id --exact --accept-source-agreements 2>$null | Out-Null
    }
  }

  if ($DryRun) {
    $list = & $winget upgrade --include-unknown --accept-source-agreements 2>$null
    $joined = ($list | Out-String)
    Write-Output "DRY RUN - winget would upgrade:`n$joined"
  } else {
    & $winget upgrade --all --silent --include-unknown `
        --accept-source-agreements --accept-package-agreements `
        --disable-interactivity 2>&1 | Tee-Object -Variable wgOut | Out-Null
    # best-effort capture of what moved (winget lacks clean machine output)
    $result.apps_updated = @($wgOut | Select-String -Pattern 'Successfully installed' | ForEach-Object { "$_" })
  }

  # --- OS: PSWindowsUpdate ---
  if (-not $SkipOS) {
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
      if (-not $DryRun) {
        Set-PSRepository PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        Install-Module PSWindowsUpdate -Force -Scope AllUsers -ErrorAction Stop
      }
    }
    Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
    if ($DryRun) {
      $pending = Get-WindowsUpdate -ErrorAction SilentlyContinue
      Write-Output "DRY RUN - pending OS updates: $($pending.Count)"
      $result.os_updates = @($pending).Count
    } else {
      $applied = Install-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction SilentlyContinue
      $result.os_updates = @($applied).Count
      $result.reboot_required = [bool](Get-WURebootStatus -Silent -ErrorAction SilentlyContinue)
    }
  }

  # --- reboot policy ---
  if ($result.reboot_required -and $AllowReboot -and -not $DryRun) {
    Write-AegisLog $result   # log BEFORE we go down
    $result.reboot_performed = $true
    Restart-Computer -Force
    return
  }
}
catch {
  $result.status = "error"
  $result.errors += "$($_.Exception.Message)"
  Write-Warning "Aegis: $_"
}
finally {
  $result.duration_sec = [int]((Get-Date) - $start).TotalSeconds
  if (-not $result.reboot_performed) { Write-AegisLog $result }
  Write-Output ($result | ConvertTo-Json -Depth 6)
}
