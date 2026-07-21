<#
.SYNOPSIS
  Aegis bootstrap (Windows) — one-time installer. Run as Administrator.

  Bolts Aegis onto an existing Wazuh agent: downloads the pinned engine, places it
  in the agent's active-response/bin, enables remote_commands, and makes the box
  AR-ready. Reads NO client data — role/policy come from the agent's Wazuh label at
  run time. Generic + safe to publish.

  One-liner (private repo -> set a token first):
    $env:AEGIS_TOKEN='ghp_...'; $env:AEGIS_REF='v0.1'
    irm "https://raw.githubusercontent.com/veteranop/Aegis/$($env:AEGIS_REF)/bootstrap.ps1" -Headers @{Authorization="token $($env:AEGIS_TOKEN)"} | iex
#>
[CmdletBinding()]
param(
  [string]$Repo  = "veteranop/Aegis",
  [string]$Ref   = $(if ($env:AEGIS_REF) { $env:AEGIS_REF } else { "main" }),   # PIN a tag/commit in prod
  [string]$Token = $env:AEGIS_TOKEN,        # required for a private repo
  [string]$Role  = $env:AEGIS_ROLE,         # pre-select the role (skips the interactive picker)
  [switch]$NoRemoteCommands                 # install engine but skip the remote_commands flip
)
$ErrorActionPreference = "Stop"

# 1. must be admin
$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as Administrator." }

# 2. Aegis bolts onto Wazuh — the agent must already be installed
$agent = "${env:ProgramFiles(x86)}\ossec-agent"
if (-not (Test-Path $agent)) {
    throw "Wazuh agent not found at $agent. Install + enroll the agent first; Aegis rides on it." }

# 3. download the pinned engine (checksum-verified) into active-response\bin\aegis
$dest = Join-Path $agent "active-response\bin\aegis"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$hdr = @{}; if ($Token) { $hdr["Authorization"] = "token $Token" }
$files = @("aegis.ps1", "roles.json", "patch-windows.ps1", "SHA256SUMS")
foreach ($f in $files) {
    $url = "https://raw.githubusercontent.com/$Repo/$Ref/$f"
    Invoke-WebRequest -Uri $url -Headers $hdr -OutFile (Join-Path $dest $f) -UseBasicParsing
}
# verify checksums (SHA256SUMS: "<sha256>  <filename>")
$sums = Get-Content (Join-Path $dest "SHA256SUMS") -ErrorAction SilentlyContinue
foreach ($line in $sums) {
    if ($line -match '^\s*([0-9a-fA-F]{64})\s+(.+?)\s*$') {
        $want = $Matches[1].ToLower(); $name = $Matches[2]
        $fp = Join-Path $dest $name
        if (Test-Path $fp) {
            $have = (Get-FileHash $fp -Algorithm SHA256).Hash.ToLower()
            if ($have -ne $want) { throw "checksum mismatch on $name (expected $want, got $have) - refusing to install" }
        }
    }
}

# 4. AR wrapper so the Wazuh manager can invoke the engine (AR runs .cmd/.exe)
$cmd = Join-Path $agent "active-response\bin\aegis.cmd"
Set-Content -Path $cmd -Encoding ASCII -Value @'
@echo off
rem execd is a 32-bit process: plain "powershell" resolves to SysWOW64 (wrong
rem ProgramFiles, wrong PSModulePath -> no winget, no PSWindowsUpdate).
rem Force 64-bit PowerShell via the sysnative alias when it exists.
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0aegis\aegis.ps1" %*
'@

# 4b. LIVE apply wrapper — separate AR command so dry-run stays the default trigger
$cmdApply = Join-Path $agent "active-response\bin\aegis-apply.cmd"
Set-Content -Path $cmdApply -Encoding ASCII -Value @'
@echo off
rem LIVE Aegis run: actually patches, may reboot per role policy. See aegis.cmd
rem for why 64-bit PowerShell must be forced via sysnative.
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0aegis\aegis.ps1" -Apply %*
'@

# 4c. self-update wrapper — lets the manager push engine updates fleet-wide via the
# `aegis-win-update` AR command. It re-pulls the pinned engine and re-runs bootstrap
# with AEGIS_NO_RESTART so it never bounces the agent that's running it.
$cmdUpdate = Join-Path $agent "active-response\bin\aegis-update.cmd"
Set-Content -Path $cmdUpdate -Encoding ASCII -Value @'
@echo off
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0aegis\aegis-update.ps1" %*
'@
Set-Content -Path (Join-Path $dest "aegis-update.ps1") -Encoding ASCII -Value @'
# Aegis self-update: re-pull the pinned engine from GitHub and re-run bootstrap,
# tracking the repo/ref recorded at install (%ProgramData%\Aegis\ref). No agent restart.
$ErrorActionPreference = "Stop"
$cfg = @{}
Get-Content "$env:ProgramData\Aegis\ref" -ErrorAction SilentlyContinue | ForEach-Object {
  if ($_ -match "^\s*(\w+)\s*=\s*(.+?)\s*$") { $cfg[$Matches[1]] = $Matches[2] }
}
$repo = if ($cfg.repo) { $cfg.repo } else { "veteranop/Aegis" }
$ref  = if ($cfg.ref)  { $cfg.ref }  else { "main" }
$hdr = @{}; if ($cfg.token) { $hdr["Authorization"] = "token $($cfg.token)" }
$env:AEGIS_REF = $ref; $env:AEGIS_NO_RESTART = "1"
Invoke-RestMethod "https://raw.githubusercontent.com/$repo/$ref/bootstrap.ps1" -Headers $hdr | Invoke-Expression
'@

# 5. enable remote_commands (the accepted-risk gate) unless told not to
if (-not $NoRemoteCommands) {
    $lio = Join-Path $agent "local_internal_options.conf"
    if (-not (Test-Path $lio)) { New-Item -ItemType File -Force -Path $lio | Out-Null }
    foreach ($opt in @("wazuh_command.remote_commands=1", "logcollector.remote_commands=1")) {
        $key = $opt.Split("=")[0]
        if (-not (Select-String -Path $lio -SimpleMatch $key -Quiet)) { Add-Content -Path $lio -Value $opt }
    }
}

# 6. app-log dir (manager's shared config adds the <localfile> to ship it to Wazuh)
New-Item -ItemType Directory -Force -Path "$env:ProgramData\Aegis" | Out-Null

# 6a. record the repo/ref this box tracks, so aegis-update re-pulls the same channel.
# Track a BRANCH (e.g. main) for push-button fleet updates; pin a tag/SHA to freeze.
$refLines = @("repo=$Repo", "ref=$Ref"); if ($Token) { $refLines += "token=$Token" }
Set-Content -Path "$env:ProgramData\Aegis\ref" -Encoding ASCII -Value $refLines

# 6b. role picker -> live from the start. The engine resolves: Wazuh label
# (authoritative, set per group on the manager) > this local file > refuse.
$roleNames = @((Get-Content (Join-Path $dest "roles.json") -Raw | ConvertFrom-Json).PSObject.Properties.Name)
if (-not $Role -and [Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
  Write-Host "`nSelect this machine's Aegis role (the manager's aegis.role label always overrides):"
  for ($i = 0; $i -lt $roleNames.Count; $i++) { Write-Host ("  {0}) {1}" -f ($i + 1), $roleNames[$i]) }
  Write-Host "  0) skip - identify via Wazuh label only"
  $sel = Read-Host "Role [0-$($roleNames.Count)]"
  if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $roleNames.Count) {
    $Role = $roleNames[[int]$sel - 1]
  }
}
if ($Role) {
  if ($roleNames -notcontains $Role) { throw "role '$Role' not in roles.json (valid: $($roleNames -join ', '))" }
  Set-Content -Path "$env:ProgramData\Aegis\role" -Encoding ASCII -Value $Role
  Write-Host "Aegis role -> '$Role' (local file; manager label overrides)"
}

# 7. restart the agent to pick up config — skipped on self-update (AEGIS_NO_RESTART=1)
# so an AR-triggered update doesn't bounce the agent that's running it.
if ($env:AEGIS_NO_RESTART -ne "1") {
    foreach ($svc in @("WazuhSvc", "Wazuh", "OssecSvc")) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) { Restart-Service -Name $svc -Force; break }
    }
}

Write-Host "Aegis installed -> $dest (ref: $Ref). remote_commands: $([bool](-not $NoRemoteCommands)). "
Write-Host "Next (manager side): set the group's aegis.role label + add the aegis-app.log <localfile>."
