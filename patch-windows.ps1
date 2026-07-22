<#
.SYNOPSIS
  Aegis — Windows patch runner. Apps via winget, OS via the Windows Update Agent API.
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
  [switch]$SkipUserApps,                        # skip the per-user winget pass (SYSTEM-only)
  [string]$ExclusionFile,                       # JSON: { "<group>": { "winget": ["Id",...] } }
  [string]$Group = "personal",
  [string]$LogDir = "$env:ProgramData\Aegis"
)

$ErrorActionPreference = "Stop"
$ConfirmPreference = "None"   # non-interactive SYSTEM/AR context: never ShouldContinue-prompt
$start = Get-Date
$result = [ordered]@{
  timestamp = $start.ToUniversalTime().ToString("o"); tool = "aegis"
  host = $env:COMPUTERNAME; os_family = "windows"; group = $Group; dry_run = [bool]$DryRun
  engine = "2026.07.21"   # engine build (bump on release; visible per-machine in the outcome)
  apps_updated = @(); user_apps_updated = @(); apps_excluded = @(); os_updates = 0
  reboot_required = $false; reboot_performed = $false; errors = @(); notes = @(); status = "success"
}

function Write-AegisLog {
  param($obj)
  # shared-mode append (see aegis.ps1 Write-AppLog): the Wazuh logcollector's
  # tail handle denies write sharing to a plain Add-Content
  try {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    $line = ($obj | ConvertTo-Json -Compress -Depth 6)
    $path = Join-Path $LogDir "aegis-patch.log"
    for ($i = 0; $i -lt 5; $i++) {
      try {
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write,
              ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        try { $sw = New-Object System.IO.StreamWriter($fs); $sw.WriteLine($line); $sw.Flush(); $sw.Close() }
        finally { $fs.Dispose() }
        return
      } catch { Start-Sleep -Milliseconds 200 }
    }
    Write-Warning "Aegis: could not write log after retries"
  } catch { Write-Warning "Aegis: could not write log: $_" }
}

# --- resolve winget under SYSTEM (per-user shim is invisible to LocalSystem) ---
# Candidates are TESTED with --version: under LocalSystem, Get-Command can resolve to
# the systemprofile's WindowsApps reparse-point alias, which exists but is NOT
# executable by SYSTEM ("The file cannot be accessed by the system"). Only the real
# packaged exe under Program Files\WindowsApps runs reliably in SYSTEM context.
function Resolve-Winget {
  # Find a winget.exe SYSTEM can actually run. WindowsApps is ACL-locked (Get-ChildItem is
  # access-denied under SYSTEM), so resolve via the Appx InstallLocation, then CONFIRM it
  # runs via --version — on some images the packaged exe can't run standalone under SYSTEM
  # (0xC0000135, MSIX package-graph); those return $null and machine-scope is skipped.
  $candidates = @()
  try {
    Get-AppxPackage -AllUsers Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue |
      Sort-Object { try { [version]$_.Version } catch { [version]'0.0' } } -Descending |
      ForEach-Object { if ($_.InstallLocation) { $candidates += (Join-Path $_.InstallLocation 'winget.exe') } }
  } catch { }
  $pf = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
  $candidates += @(Get-ChildItem "$pf\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
  $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
  if ($cmd) { $candidates += $cmd.Source }
  foreach ($c in ($candidates | Select-Object -Unique)) {
    try { $null = & $c --version 2>$null; if ($LASTEXITCODE -eq 0) { return $c } } catch { }
  }
  return $null
}

# --- user-context winget pass -------------------------------------------------
# SYSTEM's winget only sees MACHINE-scope packages; per-user installs (proven with
# ripgrep) are invisible and never patched. Run winget as the logged-on interactive
# user by impersonating their token: WTSQueryUserToken (needs SYSTEM/SeTcbPrivilege,
# which is exactly the Wazuh execd/AR context) -> CreateProcessAsUser into their
# session. No scheduled task, no password. Returns the winget output text, or $null.
$AegisNativeSrc = @'
using System;
using System.Runtime.InteropServices;
public static class AegisNative {
  [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
  [DllImport("wtsapi32.dll", SetLastError=true)] public static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool DuplicateTokenEx(IntPtr h, uint access, IntPtr attr, int imp, int type, out IntPtr phNew);
  [DllImport("userenv.dll", SetLastError=true)] public static extern bool CreateEnvironmentBlock(out IntPtr env, IntPtr token, bool inherit);
  [DllImport("userenv.dll", SetLastError=true)] public static extern bool DestroyEnvironmentBlock(IntPtr env);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr h, uint ms);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int len, out int retLen);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CreateProcessAsUser(IntPtr token, string app, string cmd, IntPtr pa, IntPtr ta,
    bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
  [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint pid, tid; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct STARTUPINFO {
    public int cb; public string reserved, desktop, title;
    public int x, y, xsize, ysize, xchars, ychars, fill, flags; public short show, cbr2;
    public IntPtr reserved2, stdin, stdout, stderr; }
  // Launch `cmdline` in the active console user's session. Returns true if the process
  // started and exited within timeoutMs. Throws nothing the caller can't catch.
  public static bool RunAsActiveUser(string cmdline, string cwd, uint timeoutMs) {
    IntPtr tok, dup = IntPtr.Zero, env = IntPtr.Zero;
    uint sid = WTSGetActiveConsoleSessionId();
    if (sid == 0xFFFFFFFF || !WTSQueryUserToken(sid, out tok)) return false;
    try {
      if (!DuplicateTokenEx(tok, 0x10000000u, IntPtr.Zero, 2, 1, out dup)) return false; // MAXIMUM_ALLOWED, SecurityImpersonation, TokenPrimary
      CreateEnvironmentBlock(out env, dup, false);
      var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(typeof(STARTUPINFO)); si.desktop = "winsta0\\default";
      PROCESS_INFORMATION pi;
      uint flags = 0x00000400u | 0x08000000u; // CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW
      if (!CreateProcessAsUser(dup, null, cmdline, IntPtr.Zero, IntPtr.Zero, false, flags, env, cwd, ref si, out pi)) return false;
      WaitForSingleObject(pi.hProcess, timeoutMs);
      CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
      return true;
    } finally {
      if (env != IntPtr.Zero) DestroyEnvironmentBlock(env);
      if (dup != IntPtr.Zero) CloseHandle(dup);
      CloseHandle(tok);
    }
  }
}
'@

function Invoke-WingetAsUser {
  # BEST-EFFORT: a failure here must NEVER fail the whole patch run.
  try {
    $work = Join-Path $env:ProgramData "Aegis"             # readable/writable by the user process
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $script = Join-Path $work "AegisUserWinget.cmd"
    $out    = Join-Path $work "AegisUserWinget.out"
    Remove-Item $out -ErrorAction SilentlyContinue
    # --scope user: only USER-scope installs. Machine-scope apps are the (elevated)
    # SYSTEM pass's job; touching them from the un-elevated user session triggers a
    # UAC prompt that would stall an unattended client run. Scoping avoids that.
    @"
@echo off
winget upgrade --all --scope user --silent --include-unknown --accept-source-agreements --accept-package-agreements --disable-interactivity > "$out" 2>&1
"@ | Set-Content -Path $script -Encoding ASCII
    if (-not ('AegisNative' -as [type])) { Add-Type -TypeDefinition $AegisNativeSrc -Language CSharp }
    # 10-min cap; runs cmd.exe /c the .cmd in the console user's session
    [void][AegisNative]::RunAsActiveUser("cmd.exe /c `"$script`"", $work, 600000)
    if (Test-Path $out) { return (Get-Content $out -Raw -ErrorAction SilentlyContinue) }
    return $null
  } catch {
    return $null   # best-effort: never let the user-pass fail the core patch run
  }
}

try {
  # --- load exclusions for this group ---
  $excluded = @()
  if ($ExclusionFile -and (Test-Path $ExclusionFile)) {
    $cfg = Get-Content $ExclusionFile -Raw | ConvertFrom-Json
    if ($cfg.$Group -and $cfg.$Group.winget) { $excluded = @($cfg.$Group.winget) }
  }
  $result.apps_excluded = $excluded

  # --- machine-scope apps: SYSTEM winget (NON-FATAL if it can't resolve/run) ---
  $winget = Resolve-Winget
  if (-not $winget) {
    $result.notes += "SYSTEM winget unavailable - machine-scope apps skipped (user-scope + OS still run)"
  }
  else {
    # pin exclusions so --all can never touch LOB apps (idempotent, persistent)
    foreach ($id in $excluded) {
      if (-not $DryRun) {
        & $winget pin add --id $id --exact --accept-source-agreements 2>$null | Out-Null
      }
    }
    if ($DryRun) {
      $list = & $winget upgrade --include-unknown --accept-source-agreements 2>$null
      Write-Output "DRY RUN - winget would upgrade:`n$($list | Out-String)"
    } else {
      & $winget upgrade --all --silent --include-unknown `
          --accept-source-agreements --accept-package-agreements `
          --disable-interactivity 2>&1 | Tee-Object -Variable wgOut | Out-Null
      $result.apps_updated = @($wgOut | Select-String -Pattern 'Successfully installed' | ForEach-Object { "$_" })
    }
  }

  # --- per-user apps: runs INDEPENDENTLY of the SYSTEM pass (winget works in the user's
  # session even when SYSTEM can't resolve/run it), so this must not be gated on $winget. ---
  if (-not $DryRun -and -not $SkipUserApps) {
    $userOut = Invoke-WingetAsUser
    if ($userOut) {
      $result.user_apps_updated = @($userOut -split "`r?`n" |
        Select-String -Pattern 'Successfully installed' | ForEach-Object { "$_".Trim() })
    }
  }

  # --- OS: native Windows Update Agent COM API. Built into Windows (no PSGallery module),
  # no ShouldContinue prompt, works under SYSTEM. Non-fatal. ---
  if (-not $SkipOS) {
   try {
    $wu = New-Object -ComObject Microsoft.Update.Session
    $found = $wu.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software' and IsHidden=0").Updates
    $coll = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $found) { if (-not $u.EulaAccepted) { try { $u.AcceptEula() } catch { } }; [void]$coll.Add($u) }
    if ($DryRun) {
      Write-Output "DRY RUN - pending OS updates: $($coll.Count)"
      $result.os_updates = $coll.Count
    } elseif ($coll.Count -gt 0) {
      $dl = $wu.CreateUpdateDownloader(); $dl.Updates = $coll; [void]$dl.Download()
      $inst = $wu.CreateUpdateInstaller(); $inst.Updates = $coll
      $ir = $inst.Install()
      $result.os_updates = $coll.Count
      $result.reboot_required = [bool]$ir.RebootRequired
    }
   } catch { $result.notes += "OS patch step error (non-fatal): $($_.Exception.Message.Substring(0,[Math]::Min(120,$_.Exception.Message.Length)))" }
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
