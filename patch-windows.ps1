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
  engine = "iter4-userpass-os"   # build marker — bump on release; proves self-update landed
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
$script:WingetDiag = @()
function Resolve-Winget {
  $candidates = @()
  # winget.exe (MSIX) needs its framework DLLs (VCLibs, UI.Xaml) on the loader path to run
  # standalone under SYSTEM; without them a raw exec fails with 0xC0000135 (STATUS_DLL_NOT_
  # FOUND). Prepend the framework package dirs so SYSTEM can run winget directly (SYSTEM
  # already has machine-scope rights — no elevation trick).
  foreach ($fw in @('Microsoft.VCLibs.140.00.UWPDesktop','Microsoft.UI.Xaml.2.8','Microsoft.UI.Xaml.2.7','Microsoft.VCLibs.140.00')) {
    try {
      $p = Get-AppxPackage -AllUsers $fw -ErrorAction SilentlyContinue |
           Sort-Object { try { [version]$_.Version } catch { [version]'0.0' } } -Descending | Select-Object -First 1
      if ($p -and $p.InstallLocation) { $env:PATH = "$($p.InstallLocation);$env:PATH"; $script:WingetDiag += "dll+=$($p.Name)" }
    } catch { }
  }
  # A: Appx InstallLocation (WindowsApps is ACL-locked; Get-ChildItem gets access-denied)
  try {
    $pkgs = @(Get-AppxPackage -AllUsers Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue)
    $script:WingetDiag += "appx=$($pkgs.Count)"
    foreach ($p in ($pkgs | Sort-Object { try { [version]$_.Version } catch { [version]'0.0' } } -Descending)) {
      if ($p.InstallLocation) { $candidates += (Join-Path $p.InstallLocation 'winget.exe'); $script:WingetDiag += "loc=$($p.InstallLocation)|v=$($p.Version)" }
    }
  } catch { $script:WingetDiag += "appxERR=$($_.Exception.Message)" }
  # B: glob under Program Files
  $pf = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
  $glob = @(Get-ChildItem "$pf\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
  $script:WingetDiag += "glob=$($glob.Count)"; $candidates += $glob
  # C: PATH
  $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
  if ($cmd) { $candidates += $cmd.Source; $script:WingetDiag += "path=$($cmd.Source)" }
  # test each candidate with --version, recording exit/exception
  foreach ($c in ($candidates | Select-Object -Unique)) {
    try {
      $out = (& $c --version 2>&1 | Out-String).Trim()
      $script:WingetDiag += "TRY[$c]=exit:$LASTEXITCODE|$($out.Substring(0,[Math]::Min(60,$out.Length)))"
      if ($LASTEXITCODE -eq 0) { return $c }
    } catch { $script:WingetDiag += "TRY[$c]=EXC:$($_.Exception.Message.Substring(0,[Math]::Min(80,$_.Exception.Message.Length)))" }
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
  $result.winget_diag = $script:WingetDiag   # TEMP diagnostic: how resolution went
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

  # --- OS: PSWindowsUpdate (non-fatal; non-interactive SYSTEM context) ---
  if (-not $SkipOS) {
   try {
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
      if (-not $DryRun) {
        Set-PSRepository PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        Install-Module PSWindowsUpdate -Force -Scope AllUsers -ErrorAction Stop
      }
    }
    Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
    if (-not (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue)) {
      # dry-run must not install software; note the gap instead of dying on a
      # missing cmdlet (a CommandNotFound is terminating under EAP=Stop)
      $result.notes += "PSWindowsUpdate unavailable - OS update check skipped"
      Write-Warning "Aegis: PSWindowsUpdate unavailable - OS update check skipped"
    } elseif ($DryRun) {
      $pending = Get-WindowsUpdate -ErrorAction SilentlyContinue
      Write-Output "DRY RUN - pending OS updates: $($pending.Count)"
      $result.os_updates = @($pending).Count
    } else {
      $applied = Install-WindowsUpdate -AcceptAll -IgnoreReboot -Confirm:$false -ErrorAction SilentlyContinue
      $result.os_updates = @($applied).Count
      $result.reboot_required = [bool](Get-WURebootStatus -Silent -ErrorAction SilentlyContinue)
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
