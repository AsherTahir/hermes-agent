# DEBUG ONLY (debug/msix-launch-blacksmith-probe): why a direct launch of the installed
# MSIX exe is "Access is denied" on blacksmith Windows runners but not on GitHub-hosted ones.
# Records the step's session/token/job facts, the package ACLs, and tries each launch route.
param(
    [Parameter(Mandatory=$true)]$Package,
    [Parameter(Mandatory=$true)][string]$Exe,
    [Parameter(Mandatory=$true)][string]$Out
)
$ErrorActionPreference = 'Continue'
Set-StrictMode -Off
$log = Join-Path $Out 'msix-launch-probe.txt'
function Note([string]$Text) { Write-Host "[probe] $Text"; Add-Content -LiteralPath $log -Value $Text }
function Section([string]$Name, [scriptblock]$Body) {
    Note "===== $Name"
    try { (& $Body 2>&1 | Out-String -Width 4096).TrimEnd() -split "`r?`n" | ForEach-Object { Note $_ } }
    catch { Note "!! $($_ | Out-String)" }
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ProbeNative {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool GetUserObjectInformation(IntPtr obj, int index, System.Text.StringBuilder info, int length, out int needed);
}
'@ -ErrorAction SilentlyContinue

$root = $Package.InstallLocation.TrimEnd('\')
$family = $Package.PackageFamilyName
$manifest = Get-AppxPackageManifest -Package $Package.PackageFullName
$appIds = @($manifest.Package.Applications.Application | ForEach-Object { $_.Id })
$probeHome = Join-Path $Out 'probe-home'
New-Item -ItemType Directory -Force -Path $probeHome | Out-Null

function Stop-PackageProcesses {
    Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) } |
        ForEach-Object { Note "  kill pid=$($_.ProcessId) session=$($_.SessionId) $($_.ExecutablePath)"; Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
function Show-PackageProcesses([string]$Label) {
    $procs = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) })
    Note "  $Label package processes: $($procs.Count)"
    foreach ($p in $procs) { Note "    pid=$($p.ProcessId) ppid=$($p.ParentProcessId) session=$($p.SessionId) $($p.CommandLine)" }
}
# Direct CreateProcess with redirected stderr: the route Playwright needs (it reads the debugger lines).
function Try-Direct([string]$Label, [string]$File, [string]$Arguments) {
    Note "----- $Label :: $File $Arguments"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardOutput = $true
    $psi.EnvironmentVariables['HERMES_HOME'] = Join-Path $probeHome 'hermes'
    try {
        $p = [System.Diagnostics.Process]::Start($psi)
        $err = $p.StandardError.ReadLineAsync()
        $deadline = (Get-Date).AddSeconds(20)
        $lines = @()
        while ((Get-Date) -lt $deadline) {
            if ($err.Wait(500)) {
                if ($null -eq $err.Result) { break }
                $lines += $err.Result
                if ($err.Result -match 'DevTools listening') { break }
                $err = $p.StandardError.ReadLineAsync()
            }
            if ($p.HasExited -and $err.IsCompleted -and $null -eq $err.Result) { break }
        }
        foreach ($l in $lines) { Note "  [err] $l" }
        Show-PackageProcesses 'after start'
        if ($p.HasExited) { Note "  exited code=$($p.ExitCode)" } else { Note "  still running pid=$($p.Id)" }
    } catch {
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        Note "  start threw: $($ex.GetType().FullName): $($ex.Message) (native=$($ex.NativeErrorCode) hresult=0x$('{0:X8}' -f $ex.HResult))"
    }
    Stop-PackageProcesses
}
function Try-Activation([string]$Label, [scriptblock]$Body) {
    Note "----- $Label"
    try { $r = & $Body 2>&1 | Out-String -Width 4096; if ($r.Trim()) { Note "  $($r.Trim())" } }
    catch { Note "  threw: $($_ | Out-String)" }
    Start-Sleep -Seconds 15
    Show-PackageProcesses 'after activation'
    Stop-PackageProcesses
}

Remove-Item -LiteralPath $log -ErrorAction SilentlyContinue
Section 'host' { [Environment]::OSVersion.VersionString; (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, BuildNumber, OSArchitecture | Format-List | Out-String) }
Section 'step process' {
    $me = [System.Diagnostics.Process]::GetCurrentProcess()
    "pid=$($me.Id) session=$($me.SessionId) user=$([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    "USERPROFILE=$env:USERPROFILE LOCALAPPDATA=$env:LOCALAPPDATA"
    $inJob = $false; [void][ProbeNative]::IsProcessInJob([ProbeNative]::GetCurrentProcess(), [IntPtr]::Zero, [ref]$inJob); "in job object: $inJob"
    $sb = New-Object System.Text.StringBuilder 256; $n = 0
    [void][ProbeNative]::GetUserObjectInformation([ProbeNative]::GetProcessWindowStation(), 2, $sb, 512, [ref]$n); "window station: $sb"
    "elevated: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
}
Section 'whoami /groups' { whoami /groups /fo list | Select-String -Pattern 'Group Name|SID|Attributes' }
Section 'whoami /priv' { whoami /priv }
Section 'sessions' { qwinsta 2>&1; query user 2>&1 }
Section 'explorer + runner processes' {
    Get-CimInstance Win32_Process -Filter "Name='explorer.exe' OR Name='Runner.Listener.exe' OR Name='Runner.Worker.exe' OR Name='winlogon.exe' OR Name='sihost.exe'" |
        Select-Object ProcessId, ParentProcessId, SessionId, Name, @{n='Owner';e={ $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner; "$($o.Domain)\$($o.User)" }} | Format-Table -AutoSize
}
Section 'runner service' { Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'runner|actions|blacksmith' } | Select-Object Name, StartName, State, PathName | Format-List }
Section 'autologon' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object AutoAdminLogon, DefaultUserName | Format-List }
Section 'appx policy' {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -ErrorAction SilentlyContinue | Format-List
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx' -ErrorAction SilentlyContinue | Format-List
    Get-Service AppXSvc, StateRepository, ClipSVC, AppInfo -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType
}
Section 'package' { $Package | Format-List PackageFullName, PackageFamilyName, InstallLocation, Status, SignatureKind, IsDevelopmentMode; "appIds: $($appIds -join ', ')"; Get-AppxPackage -AllUsers -Name $Package.Name | Select-Object -ExpandProperty PackageUserInformation }
Section 'acl exe' { icacls $Exe; (Get-Acl -LiteralPath $Exe).Sddl }
Section 'acl package dir' { icacls $root; (Get-Acl -LiteralPath $root).Sddl }
Section 'acl WindowsApps' { icacls (Split-Path -Parent $root) }
Section 'aliases' { Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps') -ErrorAction SilentlyContinue | Select-Object Name, Length, LinkType | Format-Table -AutoSize }

$electronArgs = "--inspect=0 --remote-debugging-port=0 --user-data-dir=`"$(Join-Path $probeHome 'user-data')`""
Try-Direct 'CreateProcess exe' $Exe $electronArgs
Try-Direct 'cmd.exe /d /s /c (Playwright route)' $env:ComSpec "/d /s /c `"`"$Exe`" $electronArgs`""
$alias = Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps') -Filter 'hermes-*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '-(agent|acp)\.exe$' } | Select-Object -First 1
if ($alias) { Try-Direct 'CLI execution alias' $alias.FullName '--version' } else { Note '----- no CLI execution alias found' }
Try-Activation 'Start-Process (ShellExecute) exe' { Start-Process -FilePath $Exe -ArgumentList $electronArgs -PassThru | Select-Object Id }
Try-Activation 'shell:AppsFolder activation' { Start-Process -FilePath 'explorer.exe' -ArgumentList "shell:AppsFolder\$family!$($appIds[0])" }
Try-Activation 'Invoke-CommandInDesktopPackage' { Invoke-CommandInDesktopPackage -PackageFamilyName $family -AppId $appIds[0] -Command $Exe -Args $electronArgs }
Try-Activation 'Win32_Process.Create' { Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = "`"$Exe`" $electronArgs" } | Select-Object ProcessId, ReturnValue }
Section 'application log since probe' { Get-WinEvent -FilterHashtable @{ LogName='Application'; Level=1,2,3; StartTime=(Get-Date).AddMinutes(-5) } -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, ProviderName, Message }
Section 'appx deployment log' { Get-WinEvent -LogName 'Microsoft-Windows-AppModel-Runtime/Admin' -MaxEvents 30 -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, LevelDisplayName, Message }
Note '===== probe done'
