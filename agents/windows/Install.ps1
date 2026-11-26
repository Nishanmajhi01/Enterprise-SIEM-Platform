#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][uri]$IngestUrl,[switch]$AllowLabHttp)
$ErrorActionPreference = 'Stop'
if ($IngestUrl.Scheme -ne 'https' -and -not ($AllowLabHttp -and $IngestUrl.Scheme -eq 'http')) { throw 'HTTPS required; use AllowLabHttp only on a trusted lab network.' }
if ($IngestUrl.AbsolutePath -ne '/api/ingest' -or $IngestUrl.UserInfo -or $IngestUrl.Query -or $IngestUrl.Fragment) { throw 'Specify the complete /api/ingest URL.' }
$exe = Join-Path $PSScriptRoot 'Nexus.Agent.exe'
if (!(Test-Path $exe)) { throw 'Extract the published agent package first.' }
$secret = Read-Host 'Device API key' -AsSecureString
if ($secret.Length -eq 0) { throw 'Device key required.' }
$root = Join-Path $env:ProgramData 'NexusSIEM-Agent'
$task = 'NexusSIEM-Agent'
if (Test-Path $root) { throw 'Agent directory already exists. Uninstall before reinstalling.' }
New-Item -ItemType Directory -Path $root | Out-Null
try {
    & icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not secure installation directory.' }
    Copy-Item $exe $root
    Add-Type -AssemblyName System.Security
    $plain = [System.Net.NetworkCredential]::new('', $secret).Password
    $bytes = [Text.Encoding]::UTF8.GetBytes($plain)
    try {
        $encrypted = [Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
        [IO.File]::WriteAllBytes((Join-Path $root 'key.bin'),$encrypted)
    } finally { [Array]::Clear($bytes,0,$bytes.Length); $plain = $null }
    @{url=$IngestUrl.AbsoluteUri;allowLabHttp=[bool]$AllowLabHttp} | ConvertTo-Json | Set-Content (Join-Path $root 'config.json') -Encoding UTF8
    $action = New-ScheduledTaskAction -Execute (Join-Path $root 'Nexus.Agent.exe') -WorkingDirectory $root
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName $task
    Write-Host 'Nexus agent startup task installed. Check task status and SIEM events.'
} catch {
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
    throw
}
