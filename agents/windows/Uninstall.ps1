#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$task = Get-ScheduledTask -TaskName 'NexusSIEM-Agent' -ErrorAction SilentlyContinue
if ($task) {
    Stop-ScheduledTask -TaskName 'NexusSIEM-Agent'
    Unregister-ScheduledTask -TaskName 'NexusSIEM-Agent' -Confirm:$false
}
$root = Join-Path $env:ProgramData 'NexusSIEM-Agent'
if (Test-Path $root) { Remove-Item $root -Recurse -Force }
Write-Host 'Agent removed. Disable or revoke the device key in the SIEM dashboard if no longer needed.'
