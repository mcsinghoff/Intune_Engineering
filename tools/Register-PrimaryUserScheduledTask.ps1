#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ $_.EndsWith('
    [string]$TaskIdentity,

    [string]$TaskName = "Intune Primary User Correction",

    [string]$ScriptPath = "C:\Automation\IntunePrimaryUser\Set-NewPrimaryUserForDevices-AppReg.ps1",

    [string]$LogPath = "C:\ProgramData\IntunePrimaryUserCorrection\Logs",

    [string]$StatusPath = "C:\ProgramData\IntunePrimaryUserCorrection\Status",

    [ValidateRange(1, 500)]
    [int]$MaxChanges = 25,

    [string]$CandidateUpnSuffix,

    [string]$InstallerPrimaryUserRegex = "(?i)^installer[0-9]{2}@",

    [datetime]$DailyAt = (Get-Date "03:00"),

    [switch]$Apply,

    [switch]$RequireSignedScript
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    throw "Production script not found: $ScriptPath"
}

$pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source

if ($RequireSignedScript) {
    $signature = Get-AuthenticodeSignature -FilePath $ScriptPath
    if ($signature.Status -ne "Valid") {
        throw "RequireSignedScript is enabled, but Authenticode status is '$($signature.Status)'. Sign the production script with a trusted enterprise code-signing certificate first."
    }
}

$executionPolicy = if ($RequireSignedScript) { "AllSigned" } else { "RemoteSigned" }

foreach ($pathToCreate in @($LogPath, $StatusPath)) {
    if (-not (Test-Path -LiteralPath $pathToCreate)) {
        New-Item -Path $pathToCreate -ItemType Directory -Force | Out-Null
    }
}

function Quote-TaskArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    return '"' + $Value.Replace('"', '\"') + '"'
}

$argumentParts = [System.Collections.Generic.List[string]]::new()
$argumentParts.Add("-NoLogo")
$argumentParts.Add("-NoProfile")
$argumentParts.Add("-NonInteractive")
$argumentParts.Add("-ExecutionPolicy")
$argumentParts.Add($executionPolicy)
$argumentParts.Add("-File")
$argumentParts.Add((Quote-TaskArgument $ScriptPath))
$argumentParts.Add("-TenantId")
$argumentParts.Add((Quote-TaskArgument $TenantId))
$argumentParts.Add("-ClientId")
$argumentParts.Add((Quote-TaskArgument $ClientId))
$argumentParts.Add("-CertificateThumbprint")
$argumentParts.Add((Quote-TaskArgument $CertificateThumbprint))
$argumentParts.Add("-LogPath")
$argumentParts.Add((Quote-TaskArgument $LogPath))
$argumentParts.Add("-StatusPath")
$argumentParts.Add((Quote-TaskArgument $StatusPath))
$argumentParts.Add("-InstallerPrimaryUserRegex")
$argumentParts.Add((Quote-TaskArgument $InstallerPrimaryUserRegex))
$argumentParts.Add("-MaxChanges")
$argumentParts.Add([string]$MaxChanges)

if (-not [string]::IsNullOrWhiteSpace($CandidateUpnSuffix)) {
    $argumentParts.Add("-CandidateUpnSuffix")
    $argumentParts.Add((Quote-TaskArgument $CandidateUpnSuffix))
}

if ($Apply) {
    $argumentParts.Add("-Apply")
}

$arguments = $argumentParts -join " "

$action = New-ScheduledTaskAction -Execute $pwsh -Argument $arguments
$trigger = New-ScheduledTaskTrigger -Daily -At $DailyAt
$principal = New-ScheduledTaskPrincipal `
    -UserId $TaskIdentity `
    -LogonType Password `
    -RunLevel Limited

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1)

if ($PSCmdlet.ShouldProcess($TaskName, "Register daily scheduled task as $TaskIdentity")) {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Automatically corrects Intune Primary Users that are still assigned to installerXY accounts. Exit codes: 0=success, 1=fatal failure, 2=device-level errors." `
        -Force | Out-Null
}

Write-Host "Task name:        $TaskName"
Write-Host "Task identity:    $TaskIdentity"
Write-Host "Schedule:         Daily at $($DailyAt.ToString('HH:mm'))"
Write-Host "Mode:             $(if ($Apply) { 'APPLY' } else { 'REPORT-ONLY' })"
Write-Host "Execution policy: $executionPolicy"
Write-Host "Script:           $ScriptPath"
Write-Host "Logs:             $LogPath"
Write-Host "Status:           $StatusPath"
Write-Host ""
Write-Warning "This helper does not grant NTFS or certificate private-key permissions. Grant the gMSA Read/Execute on the script directory, Modify on LogPath/StatusPath, and Read on the application certificate private key."
) })]
    [string]$TaskIdentity,

    [string]$TaskName = "Intune Primary User Correction",

    [string]$ScriptPath = "C:\Automation\IntunePrimaryUser\Set-NewPrimaryUserForDevices-AppReg.ps1",

    [string]$LogPath = "C:\ProgramData\IntunePrimaryUserCorrection\Logs",

    [string]$StatusPath = "C:\ProgramData\IntunePrimaryUserCorrection\Status",

    [ValidateRange(1, 500)]
    [int]$MaxChanges = 25,

    [string]$CandidateUpnSuffix,

    [string]$InstallerPrimaryUserRegex = "(?i)^installer[0-9]{2}@",

    [datetime]$DailyAt = (Get-Date "03:00"),

    [switch]$Apply,

    [switch]$RequireSignedScript
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    throw "Production script not found: $ScriptPath"
}

$pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source

if ($RequireSignedScript) {
    $signature = Get-AuthenticodeSignature -FilePath $ScriptPath
    if ($signature.Status -ne "Valid") {
        throw "RequireSignedScript is enabled, but Authenticode status is '$($signature.Status)'. Sign the production script with a trusted enterprise code-signing certificate first."
    }
}

$executionPolicy = if ($RequireSignedScript) { "AllSigned" } else { "RemoteSigned" }

foreach ($pathToCreate in @($LogPath, $StatusPath)) {
    if (-not (Test-Path -LiteralPath $pathToCreate)) {
        New-Item -Path $pathToCreate -ItemType Directory -Force | Out-Null
    }
}

function Quote-TaskArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    return '"' + $Value.Replace('"', '\"') + '"'
}

$argumentParts = [System.Collections.Generic.List[string]]::new()
$argumentParts.Add("-NoLogo")
$argumentParts.Add("-NoProfile")
$argumentParts.Add("-NonInteractive")
$argumentParts.Add("-ExecutionPolicy")
$argumentParts.Add($executionPolicy)
$argumentParts.Add("-File")
$argumentParts.Add((Quote-TaskArgument $ScriptPath))
$argumentParts.Add("-TenantId")
$argumentParts.Add((Quote-TaskArgument $TenantId))
$argumentParts.Add("-ClientId")
$argumentParts.Add((Quote-TaskArgument $ClientId))
$argumentParts.Add("-CertificateThumbprint")
$argumentParts.Add((Quote-TaskArgument $CertificateThumbprint))
$argumentParts.Add("-LogPath")
$argumentParts.Add((Quote-TaskArgument $LogPath))
$argumentParts.Add("-StatusPath")
$argumentParts.Add((Quote-TaskArgument $StatusPath))
$argumentParts.Add("-InstallerPrimaryUserRegex")
$argumentParts.Add((Quote-TaskArgument $InstallerPrimaryUserRegex))
$argumentParts.Add("-MaxChanges")
$argumentParts.Add([string]$MaxChanges)

if (-not [string]::IsNullOrWhiteSpace($CandidateUpnSuffix)) {
    $argumentParts.Add("-CandidateUpnSuffix")
    $argumentParts.Add((Quote-TaskArgument $CandidateUpnSuffix))
}

if ($Apply) {
    $argumentParts.Add("-Apply")
}

$arguments = $argumentParts -join " "

$action = New-ScheduledTaskAction -Execute $pwsh -Argument $arguments
$trigger = New-ScheduledTaskTrigger -Daily -At $DailyAt
$principal = New-ScheduledTaskPrincipal `
    -UserId $TaskIdentity `
    -LogonType Password `
    -RunLevel Limited

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1)

if ($PSCmdlet.ShouldProcess($TaskName, "Register daily scheduled task as $TaskIdentity")) {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "Automatically corrects Intune Primary Users that are still assigned to installerXY accounts. Exit codes: 0=success, 1=fatal failure, 2=device-level errors." `
        -Force | Out-Null
}

Write-Host "Task name:        $TaskName"
Write-Host "Task identity:    $TaskIdentity"
Write-Host "Schedule:         Daily at $($DailyAt.ToString('HH:mm'))"
Write-Host "Mode:             $(if ($Apply) { 'APPLY' } else { 'REPORT-ONLY' })"
Write-Host "Execution policy: $executionPolicy"
Write-Host "Script:           $ScriptPath"
Write-Host "Logs:             $LogPath"
Write-Host "Status:           $StatusPath"
Write-Host ""
Write-Warning "This helper does not grant NTFS or certificate private-key permissions. Grant the gMSA Read/Execute on the script directory, Modify on LogPath/StatusPath, and Read on the application certificate private key."
