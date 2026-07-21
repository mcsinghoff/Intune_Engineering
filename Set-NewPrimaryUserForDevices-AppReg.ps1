<#
.SYNOPSIS
    Updates the Microsoft Intune Primary User for Windows devices based on a reviewed Defender XDR Advanced Hunting CSV export.

.DESCRIPTION
    This script reads a CSV file that contains device/user candidates from Defender XDR Advanced Hunting.
    It resolves the candidate user against on-prem Active Directory and Microsoft Entra ID, checks the current Intune
    Primary User, and updates the Intune Primary User only when safety conditions are met.

    Designed for controlled execution from an on-premises management server, for example by Windows Scheduled Task.

    Default behavior is report-only. Use -Apply to perform changes.

.PARAMETER CsvPath
    Path to the CSV exported from Defender XDR Advanced Hunting.

.PARAMETER TenantId
    Microsoft Entra tenant ID.

.PARAMETER ClientId
    Application client ID of the Entra App Registration.

.PARAMETER CertificateThumbprint
    Thumbprint of the certificate used for app-only Microsoft Graph authentication.

.PARAMETER LogPath
    Folder where logs and result CSV files are written.

.PARAMETER MinCandidateLogonCount
    Minimum number of candidate user logons required.

.PARAMETER MinCandidateActiveDays
    Minimum number of distinct active days required.

.PARAMETER RequiredConfidence
    Required confidence from the KQL result. Default: High.

.PARAMETER InstallerPrimaryUserRegex
    Regex that identifies installer/deployment users currently set as Primary User in Intune.

.PARAMETER MaxChanges
    Maximum number of Primary User changes allowed per run.

.PARAMETER Apply
    If specified, changes are written to Intune. Without this switch, the script runs in report-only mode.

.EXAMPLE
    .\Set-IntunePrimaryUserFromCsv.ps1 `
        -CsvPath "C:\PrimaryUserCorrection\input\primary-user-candidates.csv" `
        -TenantId "00000000-0000-0000-0000-000000000000" `
        -ClientId "11111111-1111-1111-1111-111111111111" `
        -CertificateThumbprint "ABCDEF123456..." `
        -LogPath "C:\PrimaryUserCorrection\logs"

.EXAMPLE
    .\Set-IntunePrimaryUserFromCsv.ps1 `
        -CsvPath "C:\PrimaryUserCorrection\input\primary-user-candidates.csv" `
        -TenantId "00000000-0000-0000-0000-000000000000" `
        -ClientId "11111111-1111-1111-1111-111111111111" `
        -CertificateThumbprint "ABCDEF123456..." `
        -LogPath "C:\PrimaryUserCorrection\logs" `
        -Apply `
        -MaxChanges 25

.NOTES
    Requirements:
    - Microsoft.Graph.Authentication PowerShell module
    - ActiveDirectory PowerShell module
    - App Registration with certificate authentication
    - Graph application permissions:
        DeviceManagementManagedDevices.ReadWrite.All
        User.Read.All or Directory.Read.All
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $true)]
    [string]$LogPath,

    [int]$MinCandidateLogonCount = 3,

    [int]$MinCandidateActiveDays = 2,

    [string]$RequiredConfidence = "High",

    [string]$InstallerPrimaryUserRegex = "(?i)(^installer|^deployment|^intune-installer)",

    [int]$MaxChanges = 25,

    [switch]$Apply
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# -----------------------------
# Initial setup
# -----------------------------

if (-not (Test-Path -Path $CsvPath)) {
    throw "CSV file not found: $CsvPath"
}

if (-not (Test-Path -Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$transcriptPath = Join-Path $LogPath "PrimaryUserCorrection-$timestamp.log"
$resultPath = Join-Path $LogPath "PrimaryUserCorrection-Result-$timestamp.csv"

Start-Transcript -Path $transcriptPath -Force | Out-Null

$results = New-Object System.Collections.Generic.List[object]
$changeCount = 0

function Write-Info {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
}

function Add-Result {
    param(
        [string]$DeviceName,
        [string]$DeviceShortName,
        [string]$CandidateSamAccountName,
        [string]$CandidateSid,
        [string]$CandidateUpn,
        [string]$CurrentPrimaryUser,
        [string]$Action,
        [string]$Reason
    )

    $script:results.Add([PSCustomObject]@{
        Timestamp                  = (Get-Date).ToString("s")
        DeviceName                 = $DeviceName
        DeviceShortName            = $DeviceShortName
        CandidateSamAccountName    = $CandidateSamAccountName
        CandidateSid               = $CandidateSid
        CandidateUpn               = $CandidateUpn
        CurrentPrimaryUser         = $CurrentPrimaryUser
        Action                     = $Action
        Reason                     = $Reason
    })
}

function Invoke-GraphRequestWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST", "PATCH", "DELETE")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [object]$Body = $null,

        [int]$MaxRetries = 5
    )

    $attempt = 0

    while ($true) {
        try {
            if ($null -ne $Body) {
                $jsonBody = $Body | ConvertTo-Json -Depth 10
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $jsonBody -ContentType "application/json"
            }
            else {
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri
            }
        }
        catch {
            $attempt++

            $statusCode = $null
            try {
                $statusCode = $_.Exception.Response.StatusCode.value__
            }
            catch {
                $statusCode = $null
            }

            if ($attempt -ge $MaxRetries -or ($statusCode -ne 429 -and $statusCode -lt 500)) {
                throw
            }

            $sleepSeconds = [Math]::Min(60, [Math]::Pow(2, $attempt))
            Write-Info "Graph request failed with status $statusCode. Retry $attempt/$MaxRetries in $sleepSeconds seconds."
            Start-Sleep -Seconds $sleepSeconds
        }
    }
}

function Resolve-CandidateFromAd {
    param(
        [string]$CandidateSid,
        [string]$CandidateSamAccountName
    )

    $adUser = $null

    if (-not [string]::IsNullOrWhiteSpace($CandidateSid)) {
        try {
            $adUser = Get-ADUser -Identity $CandidateSid -Properties UserPrincipalName, Enabled
        }
        catch {
            $adUser = $null
        }
    }

    if ($null -eq $adUser -and -not [string]::IsNullOrWhiteSpace($CandidateSamAccountName)) {
        $safeSam = $CandidateSamAccountName.Replace("'", "''")
        $matches = @(Get-ADUser -Filter "SamAccountName -eq '$safeSam'" -Properties UserPrincipalName, Enabled)

        if ($matches.Count -eq 1) {
            $adUser = $matches[0]
        }
        elseif ($matches.Count -gt 1) {
            throw "Multiple AD users found for SamAccountName '$CandidateSamAccountName'. Use CandidateSid or enrich the CSV with UPN."
        }
    }

    if ($null -eq $adUser) {
        throw "No AD user found for SID '$CandidateSid' / SamAccountName '$CandidateSamAccountName'."
    }

    if (-not $adUser.Enabled) {
        throw "AD user '$($adUser.SamAccountName)' is disabled."
    }

    if ([string]::IsNullOrWhiteSpace($adUser.UserPrincipalName)) {
        throw "AD user '$($adUser.SamAccountName)' has no UserPrincipalName."
    }

    return $adUser.UserPrincipalName
}

function Get-GraphUserByUpn {
    param([Parameter(Mandatory = $true)][string]$UserPrincipalName)

    $encodedUpn = [uri]::EscapeDataString($UserPrincipalName)
    $uri = "https://graph.microsoft.com/v1.0/users/$encodedUpn?`$select=id,userPrincipalName,displayName,accountEnabled"
    return Invoke-GraphRequestWithRetry -Method GET -Uri $uri
}

function Get-ManagedDeviceByName {
    param([Parameter(Mandatory = $true)][string]$DeviceName)

    $escapedName = $DeviceName.Replace("'", "''")
    $filter = [uri]::EscapeDataString("deviceName eq '$escapedName'")
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=$filter&`$select=id,deviceName,userPrincipalName,userDisplayName,operatingSystem,lastSyncDateTime,azureADDeviceId"

    $response = Invoke-GraphRequestWithRetry -Method GET -Uri $uri
    return @($response.value)
}

function Get-ManagedDevicePrimaryUser {
    param([Parameter(Mandatory = $true)][string]$ManagedDeviceId)

    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$ManagedDeviceId')/users?`$select=id,userPrincipalName,displayName"
    $response = Invoke-GraphRequestWithRetry -Method GET -Uri $uri
    $users = @($response.value)

    if ($users.Count -ge 1) {
        return $users[0]
    }

    return $null
}

function Set-ManagedDevicePrimaryUser {
    param(
        [Parameter(Mandatory = $true)][string]$ManagedDeviceId,
        [Parameter(Mandatory = $true)][string]$UserId
    )

    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$ManagedDeviceId')/users/`$ref"

    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/users/$UserId"
    }

    Invoke-GraphRequestWithRetry -Method POST -Uri $uri -Body $body | Out-Null
}

try {
    # -----------------------------
    # Module import and Graph login
    # -----------------------------

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Info "Connecting to Microsoft Graph with certificate authentication."
    Connect-MgGraph `
        -TenantId $TenantId `
        -ClientId $ClientId `
        -CertificateThumbprint $CertificateThumbprint `
        -NoWelcome | Out-Null

    $context = Get-MgContext
    Write-Info "Connected to tenant: $($context.TenantId)"
    Write-Info "Mode: $(if ($Apply) { 'APPLY' } else { 'REPORT-ONLY' })"

    # -----------------------------
    # Import CSV
    # -----------------------------

    $rows = @(Import-Csv -Path $CsvPath)

    if ($rows.Count -eq 0) {
        throw "CSV contains no rows."
    }

    Write-Info "Imported $($rows.Count) rows from CSV."

    foreach ($row in $rows) {
        $deviceName = $null
        $deviceShortName = $null
        $candidateSam = $null
        $candidateSid = $null
        $candidateUpn = $null
        $currentPrimaryUserUpn = $null

        try {
            $deviceShortName = [string]$row.DeviceShortName
            $deviceName = [string]$row.DeviceName
            $candidateSam = [string]$row.CandidateSamAccountName
            $candidateSid = [string]$row.CandidateSid

            if ([string]::IsNullOrWhiteSpace($deviceShortName)) {
                if (-not [string]::IsNullOrWhiteSpace($deviceName)) {
                    $deviceShortName = [string]($deviceName.Split(".")[0])
                }
            }

            if ([string]::IsNullOrWhiteSpace($deviceShortName)) {
                Add-Result -DeviceName $deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn "" -CurrentPrimaryUser "" -Action "Skipped" -Reason "No DeviceShortName or DeviceName in CSV."
                continue
            }

            # Safety checks from KQL result
            $candidateLogonCount = 0
            $candidateActiveDays = 0
            [int]::TryParse([string]$row.CandidateLogonCount, [ref]$candidateLogonCount) | Out-Null
            [int]::TryParse([string]$row.CandidateActiveDays, [ref]$candidateActiveDays) | Out-Null

            if ($candidateLogonCount -lt $MinCandidateLogonCount) {
                Add-Result -DeviceName $deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn "" -CurrentPrimaryUser "" -Action "Skipped" -Reason "CandidateLogonCount below threshold."
                continue
            }

            if ($candidateActiveDays -lt $MinCandidateActiveDays) {
                Add-Result -DeviceName $deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn "" -CurrentPrimaryUser "" -Action "Skipped" -Reason "CandidateActiveDays below threshold."
                continue
            }

            if ($row.PSObject.Properties.Name -contains "Confidence") {
                if ([string]$row.Confidence -ne $RequiredConfidence) {
                    Add-Result -DeviceName $deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn "" -CurrentPrimaryUser "" -Action "Skipped" -Reason "Confidence is '$($row.Confidence)', required '$RequiredConfidence'."
                    continue
                }
            }

            # Resolve user from CSV UPN if present, otherwise from AD
            if ($row.PSObject.Properties.Name -contains "CandidateUserPrincipalName" -and -not [string]::IsNullOrWhiteSpace([string]$row.CandidateUserPrincipalName)) {
                $candidateUpn = [string]$row.CandidateUserPrincipalName
            }
            elseif ($row.PSObject.Properties.Name -contains "AccountUpn" -and -not [string]::IsNullOrWhiteSpace([string]$row.AccountUpn)) {
                $candidateUpn = [string]$row.AccountUpn
            }
            else {
                $candidateUpn = Resolve-CandidateFromAd -CandidateSid $candidateSid -CandidateSamAccountName $candidateSam
            }

            $graphUser = Get-GraphUserByUpn -UserPrincipalName $candidateUpn

            if ($null -eq $graphUser -or [string]::IsNullOrWhiteSpace($graphUser.id)) {
                Add-Result -DeviceName $deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn $candidateUpn -CurrentPrimaryUser "" -Action "Skipped" -Reason "User not found in Microsoft Graph."
                continue
            }

            if ($graphUser.accountEnabled -ne $true) {
                Add-Result -DeviceName $deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn $candidateUpn -CurrentPrimaryUser "" -Action "Skipped" -Reason "Entra user is disabled."
                continue
            }

            # Find Intune device by short name
            $devices = @(Get-ManagedDeviceByName -DeviceName $deviceShortName)

            if ($devices.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($deviceName)) {
                $devices = @(Get-ManagedDeviceByName -DeviceName $deviceName)
            }

            if ($devices.Count -eq 0) {
                Add-Result -DeviceName $deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn $candidateUpn -CurrentPrimaryUser "" -Action "Skipped" -Reason "Intune managed device not found."
                continue
            }

            if ($devices.Count -gt 1) {
                Add-Result -DeviceName $deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn $candidateUpn -CurrentPrimaryUser "" -Action "Skipped" -Reason "Multiple Intune managed devices found with this name. Manual review required."
                continue
            }

            $device = $devices[0]

            if ($device.operatingSystem -ne "Windows") {
                Add-Result -DeviceName $device.deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn $candidateUpn -CurrentPrimaryUser "" -Action "Skipped" -Reason "Device is not Windows."
                continue
            }

            $currentPrimary = Get-ManagedDevicePrimaryUser -ManagedDeviceId $device.id

            if ($null -ne $currentPrimary -and -not [string]::IsNullOrWhiteSpace($currentPrimary.userPrincipalName)) {
                $currentPrimaryUserUpn = $currentPrimary.userPrincipalName
            }
            else {
                $currentPrimaryUserUpn = [string]$device.userPrincipalName
            }

            if ([string]::IsNullOrWhiteSpace($currentPrimaryUserUpn)) {
                Add-Result -DeviceName $device.deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn $candidateUpn -CurrentPrimaryUser "" -Action "Skipped" -Reason "Current Primary User is empty. Manual review recommended."
                continue
            }

            if ($currentPrimaryUserUpn -notmatch $InstallerPrimaryUserRegex) {
                Add-Result -DeviceName $device.deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn $candidateUpn -CurrentPrimaryUser $currentPrimaryUserUpn -Action "Skipped" -Reason "Current Primary User does not match installer/deployment regex."
                continue
            }

            if ($currentPrimaryUserUpn -ieq $candidateUpn) {
                Add-Result -DeviceName $device.deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn $candidateUpn -CurrentPrimaryUser $currentPrimaryUserUpn -Action "Skipped" -Reason "Candidate is already current Primary User."
                continue
            }

            if ($Apply -and $changeCount -ge $MaxChanges) {
                Add-Result -DeviceName $device.deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn $candidateUpn -CurrentPrimaryUser $currentPrimaryUserUpn -Action "Skipped" -Reason "MaxChanges limit reached."
                continue
            }

            $targetDescription = "$($device.deviceName): $currentPrimaryUserUpn -> $candidateUpn"

            if (-not $Apply) {
                Add-Result -DeviceName $device.deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn $candidateUpn -CurrentPrimaryUser $currentPrimaryUserUpn -Action "WouldChange" -Reason "Report-only mode."
                continue
            }

            if ($PSCmdlet.ShouldProcess($targetDescription, "Set Intune Primary User")) {
                Set-ManagedDevicePrimaryUser -ManagedDeviceId $device.id -UserId $graphUser.id
                $changeCount++

                Add-Result -DeviceName $device.deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn $candidateUpn -CurrentPrimaryUser $currentPrimaryUserUpn -Action "Changed" -Reason "Primary User changed."
                Write-Info "Changed Primary User: $targetDescription"
            }
        }
        catch {
            Add-Result -DeviceName $deviceName -DeviceShortName $deviceShortName -CandidateSamAccountName $candidateSam -CandidateSid $candidateSid -CandidateUpn $candidateUpn -CurrentPrimaryUser $currentPrimaryUserUpn -Action "Error" -Reason $_.Exception.Message
            Write-Warning "Error processing row for device '$deviceShortName': $($_.Exception.Message)"
        }
    }

    $results | Export-Csv -Path $resultPath -NoTypeInformation -Encoding UTF8

    Write-Info "Completed."
    Write-Info "Changes performed: $changeCount"
    Write-Info "Result CSV: $resultPath"
    Write-Info "Transcript: $transcriptPath"
}
finally {
    try {
        Disconnect-MgGraph | Out-Null
    }
    catch {
        # ignore disconnect errors
    }

    Stop-Transcript | Out-Null
}
