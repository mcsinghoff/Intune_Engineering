<#
.SYNOPSIS
    Updates Intune Primary User based on Defender XDR Advanced Hunting logon data.

.DESCRIPTION
    Legacy delegated version:
    - No customer App Registration
    - No Managed Identity
    - No Azure Automation
    - Interactive delegated Microsoft Graph login
    - Runs Advanced Hunting KQL directly
    - Resolves CandidateSid to UPN using on-prem Active Directory
    - Updates Intune Primary User only if current user matches installer/deployment pattern
    - Supports -WhatIf

.REQUIREMENTS
    Modules:
    - Microsoft.Graph.Authentication
    - ActiveDirectory

    Delegated Graph scopes:
    - ThreatHunting.Read.All
    - DeviceManagementManagedDevices.ReadWrite.All
    - User.Read.All
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [string]$LogPath = (Join-Path $env:TEMP "PrimaryUserCorrection"),

    [int]$MinCandidateLogonCount = 3,

    [int]$MinCandidateActiveDays = 2,

    [string]$RequiredConfidence = "High",

    [string]$InstallerPrimaryUserRegex = "(?i)^installer[0-9]{2}@",

    [int]$MaxChanges = 25,

    [switch]$UseDeviceCode
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$resultPath = Join-Path $LogPath "PrimaryUserCorrection-Result-$timestamp.csv"
$transcriptPath = Join-Path $LogPath "PrimaryUserCorrection-$timestamp.log"

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
        [string]$CurrentPrimaryUser,
        [string]$CandidateSamAccountName,
        [string]$CandidateSid,
        [string]$CandidateUpn,
        [string]$Action,
        [string]$Reason
    )

    $script:results.Add([PSCustomObject]@{
        Timestamp               = (Get-Date).ToString("s")
        DeviceName              = $DeviceName
        DeviceShortName         = $DeviceShortName
        CurrentPrimaryUser      = $CurrentPrimaryUser
        CandidateSamAccountName = $CandidateSamAccountName
        CandidateSid            = $CandidateSid
        CandidateUpn            = $CandidateUpn
        Action                  = $Action
        Reason                  = $Reason
    })
}

function Invoke-GraphRequestWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [object]$Body = $null,

        [int]$MaxRetries = 4
    )

    $attempt = 0

    while ($true) {
        try {
            if ($null -ne $Body) {
                $jsonBody = $Body | ConvertTo-Json -Depth 20
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $jsonBody -ContentType "application/json"
            }

            return Invoke-MgGraphRequest -Method $Method -Uri $Uri
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

            $sleepSeconds = [Math]::Min(30, [Math]::Pow(2, $attempt))
            Write-Info "Graph request failed with HTTP $statusCode. Retry $attempt/$MaxRetries in $sleepSeconds seconds."
            Start-Sleep -Seconds $sleepSeconds
        }
    }
}

function Invoke-PrimaryUserHuntingQuery {
    $query = @'
let Lookback = 30d;
let InstallerDevices =
    DeviceLogonEvents
    | where Timestamp > ago(Lookback)
    | extend
        DeviceShortName = tostring(split(DeviceName, ".")[0]),
        AccountNameLower = tolower(AccountName),
        AccountDomainLower = tolower(AccountDomain)
    | summarize
        InstallerLogonCount = count(),
        InstallerActiveDays = dcount(startofday(Timestamp)),
        InstallerFirstLogon = min(Timestamp),
        InstallerLastLogon = max(Timestamp),
        InstallerAccounts = make_set(strcat(AccountDomainLower, "\\", AccountNameLower), 10)
        by DeviceId, DeviceName, DeviceShortName;
let RankedCandidates =
    DeviceLogonEvents
    | where Timestamp > ago(Lookback)
    | join kind=inner (
        InstallerDevices
        | project DeviceId
    ) on DeviceId
    | extend
        AccountNameLower = tolower(AccountName),
        AccountDomainLower = tolower(AccountDomain)
    | summarize
        CandidateLogonCount = count(),
        CandidateActiveDays = dcount(startofday(Timestamp)),
        CandidateFirstLogon = min(Timestamp),
        CandidateLastLogon = max(Timestamp),
        CandidateLogonTypes = make_set(LogonType, 10)
        by DeviceId, CandidateDomain = AccountDomainLower, CandidateSamAccountName = AccountNameLower, CandidateSid = AccountSid
    | sort by DeviceId asc, CandidateLogonCount desc, CandidateActiveDays desc, CandidateLastLogon desc
    | serialize
    | extend CandidateRank = row_number(1, prev(DeviceId) != DeviceId);
let TopCandidate =
    RankedCandidates
    | where CandidateRank == 1;
let SecondCandidate =
    RankedCandidates
    | where CandidateRank == 2
    | project
        DeviceId,
        SecondCandidate = strcat(CandidateDomain, "\\", CandidateSamAccountName),
        SecondCandidateLogonCount = CandidateLogonCount;
InstallerDevices
| join kind=leftouter TopCandidate on DeviceId
| join kind=leftouter SecondCandidate on DeviceId
| extend CandidateAccount = strcat(CandidateDomain, "\\", CandidateSamAccountName)
| extend Confidence =
    case(
        isempty(CandidateSamAccountName), "No candidate",
        isnull(SecondCandidateLogonCount), "High",
        CandidateLogonCount >= SecondCandidateLogonCount * 2, "High",
        CandidateLogonCount > SecondCandidateLogonCount, "Medium",
        "Low"
    )
| project
    DeviceName,
    DeviceShortName,
    InstallerAccounts,
    InstallerLogonCount,
    InstallerActiveDays,
    CandidateAccount,
    Confidence,
    InstallerFirstLogon,
    InstallerLastLogon,
    CandidateSamAccountName,
    CandidateSid,
    CandidateLogonCount,
    CandidateActiveDays,
    CandidateFirstLogon,
    CandidateLastLogon,
    SecondCandidate,
    SecondCandidateLogonCount
| order by DeviceShortName asc
'@

    $body = @{
        Query = $query
    }

    $response = Invoke-GraphRequestWithRetry `
        -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" `
        -Body $body

    return @($response.results)
}

function Resolve-CandidateUpnFromAd {
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
            throw "Multiple AD users found for SamAccountName '$CandidateSamAccountName'."
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
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=$filter&`$select=id,deviceName,userPrincipalName,userDisplayName,operatingSystem,lastSyncDateTime"

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
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    import-module ActiveDirectory -ErrorAction Stop

    $scopes = @(
        "ThreatHunting.Read.All",
        "DeviceManagementManagedDevices.ReadWrite.All",
        "User.Read.All"
    )

    Write-Info "Connecting to Microsoft Graph with delegated admin login."

    if ($UseDeviceCode) {
        Connect-MgGraph -Scopes $scopes -UseDeviceCode | Out-Null
    }
    else {
        Connect-MgGraph -Scopes $scopes | Out-Null
    }

    $ctx = Get-MgContext
    Write-Info "Connected as: $($ctx.Account)"
    Write-Info "Tenant: $($ctx.TenantId)"

    Write-Info "Running Defender XDR Advanced Hunting query."
    $rows = @(Invoke-PrimaryUserHuntingQuery)

    if ($rows.Count -eq 0) {
        Write-Info "Advanced Hunting query returned no rows."
        return
    }

    Write-Info "Advanced Hunting returned $($rows.Count) candidate rows."
    Write-Info "Maximum changes in this run: $MaxChanges"

    foreach ($row in $rows) {
        $deviceName = ""
        $deviceShortName = ""
        $candidateSam = ""
        $candidateSid = ""
        $candidateUpn = ""
        $currentPrimaryUserUpn = ""

        try {
            $deviceName = [string]$row.DeviceName
            $deviceShortName = [string]$row.DeviceShortName
            $candidateSam = [string]$row.CandidateSamAccountName
            $candidateSid = [string]$row.CandidateSid

            if ([string]::IsNullOrWhiteSpace($deviceShortName) -and -not [string]::IsNullOrWhiteSpace($deviceName)) {
                $deviceShortName = [string]($deviceName.Split(".")[0])
            }

            if ([string]::IsNullOrWhiteSpace($deviceShortName)) {
                Add-Result $deviceName $deviceShortName $candidateSam $candidateSid "" "" "Skipped" "Missing DeviceShortName."
                continue
            }

            if ([string]$row.Confidence -ne $RequiredConfidence) {
                Add-Result $deviceName $deviceShortName $candidateSam $candidateSid "" "" "Skipped" "Confidence '$($row.Confidence)' does not match required '$RequiredConfidence'."
                continue
            }

            $candidateLogonCount = 0
            $candidateActiveDays = 0

            [int]::TryParse([string]$row.CandidateLogonCount, [ref]$candidateLogonCount) | Out-Null
            [int]::TryParse([string]$row.CandidateActiveDays, [ref]$candidateActiveDays) | Out-Null

            if ($candidateLogonCount -lt $MinCandidateLogonCount) {
                Add-Result $deviceName $deviceShortName $candidateSam $candidateSid "" "" "Skipped" "CandidateLogonCount below threshold."
                continue
            }

            if ($candidateActiveDays -lt $MinCandidateActiveDays) {
                Add-Result $deviceName $deviceShortName $candidateSam $candidateSid "" "" "Skipped" "CandidateActiveDays below threshold."
                continue
            }

            $candidateUpn = Resolve-CandidateUpnFromAd `
                -CandidateSid $candidateSid `
                -CandidateSamAccountName $candidateSam

            $graphUser = Get-GraphUserByUpn -UserPrincipalName $candidateUpn

            if ($null -eq $graphUser -or [string]::IsNullOrWhiteSpace($graphUser.id)) {
                Add-Result $deviceName $deviceShortName $candidateSam $candidateSid $candidateUpn "" "Skipped" "Candidate user not found in Graph."
                continue
            }

            if ($graphUser.accountEnabled -ne $true) {
                Add-Result $deviceName $deviceShortName $candidateSam $candidateSid $candidateUpn "" "Skipped" "Candidate user is disabled in Entra ID."
                continue
            }

            $devices = @(Get-ManagedDeviceByName -DeviceName $deviceShortName)

            if ($devices.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($deviceName)) {
                $devices = @(Get-ManagedDeviceByName -DeviceName $deviceName)
            }

            if ($devices.Count -eq 0) {
                Add-Result $deviceName $deviceShortName $candidateSam $candidateSid $candidateUpn "" "Skipped" "Intune device not found."
                continue
            }

            if ($devices.Count -gt 1) {
                Add-Result $deviceName $deviceShortName $candidateSam $candidateSid $candidateUpn "" "Skipped" "Multiple Intune devices found. Manual review required."
                continue
            }

            $device = $devices[0]

            if ($device.operatingSystem -ne "Windows") {
                Add-Result $device.deviceName $deviceShortName $candidateSam $candidateSid $candidateUpn "" "Skipped" "Device is not Windows."
                continue
            }

            $currentPrimary = Get-ManagedDevicePrimaryUser -ManagedDeviceId $device.id

            if ($null -ne $currentPrimary -and -not [string]::IsNullOrWhiteSpace($currentPrimary.userPrincipalName)) {
                $currentPrimaryUserUpn = [string]$currentPrimary.userPrincipalName
            }
            else {
                $currentPrimaryUserUpn = [string]$device.userPrincipalName
            }

            if ([string]::IsNullOrWhiteSpace($currentPrimaryUserUpn)) {
                Add-Result $device.deviceName $deviceShortName $candidateSam $candidateSid $candidateUpn "" "Skipped" "Current Primary User is empty. Manual review recommended."
                continue
            }

            if ($currentPrimaryUserUpn -notmatch $InstallerPrimaryUserRegex) {
                Add-Result $device.deviceName $deviceShortName $candidateSam $candidateSid $candidateUpn $currentPrimaryUserUpn "Skipped" "Current Primary User does not match installer/deployment regex."
                continue
            }

            if ($currentPrimaryUserUpn -ieq $candidateUpn) {
                Add-Result $device.deviceName $deviceShortName $candidateSam $candidateSid $candidateUpn $currentPrimaryUserUpn "Skipped" "Candidate is already Primary User."
                continue
            }

            if ($changeCount -ge $MaxChanges) {
                Add-Result $device.deviceName $deviceShortName $candidateSam $candidateSid $candidateUpn $currentPrimaryUserUpn "Skipped" "MaxChanges limit reached."
                continue
            }

            $target = "$($device.deviceName): $currentPrimaryUserUpn -> $candidateUpn"

            if ($PSCmdlet.ShouldProcess($target, "Set Intune Primary User")) {
                Set-ManagedDevicePrimaryUser -ManagedDeviceId $device.id -UserId $graphUser.id
                $changeCount++

                Add-Result $device.deviceName $deviceShortName $candidateSam $candidateSid $candidateUpn $currentPrimaryUserUpn "Changed" "Primary User changed."
                Write-Info "Changed Primary User: $target"
            }
            else {
                Add-Result $device.deviceName $deviceShortName $candidateSam $candidateSid $candidateUpn $currentPrimaryUserUpn "WouldChange" "WhatIf or ShouldProcess prevented change."
            }
        }
        catch {
            Add-Result $deviceName $deviceShortName $candidateSam $candidateSid $candidateUpn $currentPrimaryUserUpn "Error" $_.Exception.Message
            Write-Warning "Error processing device '$deviceShortName': $($_.Exception.Message)"
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
        # ignore
    }

    Stop-Transcript | Out-Null
}