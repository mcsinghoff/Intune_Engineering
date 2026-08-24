<#
.SYNOPSIS
    Updates Intune Primary User assignments based on Defender XDR Advanced Hunting logon data.

.DESCRIPTION
    This script identifies likely real primary users for Intune-managed Windows devices by using
    Defender XDR Advanced Hunting logon data from DeviceLogonEvents.

    It is designed for environments where devices were initially enrolled or installed with
    installer/deployment accounts and where the Intune Primary User should later be corrected
    to the actual user of the device.

    Delegated admin version:
    - No customer App Registration required
    - No Managed Identity required
    - No Azure Automation required
    - Uses interactive delegated Microsoft Graph login
    - Runs a Defender XDR Advanced Hunting KQL query
    - Resolves candidate users either through on-prem Active Directory or by building the UPN
      from the detected samAccountName and a supplied UPN suffix
    - Updates the Intune Primary User only if the current Primary User matches the configured
      installer/deployment account regex
    - Supports -WhatIf
    - Writes a transcript and CSV result report even during -WhatIf runs

.PARAMETER TenantId
    Optional tenant ID or verified domain name used for Microsoft Graph login.
    For best reliability, use the tenant GUID.

.PARAMETER LogPath
    Folder path for transcript and CSV result output.
    If not specified, a folder named PrimaryUserCorrection is created below the user's TEMP path.

.PARAMETER MinCandidateLogonCount
    Minimum number of successful interactive logons required for a candidate user.
    Default is 3.

.PARAMETER MinCandidateActiveDays
    Minimum number of different active logon days required for a candidate user.
    Default is 2.

.PARAMETER RequiredConfidence
    Required confidence level from the KQL candidate ranking logic.
    Default is High.

.PARAMETER InstallerPrimaryUserRegex
    Regular expression used to identify current Primary Users that are installer or deployment accounts.
    Devices are only changed if the current Primary User matches this regex.
    Default is (?i)^installer[0-9]{2}@.

.PARAMETER MaxChanges
    Maximum number of Primary User changes allowed in one script run.
    Default is 25.

.PARAMETER UseDeviceCode
    Uses device code authentication for Microsoft Graph instead of the default interactive login.

.PARAMETER SkipAdResolution
    Skips on-prem Active Directory lookup and derives the candidate UPN from the candidate
    samAccountName and CandidateUpnSuffix.

    This is useful for cloud-only test tenants or lab environments without AD Web Services.
    Do not use this in production unless samAccountName and UPN prefix are guaranteed to match.

.PARAMETER CandidateUpnSuffix
    UPN suffix used together with SkipAdResolution to construct the candidate UPN.

    Example:
    CandidateSamAccountName = adminmsn
    CandidateUpnSuffix      = icscf.de
    Resulting CandidateUpn  = adminmsn@icscf.de

.PARAMETER ManualCandidateDeviceName
    Optional test mode parameter. If specified, the script skips Advanced Hunting and injects
    a synthetic candidate row for this device.

.PARAMETER ManualCandidateUpn
    Candidate UPN used in manual candidate mode.

.PARAMETER ManualCandidateSamAccountName
    Optional candidate samAccountName used in manual candidate mode.
    If not specified, it is derived from ManualCandidateUpn.

.PARAMETER AllowManualCandidateWrite
    Allows productive write operations in manual candidate mode.
    Without this switch, manual candidate mode only works with -WhatIf.

.REQUIREMENTS
    PowerShell modules:
    - Microsoft.Graph.Authentication
    - ActiveDirectory, only required when SkipAdResolution is not used

    Delegated Microsoft Graph scopes:
    - ThreatHunting.Read.All
    - DeviceManagementManagedDevices.ReadWrite.All
    - User.Read.All

    For on-prem AD resolution:
    - RSAT Active Directory PowerShell module
    - Network connectivity to a domain controller with Active Directory Web Services
    - Permission to read AD user objects

.EXAMPLE
    .\Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1 -WhatIf

    Runs the script in report-only mode using delegated Graph login and on-prem Active Directory
    user resolution.

.EXAMPLE
    .\Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1 `
        -TenantId "ade56966-ae5b-4e8d-95c6-b84548490b80" `
        -LogPath "C:\Reports\PrimaryUserCorrection" `
        -WhatIf

    Runs the script in report-only mode and writes transcript and CSV output to the specified folder.

.EXAMPLE
    .\Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1 `
        -SkipAdResolution `
        -CandidateUpnSuffix "icscf.de" `
        -WhatIf

    Runs the script in a cloud-only or test tenant without on-prem Active Directory lookup.
    Candidate UPNs are built from samAccountName + @icscf.de.

.EXAMPLE
    .\Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1 `
        -ManualCandidateDeviceName "DESKTOP-BD80G10" `
        -ManualCandidateUpn "AdminMSN@icscf.de" `
        -SkipAdResolution `
        -CandidateUpnSuffix "icscf.de" `
        -MaxChanges 1 `
        -WhatIf

    Tests the end-to-end Graph and Intune logic with a synthetic candidate row.

.EXAMPLE
    .\Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1 `
        -ManualCandidateDeviceName "DESKTOP-BD80G10" `
        -ManualCandidateUpn "AdminMSN@icscf.de" `
        -SkipAdResolution `
        -CandidateUpnSuffix "icscf.de" `
        -MaxChanges 1 `
        -AllowManualCandidateWrite

    Performs one test change using manual candidate mode.

.NOTES
    AMRunningMode / Defender Antivirus state is not evaluated by this script.
    This script only corrects Intune Primary User assignment based on Defender XDR logon data.

    For unattended scheduled execution, delegated interactive authentication is not ideal.
    Use this version for controlled admin-run batches. For fully unattended scheduled execution,
    consider app-only Graph authentication with certificate-based authentication.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = (Join-Path $env:TEMP "PrimaryUserCorrection"),

    [Parameter(Mandatory = $false)]
    [int]$MinCandidateLogonCount = 3,

    [Parameter(Mandatory = $false)]
    [int]$MinCandidateActiveDays = 2,

    [Parameter(Mandatory = $false)]
    [string]$RequiredConfidence = "High",

    [Parameter(Mandatory = $false)]
    [string]$InstallerPrimaryUserRegex = "(?i)^installer[0-9]{2}@",

    [Parameter(Mandatory = $false)]
    [int]$MaxChanges = 25,

    [Parameter(Mandatory = $false)]
    [switch]$UseDeviceCode,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAdResolution,

    [Parameter(Mandatory = $false)]
    [string]$CandidateUpnSuffix,

    [Parameter(Mandatory = $false)]
    [string]$ManualCandidateDeviceName,

    [Parameter(Mandatory = $false)]
    [string]$ManualCandidateUpn,

    [Parameter(Mandatory = $false)]
    [string]$ManualCandidateSamAccountName,

    [Parameter(Mandatory = $false)]
    [switch]$AllowManualCandidateWrite
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

function Invoke-WithoutWhatIf {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock
    )

    $previousWhatIfPreference = $false

    $existingVariable = Get-Variable `
        -Name WhatIfPreference `
        -Scope Script `
        -ErrorAction SilentlyContinue

    if ($null -ne $existingVariable) {
        $previousWhatIfPreference = [bool]$existingVariable.Value
    }
    elseif (Get-Variable -Name WhatIfPreference -ErrorAction SilentlyContinue) {
        $previousWhatIfPreference = [bool](Get-Variable -Name WhatIfPreference -ValueOnly)
    }

    try {
        Set-Variable `
            -Name WhatIfPreference `
            -Value $false `
            -Scope Script `
            -Force

        & $ScriptBlock
    }
    finally {
        Set-Variable `
            -Name WhatIfPreference `
            -Value $previousWhatIfPreference `
            -Scope Script `
            -Force
    }
}

Invoke-WithoutWhatIf {
    if (-not (Test-Path -Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$resultPath = Join-Path $LogPath "PrimaryUserCorrection-Result-$timestamp.csv"
$transcriptPath = Join-Path $LogPath "PrimaryUserCorrection-$timestamp.log"

Invoke-WithoutWhatIf {
    Start-Transcript -Path $transcriptPath -Force | Out-Null
}

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
let ExcludedCandidateRegex = @"(?i)^(adm-|admin-|svc-|sa-|installer[0-9]{2}$|dwm-|umfd-|system$|localservice$|networkservice$|root$|daemon$|sshd$|nobody$)";
let ValidLogonTypes = dynamic(["Interactive", "CachedInteractive", "RemoteInteractive"]);
let WindowsClientDevices =
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    | where OSPlatform startswith "Windows"
    | where OSPlatform !has "Server"
    | project DeviceId;
let BaseLogons =
    DeviceLogonEvents
    | where Timestamp > ago(Lookback)
    | where ActionType == "LogonSuccess"
    | where LogonType in~ (ValidLogonTypes)
    | where isnotempty(AccountName)
    | join kind=inner WindowsClientDevices on DeviceId
    | extend
        DeviceShortName = tostring(split(DeviceName, ".")[0]),
        AccountNameLower = tolower(AccountName),
        AccountDomainLower = tolower(AccountDomain),
        AccountSidString = tostring(AccountSid)
    | where AccountNameLower !endswith "$"
    | where not(AccountNameLower matches regex ExcludedCandidateRegex)
    | where AccountSidString !startswith "S-1-5-90"
    | where AccountSidString !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
    | where AccountDomainLower !in~ ("window manager", "nt authority");
let RankedCandidates =
    BaseLogons
    | summarize
        CandidateLogonCount = count(),
        CandidateActiveDays = dcount(startofday(Timestamp)),
        CandidateFirstLogon = min(Timestamp),
        CandidateLastLogon = max(Timestamp),
        CandidateLogonTypes = make_set(LogonType, 10)
        by DeviceId, DeviceName, DeviceShortName, CandidateDomain = AccountDomainLower, CandidateSamAccountName = AccountNameLower, CandidateSid = AccountSid
    | where CandidateLogonCount >= __MIN_LOGON_COUNT__ and CandidateActiveDays >= __MIN_ACTIVE_DAYS__
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
TopCandidate
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
    CandidateAccount,
    Confidence,
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

$query = $query.Replace("__MIN_LOGON_COUNT__", [string]$MinCandidateLogonCount)
$query = $query.Replace("__MIN_ACTIVE_DAYS__", [string]$MinCandidateActiveDays)

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

function Resolve-CandidateUpn {
    param(
        [string]$CandidateSid,
        [string]$CandidateSamAccountName
    )

    if ($SkipAdResolution) {
        if ([string]::IsNullOrWhiteSpace($CandidateSamAccountName)) {
            throw "SkipAdResolution is enabled, but CandidateSamAccountName is empty."
        }

        if ($CandidateSamAccountName -match "@") {
            return $CandidateSamAccountName
        }

        if ([string]::IsNullOrWhiteSpace($CandidateUpnSuffix)) {
            throw "SkipAdResolution is enabled, but CandidateUpnSuffix was not provided. Example: -CandidateUpnSuffix 'icscf.de'"
        }

        return ("{0}@{1}" -f $CandidateSamAccountName, $CandidateUpnSuffix)
    }

    return Resolve-CandidateUpnFromAd `
        -CandidateSid $CandidateSid `
        -CandidateSamAccountName $CandidateSamAccountName
}

function Get-GraphUserByUpn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    $encodedUpn = [uri]::EscapeDataString($UserPrincipalName)
    $uri = "https://graph.microsoft.com/v1.0/users/{0}?`$select=id,userPrincipalName,displayName,accountEnabled" -f $encodedUpn

    return Invoke-GraphRequestWithRetry -Method GET -Uri $uri
}

function Get-ManagedDeviceByName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeviceName
    )

    $candidateNames = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($DeviceName)) {
        $candidateNames.Add($DeviceName)

        $shortName = ($DeviceName.Split(".")[0])

        if (-not [string]::IsNullOrWhiteSpace($shortName)) {
            $candidateNames.Add($shortName)
            $candidateNames.Add($shortName.ToUpperInvariant())
            $candidateNames.Add($shortName.ToLowerInvariant())
        }

        $candidateNames.Add($DeviceName.ToUpperInvariant())
        $candidateNames.Add($DeviceName.ToLowerInvariant())
    }

    $uniqueCandidateNames = @(
        $candidateNames |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )

    $allMatches = New-Object System.Collections.Generic.List[object]

    # First attempt: direct exact Graph filter
    foreach ($candidateName in $uniqueCandidateNames) {
        $escapedName = $candidateName.Replace("'", "''")
        $filter = [uri]::EscapeDataString("deviceName eq '$escapedName'")
        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=$filter&`$select=id,deviceName,userPrincipalName,userDisplayName,operatingSystem,lastSyncDateTime,azureADDeviceId"

        try {
            $response = Invoke-GraphRequestWithRetry -Method GET -Uri $uri
            $matches = @(Get-GraphValue -Object $response -Name "value")

            foreach ($match in $matches) {
                if ($null -ne $match) {
                    $allMatches.Add($match)
                }
            }
        }
        catch {
            Write-Warning "Exact Intune device lookup failed for '$candidateName': $($_.Exception.Message)"
        }
    }

    # Second attempt: fallback to local matching from paged managedDevice inventory
    if ($allMatches.Count -eq 0) {
        Write-Info "Exact Intune device lookup did not find '$DeviceName'. Falling back to paged managedDevice inventory lookup."

        $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id,deviceName,userPrincipalName,userDisplayName,operatingSystem,lastSyncDateTime,azureADDeviceId&`$top=999"

        while (-not [string]::IsNullOrWhiteSpace($uri)) {
            $response = Invoke-GraphRequestWithRetry -Method GET -Uri $uri
            $pageDevices = @(Get-GraphValue -Object $response -Name "value")

            foreach ($managedDevice in $pageDevices) {
                if ($null -eq $managedDevice) {
                    continue
                }

                $graphDeviceName = [string](Get-GraphValue -Object $managedDevice -Name "deviceName")

                if ([string]::IsNullOrWhiteSpace($graphDeviceName)) {
                    continue
                }

                $graphShortName = ($graphDeviceName.Split(".")[0])

                $isMatch = $false

                foreach ($candidateName in $uniqueCandidateNames) {
                    if ($candidateName -ieq $graphDeviceName -or $candidateName -ieq $graphShortName) {
                        $isMatch = $true
                        break
                    }
                }

                if ($isMatch) {
                    $allMatches.Add($managedDevice)
                }
            }

            $uri = [string](Get-GraphValue -Object $response -Name "@odata.nextLink")
        }
    }

    # Deduplicate by managedDevice id
    $deduplicatedById = @{}

    foreach ($match in $allMatches) {
        $id = [string](Get-GraphValue -Object $match -Name "id")

        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $deduplicatedById[$id] = $match
        }
    }

    return @($deduplicatedById.Values)
}

function Get-ManagedDevicePrimaryUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManagedDeviceId
    )

    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$ManagedDeviceId')/users?`$select=id,userPrincipalName,displayName"
    $response = Invoke-GraphRequestWithRetry -Method GET -Uri $uri
    $users = @($response.value)

    if ($users.Count -ge 1) {
        return $users[0]
    }

    return $null
}

function Get-GraphValue {
    param(
        [Parameter(Mandatory = $false)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) {
            return $Object[$Name]
        }

        return $null
    }

    $property = $Object.PSObject.Properties[$Name]

    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function Set-ManagedDevicePrimaryUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManagedDeviceId,

        [Parameter(Mandatory = $true)]
        [string]$UserId
    )

    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$ManagedDeviceId')/users/`$ref"

    $body = @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/users/$UserId"
    }

    Write-Info "Setting Primary User with endpoint: $uri"
    Write-Info "Target user object ID: $UserId"

    Invoke-GraphRequestWithRetry `
        -Method POST `
        -Uri $uri `
        -Body $body | Out-Null
}

try {
    if (-not (Get-Module Microsoft.Graph.Authentication)) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    }

    if (-not $SkipAdResolution) {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    else {
        Write-Info "SkipAdResolution is enabled. Active Directory module will not be imported."
    }

    $scopes = @(
        "ThreatHunting.Read.All",
        "DeviceManagementManagedDevices.ReadWrite.All",
        "User.Read.All"
    )

    Write-Info "Connecting to Microsoft Graph with delegated admin login."

    if ($UseDeviceCode) {
        if ([string]::IsNullOrWhiteSpace($TenantId)) {
            Connect-MgGraph -Scopes $scopes -UseDeviceCode | Out-Null
        }
        else {
            Connect-MgGraph -TenantId $TenantId -Scopes $scopes -UseDeviceCode | Out-Null
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($TenantId)) {
            Connect-MgGraph -Scopes $scopes | Out-Null
        }
        else {
            Connect-MgGraph -TenantId $TenantId -Scopes $scopes | Out-Null
        }
    }

    $ctx = Get-MgContext
    Write-Info "Connected as: $($ctx.Account)"
    Write-Info "Tenant: $($ctx.TenantId)"

    if (-not [string]::IsNullOrWhiteSpace($ManualCandidateDeviceName)) {
        if ([string]::IsNullOrWhiteSpace($ManualCandidateUpn)) {
            throw "ManualCandidateDeviceName was provided, but ManualCandidateUpn is missing."
        }

        if (-not $WhatIfPreference -and -not $AllowManualCandidateWrite) {
            throw "Manual candidate mode requires -WhatIf or -AllowManualCandidateWrite. This prevents accidental productive changes from synthetic test data."
        }

        if ([string]::IsNullOrWhiteSpace($ManualCandidateSamAccountName)) {
            $ManualCandidateSamAccountName = ($ManualCandidateUpn -split "@")[0]
        }

        Write-Info "Manual candidate mode enabled. Advanced Hunting query will be skipped."
        Write-Info "Manual device: $ManualCandidateDeviceName"
        Write-Info "Manual candidate UPN: $ManualCandidateUpn"

        $rows = @(
            [PSCustomObject]@{
                DeviceName                = $ManualCandidateDeviceName
                DeviceShortName           = ($ManualCandidateDeviceName.Split(".")[0])
                CandidateAccount          = $ManualCandidateUpn
                Confidence                = $RequiredConfidence
                CandidateSamAccountName   = $ManualCandidateSamAccountName
                CandidateSid              = $null
                CandidateUpn              = $ManualCandidateUpn
                CandidateLogonCount       = $MinCandidateLogonCount
                CandidateActiveDays       = $MinCandidateActiveDays
                CandidateFirstLogon       = $null
                CandidateLastLogon        = $null
                SecondCandidate           = $null
                SecondCandidateLogonCount = $null
            }
        )
    }
    else {
        Write-Info "Running Defender XDR Advanced Hunting query."
        $rows = @(Invoke-PrimaryUserHuntingQuery)

        if ($rows.Count -eq 0) {
            Write-Info "Advanced Hunting query returned no rows."

            Invoke-WithoutWhatIf {
                $results | Export-Csv -Path $resultPath -NoTypeInformation -Encoding UTF8
            }

            return
        }

        Write-Info "Advanced Hunting returned $($rows.Count) candidate rows."
    }

    Write-Info "Maximum changes in this run: $MaxChanges"

    foreach ($row in $rows) {
        $deviceName = ""
        $deviceShortName = ""
        $candidateSam = ""
        $candidateSid = ""
        $candidateUpn = ""
        $currentPrimaryUserUpn = ""
        $device = $null
        $deviceId = ""
        $intuneDeviceName = ""
        $deviceOperatingSystem = ""

        try {
            $deviceName = [string]$row.DeviceName
            $deviceShortName = [string]$row.DeviceShortName
            $candidateSam = [string]$row.CandidateSamAccountName
            $candidateSid = [string]$row.CandidateSid

            if ([string]::IsNullOrWhiteSpace($deviceShortName) -and -not [string]::IsNullOrWhiteSpace($deviceName)) {
                $deviceShortName = [string]($deviceName.Split(".")[0])
            }

            if ([string]::IsNullOrWhiteSpace($deviceShortName)) {
                Add-Result `
                    -DeviceName $deviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Skipped" `
                    -Reason "Missing DeviceShortName."

                continue
            }

                        # Resolve Intune device and current Primary User early.
            # This must happen before confidence / threshold checks so skipped rows still show CurrentPrimaryUser.
            $devices = @(Get-ManagedDeviceByName -DeviceName $deviceName)

            if ($devices.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($deviceShortName)) {
                $devices = @(Get-ManagedDeviceByName -DeviceName $deviceShortName)
            }

            Write-Info "Intune lookup for Defender device '$deviceName' / short name '$deviceShortName' returned $($devices.Count) device(s)."

            if ($devices.Count -eq 0) {
                Add-Result `
                    -DeviceName $deviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Skipped" `
                    -Reason "Intune device not found."

                continue
            }

            if ($devices.Count -gt 1) {
                Add-Result `
                    -DeviceName $deviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Skipped" `
                    -Reason "Multiple Intune devices found. Manual review required."

                continue
            }

            $device = $devices[0]

            $deviceId = [string](Get-GraphValue -Object $device -Name "id")
            $intuneDeviceName = [string](Get-GraphValue -Object $device -Name "deviceName")
            $deviceOperatingSystem = [string](Get-GraphValue -Object $device -Name "operatingSystem")
            $enrolledByUserUpn = [string](Get-GraphValue -Object $device -Name "userPrincipalName")

            if ($deviceOperatingSystem -ne "Windows") {
                Add-Result `
                    -DeviceName $intuneDeviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Skipped" `
                    -Reason "Device is not Windows."

                continue
            }

            $currentPrimary = Get-ManagedDevicePrimaryUser -ManagedDeviceId $deviceId
            $currentPrimaryUserUpn = [string](Get-GraphValue -Object $currentPrimary -Name "userPrincipalName")

            if ([string]::IsNullOrWhiteSpace($currentPrimaryUserUpn)) {
                $currentPrimaryUserUpn = $enrolledByUserUpn
            }

            Write-Info "Current Intune Primary User for '$intuneDeviceName': $currentPrimaryUserUpn"

            if ([string]$row.Confidence -ne $RequiredConfidence) {
                Add-Result `
                    -DeviceName $intuneDeviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Skipped" `
                    -Reason "Confidence '$($row.Confidence)' does not match required '$RequiredConfidence'."

                continue
            }

            $candidateLogonCount = 0
            $candidateActiveDays = 0

            [int]::TryParse([string]$row.CandidateLogonCount, [ref]$candidateLogonCount) | Out-Null
            [int]::TryParse([string]$row.CandidateActiveDays, [ref]$candidateActiveDays) | Out-Null

            if ($candidateLogonCount -lt $MinCandidateLogonCount) {
                Add-Result `
                    -DeviceName $deviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Skipped" `
                    -Reason "CandidateLogonCount below threshold."

                continue
            }

            if ($candidateActiveDays -lt $MinCandidateActiveDays) {
                Add-Result `
                    -DeviceName $deviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Skipped" `
                    -Reason "CandidateActiveDays below threshold."

                continue
            }

            if (
                $row.PSObject.Properties.Name -contains "CandidateUpn" -and
                -not [string]::IsNullOrWhiteSpace([string]$row.CandidateUpn)
            ) {
                $candidateUpn = [string]$row.CandidateUpn
            }
            else {
                $candidateUpn = Resolve-CandidateUpn `
                    -CandidateSid $candidateSid `
                    -CandidateSamAccountName $candidateSam
            }

            $graphUser = Get-GraphUserByUpn -UserPrincipalName $candidateUpn

            if ($null -eq $graphUser -or [string]::IsNullOrWhiteSpace($graphUser.id)) {
                Add-Result `
                    -DeviceName $deviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Skipped" `
                    -Reason "Candidate user not found in Graph."

                continue
            }

            if ($graphUser.accountEnabled -ne $true) {
                Add-Result `
                    -DeviceName $deviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Skipped" `
                    -Reason "Candidate user is disabled in Entra ID."

                continue
            }

            if ([string]::IsNullOrWhiteSpace($currentPrimaryUserUpn)) {
                Add-Result `
                    -DeviceName $intuneDeviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Skipped" `
                    -Reason "Current Primary User is empty. Manual review recommended."

                continue
            }

            if ($currentPrimaryUserUpn -notmatch $InstallerPrimaryUserRegex) {
                Add-Result `
                    -DeviceName $intuneDeviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Skipped" `
                    -Reason "Current Primary User does not match installer/deployment regex."

                continue
            }

            if ($currentPrimaryUserUpn -ieq $candidateUpn) {
                Add-Result `
                    -DeviceName $intuneDeviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Skipped" `
                    -Reason "Candidate is already Primary User."

                continue
            }

            if ($changeCount -ge $MaxChanges) {
                Add-Result `
                    -DeviceName $intuneDeviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Skipped" `
                    -Reason "MaxChanges limit reached."

                continue
            }

            $target = "{0}: {1} -> {2}" -f $intuneDeviceName, $currentPrimaryUserUpn, $candidateUpn

            if ($PSCmdlet.ShouldProcess($target, "Set Intune Primary User")) {
                Set-ManagedDevicePrimaryUser -ManagedDeviceId $deviceId -UserId $graphUser.id
                $changeCount++

                Add-Result `
                    -DeviceName $intuneDeviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "Changed" `
                    -Reason "Primary User changed."

                Write-Info "Changed Primary User: $target"
            }
            else {
                Add-Result `
                    -DeviceName $intuneDeviceName `
                    -DeviceShortName $deviceShortName `
                    -CurrentPrimaryUser $currentPrimaryUserUpn `
                    -CandidateSamAccountName $candidateSam `
                    -CandidateSid $candidateSid `
                    -CandidateUpn $candidateUpn `
                    -Action "WouldChange" `
                    -Reason "WhatIf or ShouldProcess prevented change."
            }
        }
        catch {
            Add-Result `
                -DeviceName $deviceName `
                -DeviceShortName $deviceShortName `
                -CurrentPrimaryUser $currentPrimaryUserUpn `
                -CandidateSamAccountName $candidateSam `
                -CandidateSid $candidateSid `
                -CandidateUpn $candidateUpn `
                -Action "Error" `
                -Reason $_.Exception.Message

            Write-Warning "Error processing device '$deviceShortName': $($_.Exception.Message)"
        }
    }

    Invoke-WithoutWhatIf {
        $results | Export-Csv -Path $resultPath -NoTypeInformation -Encoding UTF8
    }

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

    try {
        Invoke-WithoutWhatIf {
            Stop-Transcript | Out-Null
        }
    }
    catch {
        # ignore transcript stop errors
    }
}
