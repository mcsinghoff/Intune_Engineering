<#
.SYNOPSIS
    Corrects Intune Primary Users from Defender XDR logon telemetry without an interactive sign-in.

.DESCRIPTION
    Runs a Defender XDR Advanced Hunting query, ranks successful local interactive logons per
    Windows client, resolves the winning account in Microsoft Entra ID, and changes the Intune
    Primary User only when the current assignment matches an installer-account pattern.

    Authentication is app-only with a certificate. The default mode is report-only; -Apply is
    required before any Intune relationship is changed. RemoteInteractive (RDP) logons are ignored
    unless -IncludeRemoteInteractive is explicitly supplied.

.PARAMETER TenantId
    Microsoft Entra tenant ID.

.PARAMETER ClientId
    Application (client) ID of the app registration.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate, including its private key, installed for the service account that
    runs this script. LocalMachine\My is recommended for a scheduled server task.

.PARAMETER CandidateUpnSuffix
    Optional UPN suffix used only when Defender supplies neither a UPN-shaped account name nor a SID
    that can be mapped to a synchronized Entra user.

.PARAMETER Apply
    Enables changes. Without this switch, the script only reports WouldChange results.

.REQUIREMENTS
    Microsoft.Graph.Authentication PowerShell module.

    Microsoft Graph application permissions with admin consent:
    - ThreatHunting.Read.All
    - DeviceManagementManagedDevices.ReadWrite.All
    - User.Read.All

.EXAMPLE
    .\Set-NewPrimaryUserForDevices-AppReg.ps1 `
        -TenantId "00000000-0000-0000-0000-000000000000" `
        -ClientId "11111111-1111-1111-1111-111111111111" `
        -CertificateThumbprint "ABCDEF1234567890" `
        -CandidateUpnSuffix "contoso.com"

    Runs a safe report-only pass.

.EXAMPLE
    .\Set-NewPrimaryUserForDevices-AppReg.ps1 `
        -TenantId "00000000-0000-0000-0000-000000000000" `
        -ClientId "11111111-1111-1111-1111-111111111111" `
        -CertificateThumbprint "ABCDEF1234567890" `
        -CandidateUpnSuffix "contoso.com" `
        -Apply

    Applies at most 25 high-confidence changes.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
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

    [string]$LogPath = (Join-Path $env:ProgramData "IntunePrimaryUserCorrection\Logs"),

    [ValidateRange(7, 90)]
    [int]$LookbackDays = 30,

    [ValidateRange(1, 1000)]
    [int]$MinCandidateLogonCount = 5,

    [ValidateRange(1, 90)]
    [int]$MinCandidateActiveDays = 3,

    [ValidateRange(1.1, 10.0)]
    [double]$MinDominanceRatio = 2.0,

    [ValidateNotNullOrEmpty()]
    [string]$InstallerPrimaryUserRegex = "(?i)^(installer|deployment|intune-installer)[0-9_-]*@",

    [string]$CandidateUpnSuffix,

    [ValidateRange(1, 500)]
    [int]$MaxChanges = 25,

    [switch]$IncludeRemoteInteractive,

    [switch]$Apply
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$resultPath = Join-Path $LogPath "PrimaryUserCorrection-Result-$timestamp.csv"
$transcriptPath = Join-Path $LogPath "PrimaryUserCorrection-$timestamp.log"
$results = [System.Collections.Generic.List[object]]::new()
$changeCount = 0
$transcriptStarted = $false
$runSucceeded = $false

function Write-Info {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
}

function Get-GraphValue {
    param([object]$Object, [Parameter(Mandatory = $true)][string]$Name)

    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Add-Result {
    param(
        [string]$DeviceName,
        [string]$EntraDeviceId,
        [string]$CurrentPrimaryUser,
        [string]$CandidateUser,
        [string]$Action,
        [string]$Reason,
        [int]$LogonCount = 0,
        [int]$ActiveDays = 0
    )

    $script:results.Add([PSCustomObject]@{
        Timestamp          = (Get-Date).ToString("s")
        DeviceName         = $DeviceName
        EntraDeviceId      = $EntraDeviceId
        CurrentPrimaryUser = $CurrentPrimaryUser
        CandidateUser      = $CandidateUser
        CandidateLogons    = $LogonCount
        CandidateActiveDays = $ActiveDays
        Action             = $Action
        Reason             = $Reason
    })
}

function Invoke-GraphRequestWithRetry {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("GET", "POST")][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [object]$Body,
        [int]$MaxRetries = 5
    )

    $attempt = 0
    while ($true) {
        try {
            if ($null -ne $Body) {
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 20) -ContentType "application/json"
            }
            return Invoke-MgGraphRequest -Method $Method -Uri $Uri
        }
        catch {
            $attempt++
            $statusCode = $null
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { $statusCode = $null }

            if ($attempt -ge $MaxRetries -or ($statusCode -ne 429 -and ($null -eq $statusCode -or $statusCode -lt 500))) {
                throw
            }

            $retryAfter = 0
            try { $retryAfter = [int]$_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds } catch { $retryAfter = 0 }
            $delay = if ($retryAfter -gt 0) { $retryAfter } else { [Math]::Min(60, [Math]::Pow(2, $attempt)) }
            Write-Info "Graph request returned HTTP $statusCode. Retry $attempt/$MaxRetries in $delay seconds."
            Start-Sleep -Seconds $delay
        }
    }
}

function Invoke-PrimaryUserHuntingQuery {
    $validLogonTypes = @("Interactive", "CachedInteractive")
    if ($IncludeRemoteInteractive) { $validLogonTypes += "RemoteInteractive" }
    $validLogonTypesJson = ConvertTo-Json -InputObject @($validLogonTypes) -Compress

    $query = @'
let Lookback = __LOOKBACK_DAYS__d;
let ValidLogonTypes = dynamic(__VALID_LOGON_TYPES__);
let ExcludedAccountRegex = @"(?i)^(adm-|admin-|svc-|sa-|installer[0-9]+$|deployment|intune-installer|dwm-|umfd-|system$|localservice$|networkservice$|defaultaccount$|wdagutilityaccount$)";
let WindowsClients =
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    | where OSPlatform startswith "Windows" and OSPlatform !has "Server"
    | project DeviceId, AadDeviceId;
let RankedCandidates =
    DeviceLogonEvents
    | where Timestamp > ago(Lookback)
    | where ActionType == "LogonSuccess"
    | where LogonType in~ (ValidLogonTypes)
    | where isnotempty(AccountName)
    | join kind=inner WindowsClients on DeviceId
    | extend
        DeviceShortName = tostring(split(DeviceName, ".")[0]),
        AccountNameLower = tolower(AccountName),
        AccountDomainLower = tolower(AccountDomain),
        AccountSidString = tostring(AccountSid)
    | where AccountNameLower !endswith "$"
    | where not(AccountNameLower matches regex ExcludedAccountRegex)
    | where AccountSidString !startswith "S-1-5-90"
    | where AccountSidString !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
    | where AccountDomainLower !in~ ("window manager", "nt authority")
    | summarize
        CandidateLogonCount = count(),
        CandidateActiveDays = dcount(startofday(Timestamp)),
        CandidateFirstLogon = min(Timestamp),
        CandidateLastLogon = max(Timestamp)
        by DeviceId, AadDeviceId, DeviceName, DeviceShortName,
           CandidateDomain = AccountDomainLower,
           CandidateAccountName = AccountNameLower,
           CandidateSid = AccountSidString
    | where CandidateLogonCount >= __MIN_LOGONS__ and CandidateActiveDays >= __MIN_ACTIVE_DAYS__
    | sort by DeviceId asc, CandidateLogonCount desc, CandidateActiveDays desc, CandidateLastLogon desc
    | serialize
    | extend CandidateRank = row_number(1, prev(DeviceId) != DeviceId);
let Winner = RankedCandidates | where CandidateRank == 1;
let RunnerUp =
    RankedCandidates
    | where CandidateRank == 2
    | project DeviceId, RunnerUpLogonCount = CandidateLogonCount;
Winner
| join kind=leftouter RunnerUp on DeviceId
| extend DominanceRatio = iff(isnull(RunnerUpLogonCount) or RunnerUpLogonCount == 0, real(null), todouble(CandidateLogonCount) / todouble(RunnerUpLogonCount))
| where isnull(RunnerUpLogonCount) or DominanceRatio >= __MIN_DOMINANCE_RATIO__
| project DeviceName, DeviceShortName, AadDeviceId, CandidateAccountName, CandidateSid,
          CandidateLogonCount, CandidateActiveDays, CandidateFirstLogon, CandidateLastLogon,
          RunnerUpLogonCount, DominanceRatio
| order by DeviceShortName asc
'@

    $query = $query.Replace("__LOOKBACK_DAYS__", [string]$LookbackDays)
    $query = $query.Replace("__VALID_LOGON_TYPES__", $validLogonTypesJson)
    $query = $query.Replace("__MIN_LOGONS__", [string]$MinCandidateLogonCount)
    $query = $query.Replace("__MIN_ACTIVE_DAYS__", [string]$MinCandidateActiveDays)
    $query = $query.Replace("__MIN_DOMINANCE_RATIO__", $MinDominanceRatio.ToString([Globalization.CultureInfo]::InvariantCulture))

    $response = Invoke-GraphRequestWithRetry -Method POST -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" -Body @{ Query = $query }
    return @(Get-GraphValue -Object $response -Name "results")
}

function Get-CandidateGraphUser {
    param(
        [string]$CandidateSid,
        [Parameter(Mandatory = $true)][string]$CandidateAccountName
    )

    if ($CandidateAccountName -match "@") {
        $encodedUpn = [uri]::EscapeDataString($CandidateAccountName)
        return Invoke-GraphRequestWithRetry -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$encodedUpn?`$select=id,userPrincipalName,accountEnabled"
    }

    if (-not [string]::IsNullOrWhiteSpace($CandidateSid)) {
        $escapedSid = $CandidateSid.Replace("'", "''")
        $filter = [uri]::EscapeDataString("onPremisesSecurityIdentifier eq '$escapedSid'")
        $response = Invoke-GraphRequestWithRetry -Method GET -Uri "https://graph.microsoft.com/v1.0/users?`$filter=$filter&`$select=id,userPrincipalName,accountEnabled,onPremisesSecurityIdentifier"
        $users = @(Get-GraphValue -Object $response -Name "value")
        if ($users.Count -eq 1) { return $users[0] }
        if ($users.Count -gt 1) { throw "SID '$CandidateSid' resolved to multiple Entra users." }
    }

    if ([string]::IsNullOrWhiteSpace($CandidateUpnSuffix)) {
        throw "Account '$CandidateAccountName' could not be resolved by SID and CandidateUpnSuffix is empty."
    }

    $fallbackUpn = "{0}@{1}" -f $CandidateAccountName, $CandidateUpnSuffix.TrimStart("@")
    $encodedFallbackUpn = [uri]::EscapeDataString($fallbackUpn)
    return Invoke-GraphRequestWithRetry -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$encodedFallbackUpn?`$select=id,userPrincipalName,accountEnabled"
}

function Get-IntuneManagedDevice {
    param([string]$AadDeviceId, [Parameter(Mandatory = $true)][string]$DeviceName)

    if (-not [string]::IsNullOrWhiteSpace($AadDeviceId)) {
        $filter = [uri]::EscapeDataString("azureADDeviceId eq '$AadDeviceId'")
        $response = Invoke-GraphRequestWithRetry -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=$filter&`$select=id,deviceName,azureADDeviceId,operatingSystem,userPrincipalName,lastSyncDateTime"
        $matches = @(Get-GraphValue -Object $response -Name "value")
        if ($matches.Count -gt 0) { return $matches }
    }

    $shortName = $DeviceName.Split(".")[0]
    $escapedName = $shortName.Replace("'", "''")
    $nameFilter = [uri]::EscapeDataString("deviceName eq '$escapedName'")
    $nameResponse = Invoke-GraphRequestWithRetry -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=$nameFilter&`$select=id,deviceName,azureADDeviceId,operatingSystem,userPrincipalName,lastSyncDateTime"
    return @(Get-GraphValue -Object $nameResponse -Name "value")
}

function Get-IntunePrimaryUser {
    param([Parameter(Mandatory = $true)][string]$ManagedDeviceId)
    $response = Invoke-GraphRequestWithRetry -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$ManagedDeviceId')/users?`$select=id,userPrincipalName"
    return @(Get-GraphValue -Object $response -Name "value")
}

function Set-IntunePrimaryUser {
    param(
        [Parameter(Mandatory = $true)][string]$ManagedDeviceId,
        [Parameter(Mandatory = $true)][string]$UserId
    )
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices('$ManagedDeviceId')/users/`$ref"
    Invoke-GraphRequestWithRetry -Method POST -Uri $uri -Body @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$UserId" } | Out-Null
}

function Get-ClientCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint
    )

    $normalizedThumbprint = ($Thumbprint -replace "\\s", "").ToUpperInvariant()
    $certificatePaths = @(
        "Cert:\\LocalMachine\\My\\$normalizedThumbprint",
        "Cert:\\CurrentUser\\My\\$normalizedThumbprint"
    )
    $foundCertificates = [System.Collections.Generic.List[string]]::new()
    $accessErrors = [System.Collections.Generic.List[string]]::new()
    $windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    foreach ($certificatePath in $certificatePaths) {
        if (-not (Test-Path -LiteralPath $certificatePath)) {
            continue
        }

        $certificate = Get-Item -LiteralPath $certificatePath
        $foundCertificates.Add($certificatePath)

        if (-not $certificate.HasPrivateKey) {
            $accessErrors.Add("${certificatePath}: certificate has no private key. Importing a .cer file is not sufficient.")
            continue
        }

        $rsa = $null
        try {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
            if ($null -eq $rsa) {
                throw "Certificate does not expose an RSA private key."
            }

            $probe = [System.Text.Encoding]::UTF8.GetBytes("Intune-PrimaryUser-Automation private-key access test")
            $null = $rsa.SignData(
                $probe,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )

            Write-Info "Using certificate '$($certificate.Subject)' from '$certificatePath' as Windows identity '$windowsIdentity'."
            return $certificate
        }
        catch {
            $accessErrors.Add("${certificatePath}: private key cannot be opened by '$windowsIdentity': $($_.Exception.Message)")
        }
        finally {
            if ($null -ne $rsa) {
                $rsa.Dispose()
            }
        }
    }

    if ($foundCertificates.Count -eq 0) {
        throw "Certificate '$normalizedThumbprint' was not found in LocalMachine\\My or CurrentUser\\My. The .cer file on disk is not used by this script."
    }

    throw (
        "Certificate '$normalizedThumbprint' was found, but no usable private key is available. " +
        "Grant the scheduled-task identity Read access through certlm.msc > Personal > Certificates > Manage Private Keys. " +
        "Details: " + ($accessErrors -join " | ")
    )
}

try {
    Start-Transcript -Path $transcriptPath -Force | Out-Null
    $transcriptStarted = $true

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $clientCertificate = Get-ClientCertificate -Thumbprint $CertificateThumbprint
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -Certificate $clientCertificate -ContextScope Process -NoWelcome | Out-Null

    $context = Get-MgContext
    if ($context.AuthType -ne "AppOnly") { throw "Expected app-only Graph authentication, but AuthType is '$($context.AuthType)'." }
    Write-Info "Connected app-only to tenant $($context.TenantId). Mode: $(if ($Apply) { 'APPLY' } else { 'REPORT-ONLY' })."

    $rows = @(Invoke-PrimaryUserHuntingQuery)
    Write-Info "Advanced Hunting returned $($rows.Count) high-confidence device candidate(s)."

    foreach ($row in $rows) {
        $deviceName = [string](Get-GraphValue -Object $row -Name "DeviceName")
        $aadDeviceId = [string](Get-GraphValue -Object $row -Name "AadDeviceId")
        $candidateAccountName = [string](Get-GraphValue -Object $row -Name "CandidateAccountName")
        $candidateSid = [string](Get-GraphValue -Object $row -Name "CandidateSid")
        $logonCount = [int](Get-GraphValue -Object $row -Name "CandidateLogonCount")
        $activeDays = [int](Get-GraphValue -Object $row -Name "CandidateActiveDays")
        $candidateUpn = ""
        $currentPrimaryUpn = ""

        try {
            $candidateUser = Get-CandidateGraphUser -CandidateSid $candidateSid -CandidateAccountName $candidateAccountName
            $candidateUpn = [string](Get-GraphValue -Object $candidateUser -Name "userPrincipalName")
            $candidateUserId = [string](Get-GraphValue -Object $candidateUser -Name "id")
            $candidateEnabled = Get-GraphValue -Object $candidateUser -Name "accountEnabled"
            if ([string]::IsNullOrWhiteSpace($candidateUserId) -or [string]::IsNullOrWhiteSpace($candidateUpn)) { throw "Candidate did not resolve to a complete Entra user." }
            if ($candidateEnabled -ne $true) { throw "Candidate '$candidateUpn' is disabled." }

            $devices = @(Get-IntuneManagedDevice -AadDeviceId $aadDeviceId -DeviceName $deviceName)
            if ($devices.Count -eq 0) { throw "No Intune managed device matched Defender device '$deviceName' / Entra ID '$aadDeviceId'." }
            if ($devices.Count -gt 1) { throw "Multiple Intune managed devices matched; manual review is required." }

            $device = $devices[0]
            $managedDeviceId = [string](Get-GraphValue -Object $device -Name "id")
            $intuneDeviceName = [string](Get-GraphValue -Object $device -Name "deviceName")
            if ([string](Get-GraphValue -Object $device -Name "operatingSystem") -ne "Windows") { throw "Matched Intune device is not Windows." }

            $primaryUsers = @(Get-IntunePrimaryUser -ManagedDeviceId $managedDeviceId)
            if ($primaryUsers.Count -gt 1) { throw "Intune returned multiple primary-user relationships; manual review is required." }
            if ($primaryUsers.Count -eq 1) { $currentPrimaryUpn = [string](Get-GraphValue -Object $primaryUsers[0] -Name "userPrincipalName") }
            if ([string]::IsNullOrWhiteSpace($currentPrimaryUpn)) { $currentPrimaryUpn = [string](Get-GraphValue -Object $device -Name "userPrincipalName") }
            if ([string]::IsNullOrWhiteSpace($currentPrimaryUpn)) { throw "Current Primary User is empty; refusing automatic assignment." }

            if ($currentPrimaryUpn -notmatch $InstallerPrimaryUserRegex) {
                Add-Result -DeviceName $intuneDeviceName -EntraDeviceId $aadDeviceId -CurrentPrimaryUser $currentPrimaryUpn -CandidateUser $candidateUpn -Action "Skipped" -Reason "Current Primary User is not an installer account." -LogonCount $logonCount -ActiveDays $activeDays
                continue
            }
            if ($currentPrimaryUpn -ieq $candidateUpn) {
                Add-Result -DeviceName $intuneDeviceName -EntraDeviceId $aadDeviceId -CurrentPrimaryUser $currentPrimaryUpn -CandidateUser $candidateUpn -Action "Skipped" -Reason "Candidate is already Primary User." -LogonCount $logonCount -ActiveDays $activeDays
                continue
            }
            if (-not $Apply) {
                Add-Result -DeviceName $intuneDeviceName -EntraDeviceId $aadDeviceId -CurrentPrimaryUser $currentPrimaryUpn -CandidateUser $candidateUpn -Action "WouldChange" -Reason "Report-only mode; use -Apply to write." -LogonCount $logonCount -ActiveDays $activeDays
                continue
            }
            if ($changeCount -ge $MaxChanges) {
                Add-Result -DeviceName $intuneDeviceName -EntraDeviceId $aadDeviceId -CurrentPrimaryUser $currentPrimaryUpn -CandidateUser $candidateUpn -Action "Skipped" -Reason "MaxChanges limit reached." -LogonCount $logonCount -ActiveDays $activeDays
                continue
            }

            $target = "${intuneDeviceName}: $currentPrimaryUpn -> $candidateUpn"
            if ($PSCmdlet.ShouldProcess($target, "Set Intune Primary User")) {
                Set-IntunePrimaryUser -ManagedDeviceId $managedDeviceId -UserId $candidateUserId
                $verifiedUsers = @(Get-IntunePrimaryUser -ManagedDeviceId $managedDeviceId)
                $verifiedUpn = if ($verifiedUsers.Count -eq 1) { [string](Get-GraphValue -Object $verifiedUsers[0] -Name "userPrincipalName") } else { "" }
                if ($verifiedUpn -ine $candidateUpn) { throw "Write completed, but verification returned '$verifiedUpn' instead of '$candidateUpn'." }

                $changeCount++
                Add-Result -DeviceName $intuneDeviceName -EntraDeviceId $aadDeviceId -CurrentPrimaryUser $currentPrimaryUpn -CandidateUser $candidateUpn -Action "Changed" -Reason "Primary User changed and verified." -LogonCount $logonCount -ActiveDays $activeDays
                Write-Info "Changed and verified: $target"
            }
        }
        catch {
            Add-Result -DeviceName $deviceName -EntraDeviceId $aadDeviceId -CurrentPrimaryUser $currentPrimaryUpn -CandidateUser $(if ($candidateUpn) { $candidateUpn } else { $candidateAccountName }) -Action "Error" -Reason $_.Exception.Message -LogonCount $logonCount -ActiveDays $activeDays
            Write-Warning "Failed '$deviceName': $($_.Exception.Message)"
        }
    }

    $runSucceeded = $true
}
finally {
    $results | Export-Csv -Path $resultPath -NoTypeInformation -Encoding UTF8
    try { Disconnect-MgGraph | Out-Null } catch { }
    if ($transcriptStarted) { try { Stop-Transcript | Out-Null } catch { } }
    if ($runSucceeded) {
        Write-Info "Completed successfully. Changes: $changeCount. Result: $resultPath"
    }
    else {
        Write-Warning "Run failed before completion. Changes: $changeCount. Diagnostic result: $resultPath"
    }
}
