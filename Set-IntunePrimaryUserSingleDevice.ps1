<#
.SYNOPSIS
    Sets the Intune Primary User for a single Intune managed Windows device.

.DESCRIPTION
    This script connects to Microsoft Graph with delegated permissions and sets
    the Primary User relationship of one Intune managed device.

    It is intended as a controlled test before using a larger automation script.
    It does not use Advanced Hunting and does not require on-prem Active Directory.

.PARAMETER DeviceName
    The Intune managed device name, for example DESKTOP-BD80G10.

.PARAMETER UserPrincipalName
    The target user's UPN, for example installer99@icscf.de.

.PARAMETER TenantId
    The tenant ID or verified domain name, for example icscf.de.

.EXAMPLE
    .\Set-IntunePrimaryUserSingleDevice.ps1 `
        -TenantId "ade56966-ae5b-4e8d-95c6-b84548490b80" `
        -DeviceName "DESKTOP-BD80G10" `
        -UserPrincipalName "installer99@icscf.de" `
        -WhatIf

.EXAMPLE
    .\Set-IntunePrimaryUserSingleDevice.ps1 `
        -TenantId "ade56966-ae5b-4e8d-95c6-b84548490b80" `
        -DeviceName "DESKTOP-BD80G10" `
        -UserPrincipalName "installer99@icscf.de"
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId="ade56966-ae5b-4e8d-95c6-b84548490b80",

    [Parameter(Mandatory = $false)]
    [string]$DeviceName="DESKTOP-BD80G10",

    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

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
            Write-Host "Graph request failed with HTTP $statusCode. Retry $attempt/$MaxRetries in $sleepSeconds seconds."
            Start-Sleep -Seconds $sleepSeconds
        }
    }
}

function Get-GraphUserByUpn {
    param([Parameter(Mandatory = $true)][string]$Upn)
    $Upn = $UserPrincipalName.Trim()
    $encodedUpn = [uri]::EscapeDataString($Upn)
    $uri = "https://graph.microsoft.com/v1.0/users/${encodedUpn}?`$select=id,userPrincipalName,displayName,accountEnabled"
    return Invoke-GraphRequestWithRetry -Method GET -Uri $uri
}

function Get-ManagedDeviceByName {
    param([Parameter(Mandatory = $true)][string]$Name)

    $escapedName = $Name.Replace("'", "''")
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
        [Parameter(Mandatory = $true)]
        [string]$ManagedDeviceId,

        [Parameter(Mandatory = $true)]
        [string]$UserId
    )

    # Primary user assignment is commonly done through the Intune beta endpoint.
    # Try slash-style first, then OData key-style as fallback.
    $uris = @(
        "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$ManagedDeviceId/users/`$ref",
        "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$ManagedDeviceId')/users/`$ref"
    )

    $body = @{
        "@odata.id" = "https://graph.microsoft.com/beta/users/$UserId"
    }

    $lastError = $null

    foreach ($uri in $uris) {
        try {
            Write-Host "Trying primary user update endpoint:"
            Write-Host $uri

            Invoke-GraphRequestWithRetry `
                -Method POST `
                -Uri $uri `
                -Body $body | Out-Null

            return
        }
        catch {
            $lastError = $_
            Write-Warning "Primary user update failed with this endpoint: $($_.Exception.Message)"
        }
    }

    throw $lastError
}

try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Continue | Out-Null

    $scopes = @(
        "DeviceManagementManagedDevices.ReadWrite.All",
        "User.Read.All"
    )

    Write-Host "Connecting to Microsoft Graph tenant '$TenantId'..."
    Connect-MgGraph -TenantId $TenantId -Scopes $scopes | Out-Null

    $ctx = Get-MgContext
    Write-Host "Connected as: $($ctx.Account)"
    Write-Host "Tenant:       $($ctx.TenantId)"
    Write-Host ""

    Write-Host "Resolving user '$UserPrincipalName'..."
    $user = Get-GraphUserByUpn -Upn $UserPrincipalName

    if ($null -eq $user -or [string]::IsNullOrWhiteSpace($user.id)) {
        throw "User not found: $UserPrincipalName"
    }

    if ($user.accountEnabled -ne $true) {
        throw "User is disabled: $UserPrincipalName"
    }

    Write-Host "User found: $($user.displayName) <$($user.userPrincipalName)>"
    Write-Host ""

    Write-Host "Resolving Intune managed device '$DeviceName'..."
    $devices = @(Get-ManagedDeviceByName -Name $DeviceName)

    if ($devices.Count -eq 0) {
        throw "No Intune managed device found with deviceName '$DeviceName'."
    }

    if ($devices.Count -gt 1) {
        $devices | Select-Object id, deviceName, operatingSystem, lastSyncDateTime | Format-Table -AutoSize
        throw "Multiple Intune managed devices found with deviceName '$DeviceName'. Aborting."
    }

    $device = $devices[0]

    Write-Host "Device found:"
    $device | Select-Object id, deviceName, operatingSystem, userPrincipalName, userDisplayName, lastSyncDateTime | Format-List

    $currentPrimary = Get-ManagedDevicePrimaryUser -ManagedDeviceId $device.id

    if ($null -ne $currentPrimary) {
        Write-Host "Current Primary User: $($currentPrimary.userPrincipalName)"
    }
    else {
        Write-Host "Current Primary User: <none returned by Graph>"
    }

    Write-Host ""

    $target = "$($device.deviceName): Primary User -> $($user.userPrincipalName)"

    if ($PSCmdlet.ShouldProcess($target, "Set Intune Primary User")) {
        Set-ManagedDevicePrimaryUser -ManagedDeviceId $device.id -UserId $user.id
        Write-Host "Primary User update request sent successfully." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Waiting 10 seconds before verification..."
    Start-Sleep -Seconds 10

    $newPrimary = Get-ManagedDevicePrimaryUser -ManagedDeviceId $device.id

    if ($null -ne $newPrimary) {
        Write-Host "New Primary User: $($newPrimary.userPrincipalName)" -ForegroundColor Cyan
    }
    else {
        Write-Host "New Primary User could not be read immediately. Check Intune portal after a few minutes." -ForegroundColor Yellow
    }
}
finally {
    try {
        Disconnect-MgGraph | Out-Null
    }
    catch {
        # ignore disconnect errors
    }
}