$cert = New-SelfSignedCertificate `
    -Subject "CN=Intune-PrimaryUser-Automation" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -KeySpec Signature `
    -KeyExportPolicy NonExportable `
    -NotAfter (Get-Date).AddYears(2)

New-Item -Path C:\Automation -ItemType Directory -Force

Export-Certificate `
    -Cert $cert `
    -FilePath C:\Automation\Intune-PrimaryUser-Automation.cer

$cert.Thumbprint



###

function Get-SafeProperty {
    param(
        $InputObject,
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject[$Name]
    }

    $property = $InputObject.PSObject.Properties[$Name]

    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

$configurations = @(
    (Invoke-MgGraphRequest `
        -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations'
    ).value
)

$configurations |
    ForEach-Object {
        $windowsRestriction = Get-SafeProperty `
            -InputObject $_ `
            -Name 'windowsRestriction'

        $singlePlatformRestriction = Get-SafeProperty `
            -InputObject $_ `
            -Name 'platformRestriction'

        $platformType = Get-SafeProperty `
            -InputObject $_ `
            -Name 'platformType'

        $effectiveRestriction = if ($null -ne $windowsRestriction) {
            $windowsRestriction
        }
        elseif ($platformType -eq 'windows') {
            $singlePlatformRestriction
        }
        else {
            $null
        }

        [pscustomobject]@{
            Id = Get-SafeProperty $_ 'id'

            DisplayName = Get-SafeProperty $_ 'displayName'

            ODataType = Get-SafeProperty $_ '@odata.type'

            EnrollmentConfigurationType = Get-SafeProperty `
                $_ `
                'deviceEnrollmentConfigurationType'

            PlatformType = $platformType

            Priority = Get-SafeProperty $_ 'priority'

            DeviceLimit = Get-SafeProperty $_ 'limit'

            WindowsPlatformBlocked = Get-SafeProperty `
                $effectiveRestriction `
                'platformBlocked'

            PersonalWindowsBlocked = Get-SafeProperty `
                $effectiveRestriction `
                'personalDeviceEnrollmentBlocked'

            MinimumVersion = Get-SafeProperty `
                $effectiveRestriction `
                'osMinimumVersion'

            MaximumVersion = Get-SafeProperty `
                $effectiveRestriction `
                'osMaximumVersion'
        }
    } |
    Format-List