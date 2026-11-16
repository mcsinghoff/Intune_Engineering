#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$Subject = "CN=Intune-PrimaryUser-Automation",
    [string]$ExportPath = "C:\Automation\Intune-PrimaryUser-Automation.cer",
    [ValidateRange(1, 5)]
    [int]$ValidityYears = 2
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$exportDirectory = Split-Path -Parent $ExportPath
if (-not (Test-Path -LiteralPath $exportDirectory)) {
    New-Item -Path $exportDirectory -ItemType Directory -Force | Out-Null
}

$cert = New-SelfSignedCertificate `
    -Subject $Subject `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -KeySpec Signature `
    -KeyExportPolicy NonExportable `
    -NotAfter (Get-Date).AddYears($ValidityYears)

Export-Certificate `
    -Cert $cert `
    -FilePath $ExportPath `
    -Force | Out-Null

Write-Host "Client-authentication certificate created."
Write-Host "Subject:    $($cert.Subject)"
Write-Host "Thumbprint: $($cert.Thumbprint)"
Write-Host "Valid until: $($cert.NotAfter)"
Write-Host "Public CER: $ExportPath"
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Upload only the CER to the Entra app registration under Certificates & secrets > Certificates."
Write-Host "2. Grant the scheduled-task identity Read access to the private key in certlm.msc."
Write-Host "3. Do not export or distribute the private key."
Write-Host ""
Write-Warning "This certificate authenticates the Graph application. It does NOT sign the PowerShell script. Use a separate enterprise code-signing certificate if Authenticode/App Control protection is required."

[PSCustomObject]@{
    Subject    = $cert.Subject
    Thumbprint = $cert.Thumbprint
    NotBefore  = $cert.NotBefore
    NotAfter   = $cert.NotAfter
    Store      = "LocalMachine\My"
    PublicCer  = $ExportPath
}
