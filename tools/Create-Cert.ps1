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