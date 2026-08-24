
$thumb = "43acc1da1f27ff26c6354c7f33c8363345722b8c"

whoami

Get-Item "Cert:\LocalMachine\My\$thumb" |
    Format-List Subject, Thumbprint, HasPrivateKey, NotBefore, NotAfter

Get-Item "Cert:\CurrentUser\My\$thumb" -ErrorAction SilentlyContinue |
    Format-List Subject, Thumbprint, HasPrivateKey, NotBefore, NotAfter


####################################################

$cert = Get-Item "Cert:\LocalMachine\My\$thumb"

$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)

if (-not $rsa) {
    throw "Kein RSA Private Key verfügbar."
}

try {
    $data = [Text.Encoding]::UTF8.GetBytes("private-key-test")

    [void]$rsa.SignData(
        $data,
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1
    )

    "Private key is usable."
}
finally {
    $rsa.Dispose()
} 

#############################################

