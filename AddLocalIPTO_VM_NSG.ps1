$rg = "rg-intune-primaryuser-test"
$vmNames = @("TEST-WIN11-00", "TEST-WIN11-01")
$myPublicIp = Invoke-RestMethod "https://api.ipify.org"

foreach ($vmName in $vmNames) {
    az network nsg rule update `
        --resource-group $rg `
        --nsg-name "$vmName`NSG" `
        --name "RDP" `
        --source-address-prefixes "$myPublicIp/32"

    Write-Host "Updated RDP NSG for $vmName to $myPublicIp/32"
}