$rg = "rg-intune-primaryuser-test"
$userUpns = @("AdminMSN@icscf.de", "installer99@icscf.de")
$vmNames = @("TEST-WIN11-00", "TEST-WIN11-01")

foreach ($vmName in $vmNames) {
    $vmId = az vm show `
        --resource-group $rg `
        --name $vmName `
        --query id `
        --output tsv

    Write-Host "`n=== RBAC for $vmName ==="

    foreach ($upn in $userUpns) {
        $userId = az ad user show --id $upn --query id --output tsv

        az role assignment list `
            --assignee $userId `
            --scope $vmId `
            --query "[].{user:'$upn',role:roleDefinitionName,scope:scope}" `
            --output table
    }
}