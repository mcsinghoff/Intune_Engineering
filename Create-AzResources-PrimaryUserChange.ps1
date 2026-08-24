# Variables
$subscriptionId = "c1fcbc7a-9c43-4da8-9629-cddbcd201532"
$location       = "westeurope"
$rg             = "rg-intune-primaryuser-test"
$vmName         = "TEST-WIN11-00"
$adminUser      = "localadmin00"

# Use a strong password
$adminPassword = Read-Host "Enter local admin password" -AsSecureString
$adminPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPassword)
)

# Select subscription
az account set --subscription $subscriptionId

# Create resource group
az group create `
  --name $rg `
  --location $location

# Optional: check available Windows 11 SKUs in your region
az vm image list `
  --location $location `
  --publisher MicrosoftWindowsDesktop `
  --offer Windows-11 `
  --all `
  --output table

# Get your public IP for RDP restriction
$myPublicIp = (Invoke-RestMethod -Uri "https://api.ipify.org")

# Create Windows 11 Enterprise VM
az vm create `
  --resource-group $rg `
  --name $vmName `
  --location $location `
  --image "MicrosoftWindowsDesktop:Windows-11:win11-24h2-ent:latest" `
  --size "Standard_D2s_v5" `
  --storage-sku Standard_LRS `
  --admin-username $adminUser `
  --admin-password $adminPasswordPlain `
  --license-type Windows_Client `
  --public-ip-sku Standard `
  --assign-identity `
  --nsg-rule RDP

# Restrict RDP to your current public IP
az network nsg rule update `
  --resource-group $rg `
  --nsg-name "$vmName`NSG" `
  --name "RDP" `
  --source-address-prefixes "$myPublicIp/32"

# Show connection info
az vm show `
  --resource-group $rg `
  --name $vmName `
  --show-details `
  --query "{name:name, publicIp:publicIps, powerState:powerState}" `
  --output table

az vm extension set `
  --resource-group $rg `
  --vm-name $vmName `
  --publisher Microsoft.Azure.ActiveDirectory `
  --name AADLoginForWindows


<# Delete the resource with: 

$rg     = "rg-intune-primaryuser-test"
$vmName = "VM NAME"

az vm delete `
  --resource-group $rg `
  --name $vmName `
  --yes

az network nic delete `
  --resource-group $rg `
  --name "$vmName`VMNic" `
  2>$null

az network public-ip delete `
  --resource-group $rg `
  --name "$vmName`PublicIP" `
  2>$null

az network nsg delete `
  --resource-group $rg `
  --name "$vmName`NSG" `
  2>$null
##########################################
#>

#Log In With Users on Machine by adding the RBAC Roles:

$vmId = az vm show `
  --resource-group $rg `
  --name $vmName `
  --query id `
  --output tsv

$installerUserId = az ad user show `
  --id "installer99@icscf.de" `
  --query id `
  --output tsv

$adminUserId = az ad user show `
  --id "AdminMSN@icscf.de" `
  --query id `
  --output tsv

az role assignment create `
  --assignee $installerUserId `
  --role "Virtual Machine User Login" `
  --scope $vmId

az role assignment create `
  --assignee $adminUserId `
  --role "Virtual Machine Administrator Login" `
  --scope $vmId

<#
################################################
#ASSIGN SAMI-IDENTITIES TO THE VMS

$subscriptionId = "c1fcbc7a-9c43-4da8-9629-cddbcd201532"
$rg = "rg-intune-primaryuser-test"
$vmNames = @(
    "TEST-WIN11-01",
    "TEST-WIN11-02"
)

az account set --subscription $subscriptionId

foreach ($vmName in $vmNames) {
    Write-Host "=== Processing $vmName ==="

    # Enable system-assigned managed identity
    az vm identity assign `
        --resource-group $rg `
        --name $vmName

    # Remove existing AADLoginForWindows extension, if present
    az vm extension delete `
        --resource-group $rg `
        --vm-name $vmName `
        --name AADLoginForWindows `
        --only-show-errors `
        2>$null

    # Reinstall AADLoginForWindows extension
    az vm extension set `
        --resource-group $rg `
        --vm-name $vmName `
        --publisher Microsoft.Azure.ActiveDirectory `
        --name AADLoginForWindows

    # Restart VM
    az vm restart `
        --resource-group $rg `
        --name $vmName
}

##################################################
#>

