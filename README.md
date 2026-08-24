# Intune Primary User Automation

This repository contains PowerShell tooling that determines the real primary user of a Windows
device from Microsoft Defender XDR logon telemetry and corrects the Primary User relationship in
Microsoft Intune. The production entry point is `Set-NewPrimaryUserForDevices-AppReg.ps1`.

The production script runs unattended with a Microsoft Entra app registration and certificate. It
queries Defender XDR directly; it does **not** require a manually exported or uploaded CSV file.
CSV files in the log directory are output reports only.

## Architecture

```text
Windows Task Scheduler identity (gMSA or dedicated service account)
    -> reads the local certificate private key
    -> authenticates as the Entra app registration
    -> runs Defender XDR Advanced Hunting
    -> resolves the candidate in Entra ID
    -> finds the matching Intune managed device
    -> changes and verifies the Intune Primary User relationship
```

The Windows identity and app registration have different responsibilities:

- The Windows identity starts PowerShell, reads the certificate private key, and writes logs.
- The app registration is the cloud identity authorized to query Defender XDR and update Intune.
- No interactive administrator sign-in is required at runtime.

## Device prerequisites

Every device processed by the automation must exist in all three services:

| Service | Required state | Why it is needed |
| --- | --- | --- |
| Microsoft Entra ID | Joined or hybrid joined | Supplies the Entra device ID used to correlate records |
| Microsoft Intune | Fully MDM-enrolled Windows managed device | Owns the Primary User relationship that is changed |
| Microsoft Defender for Endpoint | Onboarded and reporting telemetry | Populates `DeviceInfo` and `DeviceLogonEvents` |

A device displayed in Intune with **Managed by: MDE** is managed only through Defender for Endpoint
Security Settings Management. It is not a full Intune MDM enrollment and might not have an Intune
Primary User relationship. It is therefore insufficient for this automation.

The `AADLoginForWindows` Azure VM extension joins a VM to Entra ID so that Entra users can sign in.
Do not treat that join alone as proof of Intune enrollment. Confirm that the device has a normal
Intune managed-device record, an MDM check-in time, and an available Primary User relationship.

### Verify Entra join and Intune enrollment

Run these commands in a non-elevated PowerShell session of the Entra user that performs enrollment:

```powershell
whoami

dsregcmd /status |
    Select-String -Pattern 'AzureAdJoined|DomainJoined|WorkplaceJoined|AzureAdPrt|IsUserAzureAD|TenantId|MdmUrl|Executing Account Name'
```

Expected for an Entra-joined device and Entra user session:

```text
AzureAdJoined         : YES
AzureAdPrt            : YES
IsUserAzureAD         : YES
TenantId              : <customer-tenant-id>
MdmUrl                : https://enrollment.manage.microsoft.com/...
Executing Account Name: AzureAD\<user>
```

An MDM URL shows that enrollment is available; it does not prove that enrollment completed. Verify
the Intune enrollment tasks and events:

```powershell
Get-ScheduledTask |
    Where-Object TaskPath -Like '\Microsoft\Windows\EnterpriseMgmt\*' |
    Select-Object TaskName, State

Get-WinEvent `
    -FilterHashtable @{
        LogName = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
        Id      = 75, 76
    } `
    -MaxEvents 20 `
    -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List
```

- Event 75 means enrollment succeeded.
- Event 76 contains the enrollment failure code.
- No EnterpriseMgmt task and no 75/76 event normally means enrollment was never initiated.

For an already Entra-joined Windows client, the built-in manual MDM enrollment UI can be launched
from the licensed Entra user's non-elevated session:

```powershell
Start-Process explorer.exe -ArgumentList 'ms-device-enrollment:?mode=mdm'
```

The enrolling user must be in the Intune MDM user scope, be allowed by Windows enrollment
restrictions, remain below the configured device limit, and have an enabled Microsoft Intune service
plan. Microsoft 365 E5 includes Intune; Office 365 E5 does not.

### Verify Defender for Endpoint onboarding

An enabled Microsoft Defender Antivirus and a running `Sense` service do not by themselves prove
that the device is onboarded to Defender for Endpoint. Deploy an Intune **Endpoint detection and
response** onboarding policy after Intune enrollment, or use the Defender local onboarding script
for a small lab test.

```powershell
Get-Service Sense

Get-ItemProperty `
    'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' `
    -ErrorAction SilentlyContinue |
    Select-Object OnboardingState, OrgId
```

`OnboardingState` must be `1`. Verify telemetry in Defender XDR Advanced Hunting:

```kusto
DeviceInfo
| where DeviceName startswith "TEST-WIN11"
| summarize arg_max(Timestamp, *) by DeviceId
| project Timestamp, DeviceName, DeviceId, AadDeviceId, OnboardingStatus, SensorHealthState
```

## Server prerequisites

- Windows Server or Windows client that can run a scheduled task
- PowerShell 7 recommended
- Network access to Microsoft Graph, Intune, Entra ID, and Defender for Endpoint endpoints
- Microsoft Defender for Endpoint licensing and Advanced Hunting telemetry
- Microsoft Intune licensing and fully enrolled target devices
- Permission to create an Entra app registration and grant tenant-wide admin consent

Install the only required Microsoft Graph module from an elevated PowerShell session:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope AllUsers
```

## App registration

Create a single-tenant app registration in the **customer tenant**. Do not reuse a certificate or
app registration from a different customer or test tenant.

1. Open Microsoft Entra admin center.
2. Go to **Identity > Applications > App registrations > New registration**.
3. Use a descriptive name such as `Intune-PrimaryUser-Automation`.
4. Select **Accounts in this organizational directory only**.
5. Record the **Application (client) ID** and **Directory (tenant) ID**.
6. Under **API permissions**, add these Microsoft Graph **Application permissions**:

| Permission | Type | Purpose |
| --- | --- | --- |
| `ThreatHunting.Read.All` | Application | Run the Defender XDR Advanced Hunting query |
| `DeviceManagementManagedDevices.ReadWrite.All` | Application | Read managed devices and update Primary User relationships |
| `User.Read.All` | Application | Resolve and validate candidate users |

7. Select **Grant admin consent** and confirm that all three permissions show granted status.

Delegated permissions are not used by the unattended script. No user is expected to sign in during
scheduled execution.

## Certificate setup

Create the certificate on the server that will run the scheduled task. Run an elevated PowerShell
session from the repository root:

```powershell
.\tools\Create-Cert.ps1
```

The helper creates:

- A two-year RSA certificate with a non-exportable private key in `Cert:\LocalMachine\My`.
- The public certificate `C:\Automation\Intune-PrimaryUser-Automation.cer`.
- The certificate thumbprint printed to the console.

Upload only the `.cer` file under the app registration's **Certificates & secrets > Certificates**.
The `.cer` contains only the public key. The private key stays in the Windows certificate store and
does not need to be exported. Never commit or distribute a `.pfx` file or private key.

Verify the certificate:

```powershell
$thumbprint = '<certificate-thumbprint>'

Get-Item "Cert:\LocalMachine\My\$thumbprint" |
    Format-List Subject, Thumbprint, HasPrivateKey, NotBefore, NotAfter
```

`HasPrivateKey` must be `True`.

Grant the scheduled-task identity read access to the private key:

1. Run `certlm.msc`.
2. Open **Personal > Certificates**.
3. Right-click `Intune-PrimaryUser-Automation`.
4. Select **All Tasks > Manage Private Keys**.
5. Add the Windows task identity, for example `CONTOSO\gmsaIntunePU$`.
6. Grant **Read** only.

The script searches `LocalMachine\My` first and `CurrentUser\My` second. It signs a test payload
before connecting to Graph, so an inaccessible or public-only certificate fails with a clear error.

## How candidate selection works

The script queries successful logons from `DeviceLogonEvents` and correlates them with the newest
`DeviceInfo` record. The defaults are deliberately conservative:

| Parameter | Default | Meaning |
| --- | ---: | --- |
| `LookbackDays` | 30 | Defender telemetry window |
| `MinCandidateLogonCount` | 5 | Minimum successful logons by the winning user |
| `MinCandidateActiveDays` | 3 | Minimum distinct days with successful logons |
| `MinDominanceRatio` | 2.0 | Winner must have twice the runner-up's logons |
| `MaxChanges` | 25 | Maximum writes in one execution |

Only `Interactive` and `CachedInteractive` logons are considered by default. RDP
`RemoteInteractive` logons are ignored so that support and administrator sessions do not become the
Primary User. `-IncludeRemoteInteractive` exists for controlled lab testing and exceptional designs.

The query excludes installer, deployment, service, system, machine, and common administrator
accounts, including `localadmin*`. A candidate must resolve to exactly one enabled Entra user by UPN,
on-premises SID, or the optional `CandidateUpnSuffix` fallback.

Even a valid candidate is changed only when all safety checks pass:

- Exactly one Intune managed device matches the Defender device.
- The device is Windows.
- The current Primary User is present and matches `InstallerPrimaryUserRegex`.
- The candidate differs from the current Primary User.
- The run uses `-Apply` and has not reached `MaxChanges`.
- The changed relationship can be read back and verified.

## First test: report-only

The default mode never writes to Intune:

```powershell
.\Set-NewPrimaryUserForDevices-AppReg.ps1 `
    -TenantId '<tenant-id>' `
    -ClientId '<application-client-id>' `
    -CertificateThumbprint '<certificate-thumbprint>' `
    -CandidateUpnSuffix 'contoso.com' `
    -LogPath 'C:\ProgramData\IntunePrimaryUserCorrection\Logs' `
    -MaxChanges 1
```

Review the result CSV and investigate every `Error` row. Expected safe actions include:

- `WouldChange`: all checks passed, but report-only mode prevented the write.
- `Skipped`: a documented safety condition prevented the write.
- `Error`: infrastructure, identity resolution, or ambiguous data requires attention.

### Lab thresholds

A new lab device cannot satisfy the production default of three active days. For a one-day test,
reduce thresholds and keep the run report-only:

```powershell
.\Set-NewPrimaryUserForDevices-AppReg.ps1 `
    -TenantId '<tenant-id>' `
    -ClientId '<application-client-id>' `
    -CertificateThumbprint '<certificate-thumbprint>' `
    -CandidateUpnSuffix 'contoso.com' `
    -LogPath 'C:\ProgramData\IntunePrimaryUserCorrection\Logs' `
    -LookbackDays 7 `
    -MinCandidateLogonCount 1 `
    -MinCandidateActiveDays 1 `
    -MinDominanceRatio 1.1 `
    -IncludeRemoteInteractive `
    -MaxChanges 1
```

Remove `-IncludeRemoteInteractive` and restore production thresholds after lab validation.

## Apply changes

After reviewing `WouldChange` rows, start with a small limit:

```powershell
.\Set-NewPrimaryUserForDevices-AppReg.ps1 `
    -TenantId '<tenant-id>' `
    -ClientId '<application-client-id>' `
    -CertificateThumbprint '<certificate-thumbprint>' `
    -CandidateUpnSuffix 'contoso.com' `
    -LogPath 'C:\ProgramData\IntunePrimaryUserCorrection\Logs' `
    -MaxChanges 2 `
    -Apply
```

Increase `MaxChanges` only after the result has been verified in Intune. Adjust
`InstallerPrimaryUserRegex` when the customer's installer UPNs use a different naming convention.

## Scheduled task identity

Use a dedicated, least-privileged Windows service identity. In a traditional Active Directory
environment, a group Managed Service Account (gMSA) is recommended because AD rotates its password
automatically. The gMSA itself receives no Graph permissions.

The task identity needs only:

- Log on as a batch job.
- Read access to the script directory.
- Modify access to the log directory.
- Read access to the certificate private key.

It does not need to be a local administrator.

Example folder permissions:

```powershell
icacls 'C:\Automation\IntunePrimaryUser' /grant 'CONTOSO\gmsaIntunePU$:(OI)(CI)RX'
icacls 'C:\ProgramData\IntunePrimaryUserCorrection' /grant 'CONTOSO\gmsaIntunePU$:(OI)(CI)M'
```

## Windows Task Scheduler

Register the task with PowerShell so no interactive password prompt is required for a gMSA:

```powershell
$arguments = @(
    '-NoLogo'
    '-NoProfile'
    '-NonInteractive'
    '-ExecutionPolicy RemoteSigned'
    '-File "C:\Automation\IntunePrimaryUser\Set-NewPrimaryUserForDevices-AppReg.ps1"'
    '-TenantId "<tenant-id>"'
    '-ClientId "<application-client-id>"'
    '-CertificateThumbprint "<certificate-thumbprint>"'
    '-CandidateUpnSuffix "contoso.com"'
    '-LogPath "C:\ProgramData\IntunePrimaryUserCorrection\Logs"'
    '-MaxChanges 25'
    '-Apply'
) -join ' '

$action = New-ScheduledTaskAction `
    -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' `
    -Argument $arguments

$trigger = New-ScheduledTaskTrigger -Daily -At '03:00'

$principal = New-ScheduledTaskPrincipal `
    -UserId 'CONTOSO\gmsaIntunePU$' `
    -LogonType Password

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1)

Register-ScheduledTask `
    -TaskName 'Intune Primary User Correction' `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings
```

Run once in report-only mode before adding `-Apply` to the scheduled arguments.

## Logs and results

Each execution creates:

- `PrimaryUserCorrection-<timestamp>.log`: PowerShell transcript.
- `PrimaryUserCorrection-Result-<timestamp>.csv`: structured decisions and errors.

The result CSV is an audit artifact, not an input file. Protect the log directory and define a
retention period appropriate for the customer because device and user identifiers are included.

## Troubleshooting

| Symptom | Likely cause or action |
| --- | --- |
| `Der Schluesselsatz ist nicht vorhanden` / `Keyset does not exist` | The task identity cannot read the private key. Grant Read under **Manage Private Keys**. |
| Certificate found but `HasPrivateKey` is false | A public `.cer` was imported. Create the certificate on the execution server; do not use the CER as a private credential. |
| `0 high-confidence device candidate(s)` | Device not onboarded to MDE, no qualifying logons, production thresholds not yet reached, or only RDP logons occurred. |
| Local account cannot be resolved | Local accounts are not Entra users. Use a real Entra end user and ensure local admin patterns are excluded. |
| No Intune managed device matched | Device is not fully MDM-enrolled, Entra/Defender IDs do not correlate, or it is visible only as **Managed by: MDE**. |
| Device is Entra joined but absent from Intune | Check the enrolling user's Intune service plan, MDM scope, enrollment restrictions, device limit, EnterpriseMgmt tasks, and events 75/76. |
| Device is absent from Defender `DeviceInfo` | Deploy MDE onboarding and verify `OnboardingState = 1`, SENSE events, and network connectivity. |
| Candidate appears only with `-IncludeRemoteInteractive` | All observed user logons are RDP `RemoteInteractive` events. Use console logons or explicitly accept that design. |

## Repository layout

- `Set-NewPrimaryUserForDevices-AppReg.ps1`: unattended, direct-KQL production workflow.
- `Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1`: interactive delegated-permission workflow.
- `Set-IntunePrimaryUserSingleDevice.ps1`: controlled single-device testing.
- `Old_Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1`: preserved legacy implementation.
- `Create-AzResources-PrimaryUserChange.ps1`: Azure VM lab helper; review tenant-specific values before use.
- `tools/Create-Cert.ps1`: creates the local-machine certificate and exports its public CER.

## Microsoft documentation

- [Run an Advanced Hunting query with Microsoft Graph](https://learn.microsoft.com/graph/api/security-security-runhuntingquery)
- [Microsoft Graph PowerShell certificate authentication](https://learn.microsoft.com/powershell/microsoftgraph/authentication-commands)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/graph/permissions-reference)
- [Windows device enrollment guide for Intune](https://learn.microsoft.com/intune/device-enrollment/windows/guide)
- [Deploy an Endpoint detection and response policy with Intune](https://learn.microsoft.com/intune/device-configuration/endpoint-security/deploy-edr)
- [Defender XDR `DeviceLogonEvents` schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicelogonevents-table)
- [Manage group Managed Service Accounts](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/manage-group-managed-service-accounts)

