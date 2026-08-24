# Intune Primary User correction

This repository contains PowerShell tooling for correcting Intune Primary User assignments from
Microsoft Defender XDR logon telemetry. The production-oriented entry point is
`Set-NewPrimaryUserForDevices-AppOnly.ps1`.

## How the unattended workflow works

1. Authenticate to Microsoft Graph as an application with a certificate.
2. Query `DeviceLogonEvents` and the latest `DeviceInfo` through Defender XDR Advanced Hunting.
3. Rank successful interactive logons per Windows client over a configurable lookback window.
4. Accept a candidate only after minimum logon/day thresholds and a dominance check against the
   second-place user.
5. Resolve the candidate in Microsoft Entra ID.
6. Match Defender and Intune primarily by Entra device ID, with an exact short-name fallback.
7. Change the Primary User only if the current value matches the installer-account regex.
8. Read the relationship back after each write and record the result in a CSV and transcript.

RDP logons are excluded by default so that support or administrator sessions do not become the
Primary User. The script is report-only by default; `-Apply` is required for writes.

## App registration

Create a single-tenant Microsoft Entra app registration and grant these **Microsoft Graph
application permissions** with admin consent:

- `ThreatHunting.Read.All`
- `DeviceManagementManagedDevices.ReadWrite.All`
- `User.Read.All`

Use a certificate instead of a client secret. Upload only the public certificate to the app
registration. Install the certificate with its private key on the execution server and restrict
private-key ACLs to the Windows service account that runs the scheduled task.

Microsoft references:

- [Run an Advanced Hunting query](https://learn.microsoft.com/graph/api/security-security-runhuntingquery?view=graph-rest-beta)
- [App-only Microsoft Graph PowerShell authentication](https://learn.microsoft.com/powershell/microsoftgraph/app-only?view=graph-powershell-1.0)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/graph/permissions-reference)

## First rollout

Install PowerShell 7 and the authentication module on the server:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope AllUsers
```

Run report-only first:

```powershell
.\Set-NewPrimaryUserForDevices-AppOnly.ps1 `
    -TenantId "<tenant-id>" `
    -ClientId "<application-client-id>" `
    -CertificateThumbprint "<certificate-thumbprint>" `
    -CandidateUpnSuffix "contoso.com" `
    -LogPath "C:\ProgramData\IntunePrimaryUserCorrection\Logs"
```

Review every `WouldChange` row. Start productive testing with a small safety limit:

```powershell
.\Set-NewPrimaryUserForDevices-AppOnly.ps1 `
    -TenantId "<tenant-id>" `
    -ClientId "<application-client-id>" `
    -CertificateThumbprint "<certificate-thumbprint>" `
    -CandidateUpnSuffix "contoso.com" `
    -LogPath "C:\ProgramData\IntunePrimaryUserCorrection\Logs" `
    -MaxChanges 2 `
    -Apply
```

Increase `MaxChanges` only after the report and Intune results have been checked. Tune
`InstallerPrimaryUserRegex` if installer account names differ from the default.

## Windows Task Scheduler

Create the task under a dedicated, non-interactive Windows service account that can read the
certificate private key and write to the log folder. Use `pwsh.exe` as the program and arguments
similar to:

```text
-NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "C:\Automation\Set-NewPrimaryUserForDevices-AppOnly.ps1" -TenantId "<tenant-id>" -ClientId "<client-id>" -CertificateThumbprint "<thumbprint>" -CandidateUpnSuffix "contoso.com" -LogPath "C:\ProgramData\IntunePrimaryUserCorrection\Logs" -MaxChanges 25 -Apply
```

Recommended schedule: daily during a quiet period. Configure the task to stop if it runs longer
than one hour, prevent overlapping runs, and retain the CSV/transcript logs according to the
organization's audit policy.

## Other scripts

- `Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1`: interactive admin/testing workflow.
- `Set-NewPrimaryUserForDevices-AppReg.ps1`: app-only processing of a reviewed CSV export.
- `Set-IntunePrimaryUserSingleDevice.ps1`: controlled single-device test.
- `Old_Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1`: preserved legacy implementation.
- `Create-AzResources-PrimaryUserChange.ps1`: lab resource provisioning helper.
