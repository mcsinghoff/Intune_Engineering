# Command Guide

This guide explains which script to use for each stage of the Intune Primary User correction workflow.

## 1. Create or rebuild the Azure lab VM

Use:

```powershell
.\Create-AzResources-PrimaryUserChange.ps1
```

Use this only for the lab environment. The script creates the Windows 11 VM, assigns a system-managed identity, enables RDP, installs the `AADLoginForWindows` extension, and assigns the configured VM login roles.

Before recreating a VM with an existing name, check Entra ID for stale device objects with the same hostname. A stale object can cause `AADLoginForWindows` to fail with `error_hostname_duplicate`.

## 2. Test a single Intune Primary User assignment

Use this before testing the automatic Defender-based selection:

```powershell
.\Set-IntunePrimaryUserSingleDevice.ps1 `
    -TenantId "ade56966-ae5b-4e8d-95c6-b84548490b80" `
    -DeviceName "TEST-WIN11-01" `
    -UserPrincipalName "AdminMSN@icscf.de" `
    -WhatIf
```

Purpose:
- validates Graph authentication;
- validates Intune device lookup;
- validates user lookup;
- proves which Primary User would be assigned;
- does not use Defender XDR Advanced Hunting.

Remove `-WhatIf` only when a deliberate single-device write should be tested.

## 3. Test candidate detection with real Defender XDR telemetry

Use the delegated script with reduced lab thresholds and `-WhatIf`:

```powershell
$reportPath = Join-Path $PWD "PrimaryUserCorrection-Test"

.\Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1 `
    -TenantId "ade56966-ae5b-4e8d-95c6-b84548490b80" `
    -SkipAdResolution `
    -CandidateUpnSuffix "icscf.de" `
    -MinCandidateLogonCount 1 `
    -MinCandidateActiveDays 1 `
    -MaxChanges 25 `
    -LogPath $reportPath `
    -WhatIf
```

Purpose:
- runs the real Defender XDR Advanced Hunting query;
- determines the most likely user from `DeviceLogonEvents`;
- finds the matching Intune device;
- reads the current Intune Primary User;
- verifies that the current Primary User matches the installer-account pattern;
- validates the candidate user in Entra ID;
- reports `WouldChange`, `Skipped`, or `Error`;
- performs no Intune write because of `-WhatIf`.

For production, restore the normal confidence thresholds instead of the reduced 1-logon / 1-day lab thresholds.

## 4. Review the generated CSV

The delegated script writes a transcript and a structured CSV into the configured `LogPath`.

Review the newest result file:

```powershell
$csv = Get-ChildItem `
    -Path (Join-Path $PWD "PrimaryUserCorrection-Test") `
    -Filter "PrimaryUserCorrection-Result-*.csv" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

Import-Csv $csv.FullName |
    Format-Table DeviceName,CurrentPrimaryUser,CandidateSamAccountName,CandidateUpn,Action,Reason -AutoSize
```

Interpretation:
- `WouldChange`: all safety checks passed and `-WhatIf` prevented the write.
- `Skipped`: a safety rule prevented a change; review the Reason column.
- `Error`: the device or user could not be processed successfully.

Show only devices that are ready to change:

```powershell
Import-Csv $csv.FullName |
    Where-Object Action -eq "WouldChange" |
    Format-Table DeviceName,CurrentPrimaryUser,CandidateUpn,Action -AutoSize
```

Show only rows that require review:

```powershell
Import-Csv $csv.FullName |
    Where-Object Action -ne "WouldChange" |
    Format-Table DeviceName,CurrentPrimaryUser,CandidateUpn,Action,Reason -Wrap -AutoSize
```

## 5. Perform a controlled delegated write

Only after the `-WhatIf` CSV has been reviewed:

```powershell
.\Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1 `
    -TenantId "ade56966-ae5b-4e8d-95c6-b84548490b80" `
    -SkipAdResolution `
    -CandidateUpnSuffix "icscf.de" `
    -MinCandidateLogonCount 1 `
    -MinCandidateActiveDays 1 `
    -MaxChanges 1 `
    -LogPath (Join-Path $PWD "PrimaryUserCorrection-Test") `
    -Confirm:$false
```

Use `-MaxChanges 1` for the first productive lab test.

Important: `MaxChanges` limits the number of successful writes. It does not select a specific device. Always review the preceding `-WhatIf` report before a productive run.

## 6. Production unattended mode

Use:

```text
Set-NewPrimaryUserForDevices-AppReg.ps1
```

Use this after the delegated workflow has been validated. It authenticates app-only with a certificate and is designed for scheduled unattended execution.

Normal production behavior:
- conservative logon thresholds;
- installer-account safety check;
- report-only run before enabling changes;
- limited `MaxChanges`;
- transcript and CSV audit output;
- scheduled execution with a dedicated service identity.

## Which script should I use?

| Goal | Script | Safe preview |
| --- | --- | --- |
| Create Azure lab VM | `Create-AzResources-PrimaryUserChange.ps1` | N/A |
| Test one explicit Primary User assignment | `Set-IntunePrimaryUserSingleDevice.ps1` | `-WhatIf` |
| Test automatic candidate detection interactively | `Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1` | `-WhatIf` |
| Review candidate decisions | Generated result CSV | Read-only |
| Run unattended production automation | `Set-NewPrimaryUserForDevices-AppReg.ps1` | omit `-Apply` |
| Process a manually reviewed hunting CSV | `Set-NewPrimaryUserForDevices-AppReg-UploadCSV.ps1` | omit `-Apply` |

## Recommended operating sequence

1. Confirm target devices are Entra joined or hybrid joined, Intune managed, and MDE onboarded.
2. Confirm `DeviceLogonEvents` contains the expected real user.
3. Run the delegated script with `-WhatIf`.
4. Review every `WouldChange`, `Skipped`, and `Error` row.
5. Perform a one-device or one-change productive lab run.
6. Verify the Primary User in Intune.
7. Restore production thresholds.
8. Move to the app-registration version for unattended operation.
