# Intune Primary User Automation

> Deutsch: [ReadMe-Deutsch.md](ReadMe-Deutsch.md)

This repository contains the production deployment for automatically correcting Microsoft Intune **Primary User** assignments when Windows devices were initially enrolled with installer accounts such as `installer99@customer.tld`.

The customer production entry point is `Set-NewPrimaryUserForDevices-AppReg.ps1`. It is designed for unattended daily execution on a Windows management server. The delegated and CSV scripts are retained for testing/troubleshooting and are not the recommended daily scheduler.

## Production architecture

```text
Windows Scheduled Task (preferably gMSA)
        |
        | reads non-exportable certificate private key
        v
Entra app registration
        |
        +--> Defender XDR Advanced Hunting (DeviceInfo + DeviceLogonEvents)
        +--> Entra ID user validation
        +--> Intune managedDevice lookup
               read Primary User
               change only installerXY -> dominant real user
               read back and verify
```

The Windows task identity starts PowerShell, reads the certificate private key and writes logs. The Entra app registration owns the Microsoft Graph application permissions. No interactive administrator sign-in is required during daily operation.

## Candidate logic and safety

The production script intentionally does **not** assign the last person who logged on. It selects the dominant qualifying user over a lookback window so that technicians, admins or one-time logons do not become Primary User.

| Setting | Production default |
| --- | ---: |
| Lookback | 30 days |
| Minimum qualifying logons | 5 |
| Minimum active days | 3 |
| Minimum dominance ratio over runner-up | 2.0 |
| Maximum changes per run | 25 |
| RDP / RemoteInteractive logons | Excluded |
| Eligible current Primary User | `(?i)^installer[0-9]{2}@` |

Only devices whose **actual Intune Primary User relationship** matches `installerXY` are eligible. If that relationship is empty or ambiguous, the script refuses the automatic write.

## End-device prerequisites

Each target device must exist and be healthy in all three services:

| Service | Required state | Why |
| --- | --- | --- |
| Microsoft Entra ID | Entra joined or hybrid joined | Device identity/correlation |
| Microsoft Intune | Fully MDM-enrolled Windows managed device | Owns the Primary User relationship |
| Microsoft Defender for Endpoint | Onboarded and reporting | Supplies `DeviceInfo` and `DeviceLogonEvents` |

A device visible only as **Managed by MDE** through Defender Security Settings Management is not sufficient. The automation requires a normal Intune `managedDevice` record.

## 1. Prepare the customer tenant

Create a dedicated single-tenant App Registration, for example `Intune-PrimaryUser-Automation`.

Add these **Microsoft Graph Application permissions** and grant tenant-wide admin consent:

| Permission | Type | Purpose |
| --- | --- | --- |
| `ThreatHunting.Read.All` | Application | Run Defender XDR Advanced Hunting without a signed-in user |
| `DeviceManagementManagedDevices.ReadWrite.All` | Application | Read Intune managed devices and update Primary User |
| `User.Read.All` | Application | Resolve and validate candidate users |

Do not add broader permissions unless the design changes. Record the Directory (tenant) ID and Application (client) ID.

Microsoft references:
- https://learn.microsoft.com/graph/permissions-reference
- https://learn.microsoft.com/graph/api/security-security-runhuntingquery
- https://learn.microsoft.com/intune/developer/configure-graph-api-access

## 2. Prepare the management server

Recommended:
- Windows Server 2019/2022/2025 or a controlled Windows management server
- PowerShell 7
- outbound HTTPS/443 to Microsoft Graph, Entra ID, Intune and Defender XDR endpoints
- dedicated gMSA for the Scheduled Task
- no interactive use of the gMSA
- tightly controlled local administrator membership

Install the Graph authentication module:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope AllUsers
```

### Recommended Scheduled Task identity: gMSA

Have the customer's AD team create a dedicated gMSA and allow only the selected management server to retrieve its managed password. On Windows Server, install the AD PowerShell tools if needed and verify the account:

```powershell
Install-WindowsFeature RSAT-AD-PowerShell
Install-ADServiceAccount gmsaIntunePU
Test-ADServiceAccount gmsaIntunePU
```

`Test-ADServiceAccount` should return `True`. The production script itself does not query on-premises AD; the AD module is only needed here if the customer uses it to install/test the gMSA.

Recommended layout:

```text
C:\Automation\IntunePrimaryUser\
    Set-NewPrimaryUserForDevices-AppReg.ps1
    tools\

C:\ProgramData\IntunePrimaryUserCorrection\
    Logs\
    Status\
```

## 3. Create the application certificate

Create the client-authentication certificate **on the execution server**:

```powershell
.\tools\Create-Cert.ps1
```

The helper creates an RSA/SHA-256 certificate in `Cert:\LocalMachine\My`, uses a **non-exportable** private key, and exports only the public `.cer` file.

Upload only the CER under:

```text
Entra admin center
> App registrations
> Intune-PrimaryUser-Automation
> Certificates & secrets
> Certificates
```

Then grant the Scheduled Task gMSA **Read** permission on the certificate private key using `certlm.msc` > Personal > Certificates > All Tasks > Manage Private Keys.

The production script checks that the certificate exists, has an accessible private key, is currently valid, and warns when expiry is less than 30 days away.

## 4. Lock down the filesystem

The task identity must **not** be able to modify its own production code.

Example:

```powershell
$scriptRoot = "C:\Automation\IntunePrimaryUser"
$runtimeRoot = "C:\ProgramData\IntunePrimaryUserCorrection"
$gmsa = "CONTOSO\gmsaIntunePU$"

icacls $scriptRoot /inheritance:r
icacls $scriptRoot /grant:r `
    "*S-1-5-18:(OI)(CI)F" `
    "*S-1-5-32-544:(OI)(CI)F" `
    "$gmsa:(OI)(CI)RX"

icacls $runtimeRoot /inheritance:r
icacls $runtimeRoot /grant:r `
    "*S-1-5-18:(OI)(CI)F" `
    "*S-1-5-32-544:(OI)(CI)F" `
    "$gmsa:(OI)(CI)M"
```

Result: SYSTEM and local Administrators retain Full Control; the gMSA receives only Read/Execute on code and Modify on runtime logs/status. Test ACL changes before removing inheritance in a customer environment.

## 5. Tamper protection and misuse

No PowerShell script can be made absolutely unchangeable to a compromised local Administrator or SYSTEM account. Treat the management server's administrator boundary as a security boundary.

The solution now includes these safeguards:

- non-exportable application certificate private key;
- gMSA itself has no Microsoft Graph role;
- automatic writes only when current Primary User matches `installerXY`;
- telemetry thresholds and dominance check;
- `MaxChanges` batch limit;
- no fallback from an empty Primary User relationship to another Intune user property;
- every write is read back and verified;
- CSV, transcript and machine-readable LastRun JSON are written for every run;
- the service identity should have no write permission to the code directory.

These controls protect against accidental misuse and service-account modification, but they do **not** make an unsigned `.ps1` tamper-proof.

### Recommended code-integrity hardening

For production, sign the production script with a **separate enterprise Authenticode code-signing certificate**. Do not reuse the Graph client-authentication certificate.

The Scheduled Task helper supports `-RequireSignedScript`. It then refuses registration if the production script's Authenticode signature is not valid and launches PowerShell with `AllSigned`.

PowerShell execution policy is defense in depth, not a security boundary. For stronger enforcement use **App Control for Business (WDAC)** or the customer's existing application-control platform, allow only approved Microsoft/internal signers, and test in audit mode before enforcement.

## 6. Run report-only first

Do not enable writes immediately:

```powershell
.\Set-NewPrimaryUserForDevices-AppReg.ps1 `
    -TenantId "<tenant-id>" `
    -ClientId "<application-client-id>" `
    -CertificateThumbprint "<certificate-thumbprint>" `
    -CandidateUpnSuffix "customer.tld" `
    -LogPath "C:\ProgramData\IntunePrimaryUserCorrection\Logs" `
    -StatusPath "C:\ProgramData\IntunePrimaryUserCorrection\Status" `
    -MaxChanges 25
```

Review the CSV output:
- `WouldChange`: all checks passed; report-only prevented the write.
- `Skipped`: a safety condition prevented a write.
- `Error`: investigate before enabling `-Apply`.

Recommended: run several days in report-only mode.

## 7. Register the daily Scheduled Task

The repository includes `tools\Register-PrimaryUserScheduledTask.ps1`.

Report-only example:

```powershell
.\tools\Register-PrimaryUserScheduledTask.ps1 `
    -TenantId "<tenant-id>" `
    -ClientId "<application-client-id>" `
    -CertificateThumbprint "<certificate-thumbprint>" `
    -TaskIdentity "CONTOSO\gmsaIntunePU$" `
    -CandidateUpnSuffix "customer.tld" `
    -DailyAt "03:00" `
    -MaxChanges 25
```

After report review, register again with `-Apply`. If the script has a valid enterprise Authenticode signature, additionally use `-RequireSignedScript`.

The helper deliberately does not grant NTFS or private-key permissions. Those are explicit customer security decisions.

## Monitoring and exit codes

Every run creates:
- `PrimaryUserCorrection-<timestamp>.log`
- `PrimaryUserCorrection-Result-<timestamp>.csv`
- `PrimaryUserCorrection-LastRun.json`

| Exit code | Meaning |
| ---: | --- |
| 0 | Completed without per-device errors |
| 1 | Fatal run failure |
| 2 | Completed, but at least one device produced an Error row |

Recommended alerts:
- Scheduled Task result 1 or 2
- LastRun JSON older than 26 hours
- certificate expiry < 30 days
- unexpected increase in `Error` or `Skipped`
- repeated runs close to `MaxChanges`

## Customer rollout checklist

1. Validate Intune MDM and MDE coverage.
2. Create the single-purpose App Registration.
3. Add only the three documented Application permissions and grant admin consent.
4. Prepare the management server and gMSA.
5. Create the non-exportable client certificate and upload its CER.
6. Grant gMSA Read on the private key.
7. Lock down code/runtime NTFS permissions.
8. Run app-only report-only for several days.
9. Review all `WouldChange`, `Skipped` and `Error` rows.
10. Start production writes with `MaxChanges 5`.
11. Verify changes in Intune.
12. Increase to the agreed production batch size, for example 25.
13. Register the daily Scheduled Task.
14. Add monitoring and certificate-renewal ownership.
15. Optionally enforce Authenticode + App Control for Business.

## Repository layout

- `Set-NewPrimaryUserForDevices-AppReg.ps1` — production unattended direct-Defender workflow.
- `Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1` — interactive validation/troubleshooting.
- `Set-IntunePrimaryUserSingleDevice.ps1` — explicit single-device test.
- `Set-NewPrimaryUserForDevices-AppReg-UploadCSV.ps1` — legacy/manual CSV workflow; not recommended for daily production.
- `Create-AzResources-PrimaryUserChange.ps1` — Azure lab helper.
- `tools/Create-Cert.ps1` — customer app-authentication certificate helper.
- `tools/Register-PrimaryUserScheduledTask.ps1` — daily gMSA Scheduled Task registration helper.
- `COMMAND-GUIDE.md` — concise operator command guide.
