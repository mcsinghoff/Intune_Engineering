# Intune Primary User Automation – Kundenimplementierung

> English: [README.md](README.md)
>
> Dokumentationsregel: Änderungen an Produktiv-Setup, Berechtigungen, Sicherheitsmaßnahmen, Parametern oder Scheduled-Task-Deployment müssen in beiden README-Dateien gepflegt werden.

Dieses Repository enthält die produktive Lösung zur automatischen Korrektur des **Primary User** in Microsoft Intune, wenn Windows-Geräte ursprünglich mit Installationskonten wie `installer99@kunde.de` registriert wurden.

Der produktive Einstiegspunkt für Kunden ist `Set-NewPrimaryUserForDevices-AppReg.ps1`. Das Skript ist für einen unbeaufsichtigten täglichen Betrieb auf einem Windows-Managementserver ausgelegt. Die Delegated- und CSV-Skripte bleiben für Tests und Fehlersuche im Repository, sind aber nicht für den täglichen Produktiv-Scheduler vorgesehen.

## Zielarchitektur

```text
Windows Scheduled Task (vorzugsweise gMSA)
        |
        | liest privaten, nicht exportierbaren Zertifikatsschlüssel
        v
Entra App Registration
        |
        +--> Defender XDR Advanced Hunting (DeviceInfo + DeviceLogonEvents)
        +--> Entra ID Benutzerprüfung
        +--> Intune managedDevice Lookup
               Primary User lesen
               nur installerXY -> dominanter echter Benutzer
               Änderung zurücklesen und verifizieren
```

Die Windows-Task-Identität startet PowerShell, liest den privaten Zertifikatsschlüssel und schreibt Logs. Die Entra App Registration besitzt die Microsoft-Graph-Anwendungsberechtigungen. Im täglichen Betrieb ist keine interaktive Administratoranmeldung erforderlich.

## Auswahl des Zielbenutzers und Schutzmechanismen

Das Produktionsskript setzt absichtlich **nicht einfach den zuletzt angemeldeten Benutzer**. Es ermittelt den dominanten qualifizierten Benutzer über einen Lookback-Zeitraum. Dadurch wird verhindert, dass Techniker, Administratoren oder einmalige Anmeldungen zum Primary User werden.

| Einstellung | Produktionsstandard |
| --- | ---: |
| Lookback | 30 Tage |
| Mindestanzahl qualifizierter Logons | 5 |
| Mindestanzahl aktiver Tage | 3 |
| Mindest-Dominanz gegenüber Platz 2 | 2,0 |
| Maximale Änderungen pro Lauf | 25 |
| RDP / RemoteInteractive | ausgeschlossen |
| Zulässiger aktueller Primary User | `(?i)^installer[0-9]{2}@` |

Nur Geräte, deren **echte Intune-Primary-User-Beziehung** dem Muster `installerXY` entspricht, dürfen automatisch geändert werden. Ist diese Beziehung leer oder mehrdeutig, verweigert das Skript die automatische Änderung.

## Voraussetzungen auf den Endgeräten

Jedes Zielgerät muss in allen drei Diensten korrekt vorhanden sein:

| Dienst | Erforderlicher Zustand | Zweck |
| --- | --- | --- |
| Microsoft Entra ID | Entra joined oder hybrid joined | Geräteidentität/Korrelation |
| Microsoft Intune | vollständig per MDM verwaltetes Windows-Gerät | besitzt die Primary-User-Beziehung |
| Microsoft Defender for Endpoint | onboarded und meldend | liefert `DeviceInfo` und `DeviceLogonEvents` |

Ein Gerät, das nur über Defender Security Settings Management als **Managed by MDE** erscheint, reicht nicht aus. Benötigt wird ein normales Intune-`managedDevice`.

## 1. Kunden-Tenant vorbereiten

Eine dedizierte Single-Tenant App Registration anlegen, zum Beispiel `Intune-PrimaryUser-Automation`.

Folgende **Microsoft Graph Application Permissions** hinzufügen und tenantweiten Admin Consent erteilen:

| Berechtigung | Typ | Zweck |
| --- | --- | --- |
| `ThreatHunting.Read.All` | Application | Defender XDR Advanced Hunting ohne angemeldeten Benutzer ausführen |
| `DeviceManagementManagedDevices.ReadWrite.All` | Application | Intune Managed Devices lesen und Primary User ändern |
| `User.Read.All` | Application | Kandidatenbenutzer in Entra auflösen und validieren |

Keine breiteren Berechtigungen vergeben, solange sich der Funktionsumfang nicht ändert. Directory (tenant) ID und Application (client) ID dokumentieren.

Microsoft-Dokumentation:
- https://learn.microsoft.com/graph/permissions-reference
- https://learn.microsoft.com/graph/api/security-security-runhuntingquery
- https://learn.microsoft.com/intune/developer/configure-graph-api-access

## 2. Managementserver vorbereiten

Empfohlen:
- Windows Server 2019/2022/2025 oder kontrollierter Windows-Managementserver
- PowerShell 7
- ausgehendes HTTPS/443 zu Microsoft Graph, Entra ID, Intune und Defender XDR
- dedizierte gMSA für den Scheduled Task
- keine interaktive Nutzung der gMSA
- möglichst wenige lokale Administratoren

Microsoft Graph Authentication installieren:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope AllUsers
```

### Empfohlene Scheduled-Task-Identität: gMSA

Die AD-Verantwortlichen des Kunden erstellen eine dedizierte gMSA und erlauben nur dem vorgesehenen Managementserver, das verwaltete Kennwort abzurufen. Auf Windows Server bei Bedarf die AD-PowerShell-Werkzeuge installieren und die gMSA prüfen:

```powershell
Install-WindowsFeature RSAT-AD-PowerShell
Install-ADServiceAccount gmsaIntunePU
Test-ADServiceAccount gmsaIntunePU
```

`Test-ADServiceAccount` sollte `True` liefern. Das Produktionsskript selbst fragt das lokale Active Directory nicht ab; das AD-Modul wird hier nur benötigt, wenn der Kunde es zur Installation/Prüfung der gMSA verwendet.

Empfohlene Verzeichnisstruktur:

```text
C:\Automation\IntunePrimaryUser\
    Set-NewPrimaryUserForDevices-AppReg.ps1
    tools\

C:\ProgramData\IntunePrimaryUserCorrection\
    Logs\
    Status\
```

## 3. Zertifikat für die App Registration erstellen

Das Client-Authentifizierungszertifikat **auf dem späteren Ausführungsserver** erzeugen:

```powershell
.\tools\Create-Cert.ps1
```

Der Helper erzeugt ein RSA/SHA-256-Zertifikat in `Cert:\LocalMachine\My`, verwendet einen **nicht exportierbaren** privaten Schlüssel und exportiert nur die öffentliche `.cer`-Datei.

Nur die CER hochladen unter:

```text
Entra Admin Center
> App registrations
> Intune-PrimaryUser-Automation
> Certificates & secrets
> Certificates
```

Danach der Scheduled-Task-gMSA **Leserechte** auf den privaten Schlüssel geben: `certlm.msc` > Persönlich > Zertifikate > Alle Aufgaben > Private Schlüssel verwalten.

Das Produktionsskript prüft, ob das Zertifikat vorhanden ist, einen zugänglichen privaten Schlüssel besitzt, aktuell gültig ist und warnt bei weniger als 30 Tagen Restlaufzeit.

## 4. NTFS-Rechte härten

Die Task-Identität darf **ihr eigenes Produktionsskript nicht verändern können**.

Beispiel:

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

Ergebnis: SYSTEM und lokale Administratoren behalten Vollzugriff; die gMSA erhält nur Lesen/Ausführen auf Code und Ändern auf Logs/Status. ACL-Änderungen im Kundenumfeld zuerst testen.

## 5. Schutz vor Manipulation und Missbrauch

Ein PowerShell-Skript kann gegenüber einem kompromittierten lokalen Administrator oder SYSTEM nicht absolut unveränderbar gemacht werden. Der Administratorzugriff auf den Managementserver ist deshalb eine Sicherheitsgrenze.

Die Lösung enthält inzwischen folgende Schutzmaßnahmen:

- nicht exportierbarer privater Schlüssel des App-Zertifikats;
- gMSA selbst besitzt keine Microsoft-Graph-Rollen;
- automatische Writes nur, wenn der aktuelle Primary User `installerXY` entspricht;
- Telemetrie-Schwellen und Dominanzprüfung;
- `MaxChanges` als Batch-Limit;
- kein Fallback mehr von einer leeren Primary-User-Beziehung auf ein anderes Intune-Benutzerfeld;
- jeder Write wird zurückgelesen und verifiziert;
- CSV, Transcript und maschinenlesbare LastRun-JSON pro Lauf;
- die Service-Identität soll keine Schreibrechte auf das Code-Verzeichnis besitzen.

Diese Maßnahmen reduzieren versehentlichen Missbrauch und Manipulation durch die Service-Identität, machen eine unsignierte `.ps1` aber nicht manipulationssicher.

### Empfohlene zusätzliche Code-Integrity-Härtung

Für Produktion das Skript mit einem **separaten unternehmensweiten Authenticode Code-Signing-Zertifikat** signieren. Das Graph-Client-Zertifikat nicht dafür wiederverwenden.

Der Scheduled-Task-Helper unterstützt `-RequireSignedScript`. Dann wird die Registrierung verweigert, wenn die Authenticode-Signatur des Produktionsskripts nicht gültig ist, und PowerShell wird mit `AllSigned` gestartet.

Wichtig: PowerShell Execution Policy ist Defense in Depth und keine vollständige Security Boundary. Für stärkere Durchsetzung **App Control for Business (WDAC)** oder die vorhandene Application-Control-Lösung des Kunden verwenden, nur freigegebene Microsoft-/Unternehmens-Signer zulassen und zunächst im Audit Mode testen.

## 6. Zuerst Report-only betreiben

Schreibzugriffe nicht sofort aktivieren:

```powershell
.\Set-NewPrimaryUserForDevices-AppReg.ps1 `
    -TenantId "<tenant-id>" `
    -ClientId "<application-client-id>" `
    -CertificateThumbprint "<certificate-thumbprint>" `
    -CandidateUpnSuffix "kunde.de" `
    -LogPath "C:\ProgramData\IntunePrimaryUserCorrection\Logs" `
    -StatusPath "C:\ProgramData\IntunePrimaryUserCorrection\Status" `
    -MaxChanges 25
```

CSV auswerten:
- `WouldChange`: alle Prüfungen bestanden; Report-only hat den Write verhindert.
- `Skipped`: eine Schutzbedingung hat die Änderung verhindert.
- `Error`: vor Aktivierung von `-Apply` untersuchen.

Empfehlung: mehrere Tage Report-only laufen lassen.

## 7. Täglichen Scheduled Task registrieren

Im Repository liegt `tools\Register-PrimaryUserScheduledTask.ps1`.

Beispiel Report-only:

```powershell
.\tools\Register-PrimaryUserScheduledTask.ps1 `
    -TenantId "<tenant-id>" `
    -ClientId "<application-client-id>" `
    -CertificateThumbprint "<certificate-thumbprint>" `
    -TaskIdentity "CONTOSO\gmsaIntunePU$" `
    -CandidateUpnSuffix "kunde.de" `
    -DailyAt "03:00" `
    -MaxChanges 25
```

Nach Freigabe der Reports erneut mit `-Apply` registrieren. Bei gültiger Enterprise-Authenticode-Signatur zusätzlich `-RequireSignedScript` verwenden.

Der Helper vergibt absichtlich keine NTFS- oder Private-Key-Berechtigungen. Diese Einstellungen werden bewusst im Kundenumfeld gesetzt.

## Monitoring und Exit-Codes

Jeder Lauf erzeugt:
- `PrimaryUserCorrection-<timestamp>.log`
- `PrimaryUserCorrection-Result-<timestamp>.csv`
- `PrimaryUserCorrection-LastRun.json`

| Exit-Code | Bedeutung |
| ---: | --- |
| 0 | Lauf ohne Gerätefehler abgeschlossen |
| 1 | Fataler Fehler des gesamten Laufs |
| 2 | Lauf abgeschlossen, aber mindestens ein Gerät hatte `Error` |

Empfohlene Alarme:
- Scheduled Task Result 1 oder 2
- LastRun-JSON älter als 26 Stunden
- Zertifikatsablauf < 30 Tage
- unerwarteter Anstieg von `Error` oder `Skipped`
- wiederholt nahezu `MaxChanges` Änderungen

## Checkliste für den Kunden-Rollout

1. Intune-MDM- und MDE-Abdeckung validieren.
2. Dedizierte Single-Purpose App Registration anlegen.
3. Nur die drei dokumentierten Application Permissions hinzufügen und Admin Consent erteilen.
4. Managementserver und gMSA vorbereiten.
5. Nicht exportierbares Client-Zertifikat erstellen und CER hochladen.
6. gMSA Leserechte auf den Private Key geben.
7. Code- und Runtime-NTFS-Rechte härten.
8. App-only mehrere Tage Report-only betreiben.
9. Alle `WouldChange`, `Skipped` und `Error` auswerten.
10. Produktive Writes zunächst mit `MaxChanges 5` starten.
11. Änderungen in Intune verifizieren.
12. Auf vereinbarte Batchgröße, z. B. 25, erhöhen.
13. Täglichen Scheduled Task registrieren.
14. Monitoring und Zertifikatserneuerung organisatorisch zuordnen.
15. Optional Authenticode + App Control for Business durchsetzen.

## Repository-Inhalt

- `Set-NewPrimaryUserForDevices-AppReg.ps1` — produktive unbeaufsichtigte direkte Defender-Automation.
- `Set-NewPrimaryUserForDevices-DelegatedPermissions.ps1` — interaktive Validierung/Fehlersuche.
- `Set-IntunePrimaryUserSingleDevice.ps1` — gezielter Einzelgerätetest.
- `Set-NewPrimaryUserForDevices-AppReg-UploadCSV.ps1` — alter/manueller CSV-Weg; nicht für täglichen Produktivbetrieb empfohlen.
- `Create-AzResources-PrimaryUserChange.ps1` — Azure-Lab-Helfer.
- `tools/Create-Cert.ps1` — Client-Zertifikat für die Kunden-App-Registration.
- `tools/Register-PrimaryUserScheduledTask.ps1` — Registrierung des täglichen gMSA Scheduled Tasks.
- `COMMAND-GUIDE.md` — kurze Befehlsübersicht.
