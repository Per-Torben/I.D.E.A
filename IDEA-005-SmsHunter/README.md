# I.D.E.A. 005 – SMS MFA Hunter

## Overview
Interactive, menu-driven tool for Microsoft Entra ID. It finds users who have SMS or voice call registered as an MFA method, shows who actually uses it, and checks whether the tenant is set up to move them away from it. It combines a user hunt with a posture check of the authentication methods policy, the registration campaign and passkey profiles.

Read-only. No changes are made to the tenant.

## Script

### Get-SmsMfaReport.ps1
Interactive menu-driven analysis with console, CSV and HTML output. The HTML report uses the same layout as I.D.E.A. 004.

## Features
- **Scales to large tenants**: one bulk pull of the authentication methods registration report, then per-user phone detail only for users with a phone method registered
- **Report-lag aware**: directory users missing from the registration report are checked directly
- **Phone detail**: phone type (mobile, alternate mobile, office), number, country and SMS sign-in state
- **Effective default method**: the system-preferred method when that feature is on, otherwise the user's own default
- **Actual usage (optional)**: scans MFA sign-ins (1–30 days) for users who completed MFA with SMS/voice
- **Policy posture**:
  - Authentication methods policy: migration state, system-preferred MFA, report suspicious activity, every method configuration
  - SMS and Voice: state, targets, SMS sign-in (passwordless SMS), office phone
  - Registration campaign: state, snooze, enforcement after snoozes, targets and targeted method
  - Passkeys (FIDO2): state, self-service registration, each passkey profile (types, attestation, key restrictions, targeted groups), Temporary Access Pass
  - Warns when the default passkey profile is unchanged (synced allowed, no attestation, no key restrictions), and for any profile that allows synced passkeys without AAGUID restrictions
- **Cross-checks**: SMS/voice-only users, users still allowed SMS/voice, leftover registrations blocked by policy, users outside the campaign, users who cannot register a passkey, users who used SMS recently
- **Output**: console summary, semicolon-delimited CSV, self-contained HTML report (auto-opens in Edge)

## Risk model

| Level | Meaning |
| --- | --- |
| **High** | SMS/voice only |
| **Medium** | SMS/voice + other MFA, no phishing-resistant |
| **Low** | SMS/voice + phishing-resistant (cleanup) |
| **N/A** | Account disabled |

Phishing-resistant = passkeys (device-bound, synced, Authenticator, Windows Hello), FIDO2, Windows Hello for Business, platform credential, certificate.

Risk is the fallback category only, with the same wording in the console, CSV and every part of the HTML report. SMS sign-ins in the scanned window, SMS as default method, SMS sign-in state, policy targeting, campaign scope and passkey policy scope are separate columns and never change the level.

## Prerequisites
- PowerShell 7.0+
- Required module (auto-installed if missing): `Microsoft.Graph.Authentication`
- Entra ID P1 for the sign-in log scan

## Required Permissions (Graph API Scopes)
```
User.Read.All
Directory.Read.All
UserAuthenticationMethod.Read.All
AuditLog.Read.All
Policy.Read.All
```

This is the I.D.E.A. 004 set without `CrossTenantInformation.ReadBasic.All`. An app registration made for 004 (or with [I.D.E.A. 003](../IDEA-003-CertAppRegistration/README.md)) works here. Tested with certificate app-only auth.

Graph **beta** is used for passkey profiles, registration campaign enforcement, system-preferred MFA and sign-in log `authenticationDetails` (v1.0 returns that property empty). Beta may change without notice; beta-only checks are skipped with a warning if the call fails.

## Usage

```powershell
# Launch the interactive menu
.\Get-SmsMfaReport.ps1

# Reuse a certificate app-only connection
Connect-MgGraph -TenantId <tenant-id> -ClientId <app-id> -CertificateThumbprint <thumbprint> -NoWelcome
.\Get-SmsMfaReport.ps1

# Launch with diagnostic mode (transcript + verbose logging)
.\Get-SmsMfaReport.ps1 -DiagnosticMode
```

### Menu Options
```
[1] Connect to Microsoft Graph
[2] Check policy posture (auth methods, SMS/voice, registration campaign, passkeys)
[3] Hunt SMS/voice MFA users
[4] Export report (HTML/CSV) from the results above
[C] Clear cached results
[Q] Quit
```

[2] and [3] collect data and show it in the console. [4] only exports: it writes the HTML and/or CSV from whatever [2] and [3] collected in this session, and does not query Graph for data. Run [2], [3] or both before [4]; [4] is greyed out until then and lists which parts the report will contain. Re-run [2] or [3] to refresh, or [C] to clear. An existing Graph connection (including certificate app-only auth) is reused.

The hunt asks how many days of sign-in logs to scan (default 7, 0 to skip). The scan reads every MFA sign-in in the window, because Graph cannot filter on the authentication method server-side.

### Export Format Selection (after choosing [4])
```
[1] HTML (default)
[2] CSV
[3] HTML + CSV
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-LogDirectory` | String | Log file directory (default: `.\Logs`) |
| `-DiagnosticMode` | Switch | Enables transcript logging and verbose output for troubleshooting |

## Output Files

| File | Description |
|------|-------------|
| `exports/SmsMfaUsers-{timestamp}.csv` | One row per user with SMS/voice registered |
| `exports/SmsMfaPolicyPosture-{timestamp}.csv` | Policy and cross-check findings (area, check, status, current, recommended, notes) |
| `exports/SmsMfaReport-{tenant}-{timestamp}.html` | Interactive HTML report |
| `Logs/Get-SmsMfaReport-{timestamp}.log` | Execution log |
| `Logs/Get-SmsMfaReport-Diagnostic-{timestamp}.log` | Diagnostic transcript (only with `-DiagnosticMode`) |

## HTML Report
- Retirement notice when SMS/voice-only users exist
- **Part 1 - Policy posture** (tenant configuration): Fail/Warn/Pass/Info cards, findings-by-status pie, findings grouped by area (collapsible)
- **Part 2 - SMS/voice users**: cross-checks (users compared with policy), risk cards, fallback bar and risk pie (identical counts and labels), phone numbers by country
- Red "Has signed in with SMS" key filter with count and one-click button; the matching dashboard card is clickable
- User table: sorting, text search (name/UPN/phone), filters for risk (fallback category), type, account, SMS policy, passkey policy, campaign scope; SMS Uses, SMS Default and Fallback Category columns
- Method chip filters built from the data, with AND/OR and "only selected methods"
- Users found by direct lookup or the sign-in scan (missing from the registration report's phone set) are marked with `*`

## Known Limitations
- The registration details report lags behind real registrations. Users missing from it are checked directly; recent changes for users already in it may not show yet.
- Sign-in logs are ingested with a delay of several minutes. Very recent sign-ins may be missing from the scan.
- Users who used SMS/voice in the scanned window are always included, even if the registration report does not show a phone method yet.
- Sign-in log matching uses the `authenticationMethod` text (`Text message`, `Phone call`, ...). Validated against live data without SMS sign-ins; review the match pattern if your tenant reports different strings.
- Passkey profile to group mapping uses `includeTargets[].allowedPasskeyProfiles` as returned by Graph. Targets without that list are shown against the default profile.
- When the registration campaign is in `default` (Microsoft-managed) state, its scope cannot be evaluated per user.

## Troubleshooting

### WAM Token Cache Issues (403 Authorization_RequestDenied)
1. Clear the stale WAM token cache:
   ```powershell
   Remove-Item "$env:LOCALAPPDATA\.IdentityService" -Recurse -Force -ErrorAction SilentlyContinue
   ```
2. Reconnect using menu option [1]

### Sign-in log scan fails
Requires `AuditLog.Read.All` and Entra ID P1. The hunt continues without usage data.

## Security Considerations
- Script requires **read-only** permissions. No modifications are made to the tenant.
- No credentials or tokens are stored or exported
- Output contains personal data (names, UPNs, phone numbers, sign-in activity). Handle as sensitive data per GDPR/applicable regulations
- The menu warns about export/log files older than 24 hours
- Log files may contain UPNs. Manage log retention appropriately

## Author
Per-Torben Sørensen

## Version
1.0 – October 2026
