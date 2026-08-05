# I.D.E.A. 004 – Comprehensive MFA Report

## Overview
Interactive, menu-driven MFA report tool for Microsoft Entra ID. Generates a comprehensive Multi-Factor Authentication status report for all accounts in the tenant, with an interactive HTML dashboard, optional CSV exports, and a console summary with risk analysis.

## Script

### Get-EntraMFAReport.ps1
Interactive menu-driven MFA analysis with multiple output formats.

## Features
- **Interactive menu**: Connect to services and choose output format from an in-script menu
- **Full MFA method detection**: Authenticator App, SMS, Voice, FIDO2, Windows Hello for Business, Passwordless phone sign-in, Software OATH, Email, Temporary Access Pass
- **Account categorization**: User, Room, Shared Mailbox, Equipment (detected via Exchange Online RecipientTypeDetails)
- **Risk level scoring** (5-tier model):
  - **Critical**: Enabled account with no MFA registered
  - **High**: SMS/voice-only MFA (SIM-swap vulnerable; retirement advisory banner for Feb 1, 2027)
  - **Medium**: MFA enabled but no phishing-resistant method
  - **Good**: Has phishing-resistant method but also weaker methods registered (residual attack surface)
  - **Secure**: All registered methods are phishing-resistant (FIDO2/Windows Hello only)
  - **N/A**: Account disabled
- **MFA strength classification**:
  - **Phishing-resistant**: FIDO2 security key, Windows Hello for Business (origin-bound credentials)
  - **Authenticator tier**: Microsoft Authenticator app, Passwordless phone sign-in (AiTM vulnerable)
  - **Weak**: SMS, voice call, email OTP (SIM-swap/interception vulnerable)
  - Note: Passwordless phone sign-in is NOT phishing-resistant — it remains vulnerable to real-time phishing proxies (AiTM)
- **HTML dashboard sections**:
  - MFA Method Distribution Bar (No MFA / Weak only / Authenticator only / Phishing-resistant)
  - Admins and Members stat cards with X/N fractions
  - Risk score pie chart
  - Phone number country distribution pie chart
- **Admin role detection**: Flags accounts with active directory role assignments
- **License status**: Licensed vs. unlicensed accounts
- **Last sign-in activity**: Identifies inactive/stale accounts
- **Interactive HTML report**: Self-contained, works offline, no external dependencies
  - Column sorting (click any header)
  - Dropdown filters: Risk Level, MFA Status, User Type, Account Category, Account Status, Admin, Licensed, Last Sign-In
  - Text search across Display Name and UPN
  - MFA Method chip filters with OR / AND matching for multi-method searches
  - Separate `Only selected methods` option to exclude accounts that have methods outside the selected set
  - Retirement advisory banner with Microsoft guidance and background reading links for SMS/voice-only MFA
  - Color-coded risk indicators
- **CSV export**: Semicolon-delimited detailed user data + summary statistics
- **Console summary**: Risk breakdown, method distribution, admin/member/guest stats, and a pause before returning to the main menu

## Prerequisites
- PowerShell 7.0+
- Required modules (auto-installed if missing):
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Beta.Identity.SignIns`
  - `Microsoft.Graph.Identity.DirectoryManagement`
  - `ExchangeOnlineManagement`

## Required Permissions (Graph API Scopes)
```
User.Read.All
Directory.Read.All
UserAuthenticationMethod.Read.All
AuditLog.Read.All
```

Exchange Online connectivity is also required for authoritative mailbox-type detection (shared/room/equipment). The script connects automatically via menu option [2] if no existing EXO session is found.

## Usage

The script is fully interactive — launch it and use the menu:

```powershell
# Launch the interactive menu
.\Get-EntraMFAReport.ps1

# Launch with diagnostic mode (transcript + verbose logging for troubleshooting)
.\Get-EntraMFAReport.ps1 -DiagnosticMode
```

### Menu Options
```
[1] Connect to Microsoft Graph
[2] Connect to Exchange Online (optional)
[3] Generate MFA Report
[Q] Quit
```

### Output Format Selection (after choosing [3])
```
[1] Console + HTML report (default)
[2] Console + HTML + CSV
[3] Console only
[4] CSV only (no HTML)
```

Connection to Microsoft Graph is handled via menu option [1] — the script requests all required scopes and handles WAM token cache issues automatically.

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-LogDirectory` | String | Log file directory (default: `.\Logs`) |
| `-DiagnosticMode` | Switch | Enables transcript logging and verbose output for troubleshooting permission/consent issues |

## Output Files

| File | Description |
|------|-------------|
| `exports/MFADetailedReport-{timestamp}.csv` | All users with MFA details, risk levels, categories |
| `exports/MFASummaryReport-{timestamp}.csv` | Aggregated statistics |
| `exports/MFAReport-{tenant}-{timestamp}.html` | Interactive HTML dashboard report |
| `Logs/Get-EntraMFAReport-{timestamp}.log` | Execution log |
| `Logs/Get-EntraMFAReport-Diagnostic-{timestamp}.log` | Diagnostic transcript (only with `-DiagnosticMode`) |

## HTML Report Features
The HTML report is a single self-contained file that works offline in any modern browser. Automatically opens in Edge after generation.

**Dashboard**:
- MFA Method Distribution Bar: stacked bar showing No MFA / Weak only / Authenticator only / Phishing-resistant
- Admin and Member stat cards: Without MFA, Weak MFA, Phishing-resistant (as X/N counts)
- Guest summary line
- Risk score pie chart
- Phone number country distribution pie chart

**Filters**:
- Text search (name/UPN)
- Risk Level: Critical / High / Medium / Good / Secure / N/A
- MFA Status: Enabled / Disabled / Unknown
- User Type: Member / Guest
- Account Category: User / Room / Shared Mailbox / Equipment
- Account Status: Enabled / Disabled
- Is Admin: Yes / No
- Licensed: Yes / No
- Last Sign-In: Active (30d) / Inactive 30+ days / Inactive 90+ days / Never
- MFA Method chips: click to filter by specific methods
- OR / AND mode toggle: enabled when 2 or more methods are selected
- Only selected methods: limits results to accounts whose registered methods are all within the selected set

**Table**: Sortable columns, color-coded risk levels, responsive layout.

## Troubleshooting

### WAM Token Cache Issues (403 Authorization_RequestDenied)
If you get permission errors despite having the correct scopes:

1. Clear the stale WAM token cache:
   ```powershell
   Remove-Item "$env:LOCALAPPDATA\.IdentityService" -Recurse -Force -ErrorAction SilentlyContinue
   ```
2. Reconnect using menu option [1]

Use `-DiagnosticMode` to inspect which scopes the current token actually contains.

## Security Considerations
- Script requires **read-only** permissions — no modifications are made to the tenant
- No credentials or tokens are stored or exported
- HTML report contains personal data (names, UPNs, phone numbers, sign-in activity) — handle as sensitive data per GDPR/applicable regulations
- Log files may contain UPNs — manage log retention appropriately
- Report auto-opens in Edge in a normal window (not guest mode)

## Author
Per-Torben Sørensen

## Version
2.3 — June 2026
