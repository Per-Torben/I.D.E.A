# I.D.E.A. 004 – Comprehensive MFA Report

## Overview
Generates a detailed Multi-Factor Authentication (MFA) status report for all accounts in a Microsoft Entra ID tenant. Produces an interactive HTML report, CSV exports, and a console summary with risk analysis.

## Script

### Get-EntraMFAReport.ps1
Comprehensive MFA analysis with multiple output formats.

## Features
- **Full MFA method detection**: Authenticator App, Phone/SMS, FIDO2, Windows Hello for Business, Passwordless, Software OATH, Email, Temporary Access Pass
- **Account categorization**: User, Room, Shared Mailbox, Equipment (detected via license SKUs and UPN heuristics)
- **Risk level scoring**:
  - **Critical**: Enabled account with no MFA registered
  - **High**: SMS-only MFA (SIM-swap vulnerable)
  - **Medium**: MFA enabled but no phishing-resistant method (no FIDO2/Windows Hello)
  - **Low**: Phishing-resistant MFA (FIDO2 or Windows Hello)
  - **N/A**: Account disabled or assessment blocked by CA policy
- **Admin role detection**: Flags accounts with active directory role assignments
- **License status**: Licensed vs. unlicensed accounts
- **Last sign-in activity**: Identifies inactive/stale accounts
- **Interactive HTML report**: Self-contained, works offline, no external dependencies
  - Column sorting (click any header)
  - Dropdown filters: Risk Level, MFA Status, User Type, Account Category, Account Status, Admin, Licensed, Last Sign-In
  - Text search across Display Name and UPN
  - MFA Method chip filters (toggle multiple methods)
  - Color-coded risk indicators
- **CSV export**: Semicolon-delimited detailed user data + summary statistics
- **Console summary**: Risk breakdown, method distribution, admin warnings

## Prerequisites
- PowerShell 7.0+
- Active Microsoft Graph connection with required scopes
- Required modules (auto-installed if missing):
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Beta.Identity.SignIns`
  - `Microsoft.Graph.Identity.DirectoryManagement`

## Required Permissions (Graph API Scopes)
```
User.Read.All
Directory.Read.All
UserAuthenticationMethod.Read.All
AuditLog.Read.All
```

## Usage

### 1. Connect to Microsoft Graph
```powershell
Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All","UserAuthenticationMethod.Read.All","AuditLog.Read.All" -NoWelcome
```

### 2. Run the report
```powershell
# Console summary only
.\Get-EntraMFAReport.ps1

# Export interactive HTML report
.\Get-EntraMFAReport.ps1 -ExportToHtml

# Export CSV files
.\Get-EntraMFAReport.ps1 -ExportToCsv

# Export both HTML and CSV
.\Get-EntraMFAReport.ps1 -ExportAll

# Store results in variable for programmatic analysis
$results = .\Get-EntraMFAReport.ps1 -ReturnData
$results.Users | Where-Object { $_.RiskLevel -eq "Critical" }
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-ExportToCsv` | Switch | Export detailed user data and summary to CSV |
| `-ExportToHtml` | Switch | Generate self-contained interactive HTML report |
| `-ExportAll` | Switch | Export both CSV and HTML |
| `-ReturnData` | Switch | Return data objects for programmatic use |
| `-LogDirectory` | String | Log file directory (default: `.\Logs`) |

## Output Files

| File | Description |
|------|-------------|
| `exports/MFADetailedReport-{timestamp}.csv` | All users with MFA details, risk levels, categories |
| `exports/MFASummaryReport-{timestamp}.csv` | Aggregated statistics |
| `exports/MFAReport-{tenant}-{timestamp}.html` | Interactive HTML report |
| `Logs/Get-EntraMFAReport-{timestamp}.log` | Execution log |

## HTML Report Features
The HTML report is a single self-contained file that works offline in any modern browser.

**Dashboard**: Total accounts, MFA percentage, risk level counts at a glance.

**Filters**:
- Text search (name/UPN)
- Risk Level: Critical / High / Medium / Low / N/A
- MFA Status: Enabled / Disabled / Unknown
- User Type: Member / Guest
- Account Category: User / Room / Shared Mailbox / Equipment
- Account Status: Enabled / Disabled
- Is Admin: Yes / No
- Licensed: Yes / No
- Last Sign-In: Active (30d) / Inactive 30+ days / Inactive 90+ days / Never
- MFA Method chips: click to filter by specific methods

**Table**: Sortable columns, color-coded risk levels, responsive layout.

## Data Analysis Examples
```powershell
$results = .\Get-EntraMFAReport.ps1 -ReturnData

# Critical risk accounts (enabled, no MFA)
$results.Users | Where-Object { $_.RiskLevel -eq "Critical" } | Select-Object user, upn, accountCategory

# Admins without phishing-resistant MFA
$results.Users | Where-Object { $_.isAdmin -and $_.RiskLevel -ne "Low" } | Select-Object user, RiskLevel, RiskNotes

# Inactive accounts still enabled (90+ days)
$results.Users | Where-Object { $_.enabled -and $_.lastSignIn -and ((Get-Date) - [datetime]$_.lastSignIn).Days -gt 90 }

# Room accounts that are enabled without MFA
$results.Users | Where-Object { $_.accountCategory -eq "Room" -and $_.enabled -and $_.MFAstatus -eq "disabled" }

# Guest accounts breakdown
$results.Users | Where-Object { $_.usertype -eq "Guest" } | Group-Object RiskLevel | Select-Object Name, Count
```

## Security Considerations
- Script requires **read-only** permissions — no modifications are made to the tenant
- No credentials or tokens are stored or exported
- HTML report contains user display names and UPNs — handle as sensitive data
- Log files may contain UPNs — manage log retention appropriately

## Author
Per-Torben Sørensen

## Version
2.0 — June 2026
