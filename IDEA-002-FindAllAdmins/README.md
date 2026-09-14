# I.D.E.A. 002 – Privileged Account Security Audit

## Overview
Comprehensive security audit tool that discovers **administrative privilege assignments and paths** in Entra ID and performs automated risk assessment based on MFA strength and RMAU protection. Goes beyond simple role enumeration to resolve complex PIM chains, nested groups, and group eligibility scenarios that traditional tools miss. Related blogpost: https://agderinthe.cloud/2026/02/19/i-d-e-a-002-will-the-real-admin-please-stand-up/

## Scripts in This I.D.E.A.

### `Create-PrivilegedAccountReportApp.ps1`
Helper script to create the required app registration with certificate-based authentication and proper Graph API permissions. **Run this first** before using the report script.

### `Get-PrivilegedAccountReport.ps1`
Main audit script - complete privileged account discovery with automated security risk assessment.

**What It Discovers**
- ✅ **Direct Role Assignments** – Active/permanent administrative roles
- ✅ **PIM Eligible Roles** – Users who can activate privileges on-demand
- ✅ **Group-Based Roles** – Privileges inherited through role-assignable groups
- ✅ **Complex PIM Chains** – Groups eligible to activate membership in other groups that grant roles (3+ levels deep)
- ✅ **Complete Nested Groups** – Full resolution of group membership chains
- ✅ **Service Principals** – Non-human identities with administrative roles
- ✅ **MFA Methods** – Detailed authentication methods for each privileged user
- ✅ **RMAU Protection** – Restricted Administrative Unit membership status

**Automated Risk Assessment**
Each privileged user receives a risk level:
- 🚨 **CRITICAL**: No MFA enabled (immediate action required)
- 🚨 **HIGH**: Phone/SMS MFA + No RMAU (vulnerable to SIM swapping + lateral movement)
- ⚠️ **MEDIUM**: Single weakness (phone MFA with RMAU OR strong MFA without RMAU)
- ✅ **LOW**: Fully secured (strong MFA + RMAU protected)

**Why Use This Tool**
- Identifies **complex privilege paths** including multi-level PIM chains that other tools miss
- **Automated risk scoring** eliminates manual security assessment
- **Deduplication logic** prevents counting the same permission multiple times
- **CSV exports** for compliance reporting and tracking remediation progress
- **Service principal inclusion** covers non-human admin accounts

## Prerequisites

### Required Modules
- Microsoft Graph PowerShell SDK (automatically installed if missing)
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Identity.SignIns`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Groups`
  - `Microsoft.Graph.Identity.DirectoryManagement`

### Graph API Permissions
The script requires read-only permissions:
- `User.Read.All` – Read user profiles
- `Directory.Read.All` – Read directory data
- `RoleManagement.Read.Directory` – Read role assignments
- `RoleEligibilitySchedule.Read.Directory` – Read PIM eligible assignments
- `UserAuthenticationMethod.Read.All` – Read MFA methods
- `PrivilegedAccess.Read.AzureADGroup` – Read PIM group eligibility
- `Policy.Read.All` – Read cross-tenant access settings
- `CrossTenantInformation.ReadBasic.All` – Resolve a guest's home tenant

### Cross-tenant inbound MFA trust

A privileged B2B guest performs MFA in their home tenant, so their authentication methods are not visible here and they are reported as having no MFA. The script reads the cross-tenant access policy and adds `MFATrust` and `HomeTenant` columns to the user status CSV. When inbound MFA trust is enabled for the guest's home tenant, the risk level is downgraded from `Critical (No MFA)` to `Medium (Home tenant MFA trusted)`. Without `Policy.Read.All` the report still runs and MFA trust shows as `Unknown`.

## Quick Start

### Step 1: Create App Registration (One-Time Setup)
```powershell
# Run the helper script to create required app registration
.\Create-PrivilegedAccountReportApp.ps1
```

This creates a certificate-based app registration with all required permissions and saves connection details.

**Important**: Run this script on the same machine where you plan to run the main report script. It creates a self-signed certificate stored in the local computer's certificate store for authentication. If you need to run the report from a different machine, you can either:
- Export and import the certificate to the target machine
- Configure alternative authentication methods (interactive auth using `-UseInteractiveAuth`, client secrets, etc.)

### Step 2: Run the Report
```powershell
# Establish Graph connection (follow your tenant's authentication method)
# Then run the report:
.\Get-PrivilegedAccountReport.ps1
```

**Note**: The script assumes an active Microsoft Graph connection. Use certificate-based authentication (recommended) or the `-UseInteractiveAuth` parameter.

## Usage

### Certificate-Based Authentication (Recommended)
```powershell
# After running Create-PrivilegedAccountReportApp.ps1, use the connection details
# to establish authentication, then run:
.\Get-PrivilegedAccountReport.ps1
```

### Interactive Authentication
```powershell
# Connect and run in one step using interactive auth
.\Get-PrivilegedAccountReport.ps1 -UseInteractiveAuth
```

### Basic Report (Display Only)
```powershell
# Shows on-screen summary with risk statistics
.\Get-PrivilegedAccountReport.ps1
```

### Export to CSV
```powershell
# After running, you'll be prompted to export to CSV
# Two files are created in the exports/ subfolder:
# - RoleDistribution-[timestamp].csv (roles/groups with counts)
# - UserStatus-[timestamp].csv (detailed per-user report)
```

### Return Data for Further Processing
```powershell
# Capture results in variables for automation
$results = .\Get-PrivilegedAccountReport.ps1 -ReturnData

# Access the data
$results.PrivilegedUsers      # Hashtable of all privileged users
$results.RoleDistribution     # Role/group assignment statistics
$results.Statistics           # Summary counts and risk stats
```

## Output

### On-Screen Report
The script displays:
1. **Connection Summary** – Authentication status and permissions verification
2. **Role Discovery Statistics** – Counts of roles, groups, assignments by type
3. **Privileged Users Details** – Per-user breakdown showing:
   - All role assignments with assignment type (Active, PIM Eligible, Group-Based, PIM Group Eligible)
   - Complete privilege paths (e.g., "User → Group A → PIM Group B → Role")
   - MFA methods and counts
   - Phone MFA detection
   - RMAU protection status and AU name
   - Calculated risk level
4. **Risk Assessment Summary** – Counts by risk level with percentages
5. **Role Distribution** – Top roles/groups by assignment count

### CSV Exports (exports/ subfolder)

#### RoleDistribution-[timestamp].csv
Role and group statistics:
- **RoleOrGroupName**: Display name of role or group
- **RoleId**: Unique identifier
- **Type**: "Role" or "PIM Group"
- **ActiveAssignments**: Count of active/permanent assignments
- **EligibleAssignments**: Count of PIM eligible assignments
- **GroupBasedAssignments**: Count via group membership
- **PIMGroupEligible**: Count eligible to activate group membership
- **TotalUniqueUsers**: Unique user count (deduplicated)

#### UserStatus-[timestamp].csv
Per-user detailed report:
- **PrincipalType**: "User" or "Service Principal"
- **UserPrincipalName**: Login name
- **DisplayName**: Full name
- **UserId**: Unique identifier
- **AccountEnabled**: "Enabled" or "Disabled"
- **RoleName**: Administrative role name
- **RoleId**: Role identifier
- **AssignmentType**: "Active", "PIM Eligible", "Group-Based", "PIM Group Eligible"
- **GroupName**: Group providing privilege (if applicable)
- **GroupId**: Group identifier
- **MFAEnabled**: "Yes", "No", or "N/A" (service principals)
- **MFAMethods**: Comma-separated list of registered methods
- **MethodCount**: Number of MFA methods
- **HasPhoneMFA**: "Yes" or "No"
- **AUProtected**: "Yes" or "No" (RMAU membership)
- **AUName**: Name of Restricted AU (if protected)
- **RiskLevel**: "Critical (No MFA)", "High (Phone MFA + No AU)", "Medium (MFA, No AU)", "Medium (Phone MFA, Has AU)", "Low (Secure)", or "N/A"

## Understanding Risk Levels

### Why Phone MFA is Risky
Phone/SMS-based MFA is vulnerable to:
- SIM swapping attacks (social engineering at mobile carriers)
- SMS interception
- Number porting attacks

Strong MFA methods (FIDO2, Microsoft Authenticator push, Windows Hello) are resistant to these attacks.

### Why RMAU Protection Matters
Restricted Administrative Units prevent:
- Lateral movement between admin accounts
- Privilege escalation attacks
- Unauthorized scope expansion

When privileged accounts are in RMAUs, only specific administrators can modify them.

### Combined Risk Assessment
| MFA Method | RMAU Protected | Risk Level | Rationale |
|------------|----------------|------------|-----------|
| None | No | 🚨 CRITICAL | No authentication protection |
| Phone/SMS | No | 🚨 HIGH | Vulnerable to SIM swap + lateral movement |
| Phone/SMS | Yes | ⚠️ MEDIUM | RMAU protects from escalation, but MFA is weak |
| Strong | No | ⚠️ MEDIUM | Good MFA, but no containment of privileges |
| Strong | Yes | ✅ LOW | Fully secured with strong auth + privilege containment |

## Complex Privilege Path Examples

### Scenario 1: Direct PIM Eligible
```
User → [PIM Eligible] → Global Administrator
```
User can activate Global Administrator role directly.

### Scenario 2: Group-Based Active
```
User → Group Membership → PIM-GlobalAdmins → Global Administrator
```
User has active membership in a role-assignable group.

### Scenario 3: PIM Group Eligible (2 levels)
```
User → [PIM Eligible Member] → PIM-GlobalAdmins → Global Administrator
```
User can activate membership in a group that grants Global Administrator.

### Scenario 4: Complex PIM Chain (3+ levels)
```
User → [PIM Eligible] → Group A → [PIM Eligible] → Group B → User Administrator
```
User is eligible to activate membership in Group A, which is itself eligible to activate membership in Group B, which grants the User Administrator role.

**This tool resolves all these scenarios automatically.**

## Deduplication Logic

The script prevents duplicate reporting when the same permission is accessible through multiple paths:
1. **Same Role via Different Paths**: If PIM eligibility exists, active group membership for the same role is not reported separately
2. **Redundant Group Membership**: "PIM Group Active Member" is filtered when the group actually grants specific roles
3. **Multi-level Chains**: Each unique permission path is reported once, even if it involves multiple groups

## Security Considerations

**Immediate Actions Required**
- 🚨 **Critical Risk Users**: Enable MFA immediately
- 🚨 **High Risk Users**: Replace phone MFA with FIDO2/Authenticator and add to RMAU

**Best Practices**
- Run this report monthly to track security improvements
- Export CSVs for compliance documentation and trend analysis
- Focus remediation on Critical and High risk users first
- Use RMAU protection for all Tier 0 administrators
- Require FIDO2 keys for Global Administrators and Privileged Role Administrators
- Review PIM eligible assignments for appropriate business justification

## Troubleshooting

### Permission Errors
If you see permission-related errors, verify the app registration has all required permissions and admin consent has been granted.

### MFA Methods Show "N/A"
Requires `UserAuthenticationMethod.Read.All` permission. Without it, MFA assessment cannot be performed.

### No RMAU Data
Users not in any Restricted Administrative Unit will show "No" for AUProtected. Consider creating RMAUs for high-privilege accounts.

### Long Execution Time
For large tenants with thousands of users and complex group structures, the script may take 5-10 minutes. Progress is logged to console.

## Files and Folders

```
IDEA-002-FindAllAdmins/
├── Get-PrivilegedAccountReport.ps1       # Main script
├── Create-PrivilegedAccountReportApp.ps1 # Helper for app registration
├── README.md                             # This file
├── Logs/                                 # Execution logs (auto-created)
└── exports/                              # CSV exports (auto-created)
    ├── RoleDistribution-[timestamp].csv
    └── UserStatus-[timestamp].csv
```

## Author
Per-Torben Sørensen

## Version
1.0

## Last Updated
February 17, 2026
