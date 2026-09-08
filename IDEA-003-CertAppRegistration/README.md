# I.D.E.A. 003 – M365 Certificate App Registration

Interactive, menu-driven tool that creates Microsoft Entra ID app registrations with certificate-based authentication for one or more M365 services — and generates ready-to-use connection scripts for each.

## Overview

Connecting PowerShell non-interactively to M365 services requires app registrations with certificate authentication. Setting these up manually is repetitive and error-prone. This tool automates the entire process in a single guided session.

The script registers one app per selected service, attaches a shared certificate, assigns the correct API permissions with admin consent, grants the required administrative access (Teams, and a choice of view-only or full for Exchange), and exports ready-to-use `.ps1` connection scripts.

## Supported Services

| # | Service | Module | Access Granted |
|---|---------|--------|----------------|
| 1 | Microsoft Graph / Entra ID | `Microsoft.Graph.Authentication` | — |
| 2 | Microsoft Teams | `MicrosoftTeams` | Teams Administrator |
| 3 | Exchange Online | `ExchangeOnlineManagement` | **Choice:** view-only (default) or full — see below |
| 4 | SharePoint Online | `PnP.PowerShell` | — |

## Prerequisites

- **PowerShell 7.0 or later** — required, not merely recommended. The Graph SDK isolates its
  dependencies in a private assembly load context (`msgraph-load-context`), which lets its MSAL
  version coexist with the different MSAL version the Exchange module loads. Windows PowerShell 5.1
  has no such isolation and hits assembly conflicts between the two modules.
- **Microsoft Graph PowerShell SDK** — auto-installed if missing (`Microsoft.Graph.Authentication`, `Microsoft.Graph.Applications`)
- **`ExchangeOnlineManagement`** — auto-installed if missing, but only when Exchange Online is selected with view-only access
- **Entra ID role:** Global Administrator, or Application Administrator + Privileged Role Administrator
- Internet access to Microsoft Graph

## Usage

```powershell
.\New-M365CertAppRegistration.ps1
```

The script is fully interactive — no parameters required.

## Step-by-Step Flow

### Step 1 — Select Services

Choose one or more services to register (comma-separated), e.g.:

```
[1]  Microsoft Graph / Entra ID
[2]  Microsoft Teams
[3]  Exchange Online
[4]  SharePoint Online
[A]  All services
[Q]  Quit

Your selection: 1,3
```

### Step 2 — Certificate

```
[1]  Create new self-signed certificate (4096-bit RSA, default 180 days)
[2]  Use existing .cer file
```

**Option 1 — New self-signed:**
- Prompted for certificate name (default: `PSAppCert-{Prefix}-{date}`)
- Prompted for validity in days (default: **180 days**)
- Creates 4096-bit RSA / SHA256 certificate in `Cert:\CurrentUser\My`
- Exports the public key (`.cer`) to `.\exports\`

**Option 2 — Existing certificate:**
- Prompted for path to `.cer` file
- Displays subject, thumbprint, validity dates
- Warns if certificate is expired (user can proceed or cancel)

> **Note:** One certificate is shared across all selected services. This is supported by Entra ID — a single certificate can be attached to multiple app registrations.

### Step 3 — Review Permissions

For each selected service, a numbered permission list is shown. Default permissions are pre-selected. Optional permissions can be toggled on/off:

```
  [A] Accept   [R] Reset to defaults   [number] Toggle permission
```

#### Default Permissions per Service

**Microsoft Graph / Entra ID** (minimal read-only defaults):
| Permission | Description |
|---|---|
| `User.Read.All` | Read all users |
| `Directory.Read.All` | Read directory data |

Optional extras include write permissions and policy management scopes.

**Microsoft Teams** (all required for app-only Teams management):
| Permission | Description |
|---|---|
| `Organization.Read.All` | Read organization info |
| `User.Read.All` | Read all users |
| `Group.ReadWrite.All` | Read and write all groups |
| `AppCatalog.ReadWrite.All` | Manage Teams app catalog |
| `TeamSettings.ReadWrite.All` | Manage team settings |
| `Channel.Delete.All` | Delete Teams channels |
| `ChannelSettings.ReadWrite.All` | Manage channel settings |
| `ChannelMember.ReadWrite.All` | Manage channel members |

**Exchange Online:**
| Permission | Description |
|---|---|
| `Exchange.ManageAsApp` | Required app-only permission — does **not** by itself define the access level |

> `Exchange.ManageAsApp` is the only application permission available for Exchange app-only auth, and it does not distinguish read from write. The effective access level is decided separately in Step 3b.

**SharePoint Online (via PnP):**
| Permission | Description |
|---|---|
| `Sites.FullControl.All` | Full control of all site collections |

### Step 3b — Exchange Access Level

Shown only when Exchange Online is selected:

```
[1]  View-only — 'View-Only Organization Management' role group (default)
     Read-only, scoped to Exchange only. Requires an extra Exchange sign-in.
[2]  Full      — Exchange Administrator directory role
     Full Exchange management access.
```

| | View-only (default) | Full |
|---|---|---|
| Mechanism | `New-ServicePrincipal` + `Add-RoleGroupMember` | Entra directory role assignment |
| Grants | `View-Only Organization Management` role group | `Exchange Administrator` |
| Scope | Exchange only | Exchange, plus minor non-Exchange rights |
| Extra sign-in | **Yes** — interactive Exchange Online sign-in mid-run | No |
| Visible in Entra "Roles & admins" | No | Yes |

**Why the two paths differ.** Exchange surfaces directory-role holders inside its own RBAC through auto-maintained linked groups. `Exchange Administrator` lands in `ExchangeServiceAdmins_*`, which is itself a member of the `Organization Management` role group — so the app inherits exactly those permissions without being a literal member. Likewise `Global Reader` maps into `View-Only Organization Management`, meaning Global Reader and the role group grant *identical* Exchange permissions.

The view-only path deliberately uses the role group rather than `Global Reader`, because `Global Reader` would also grant read access across the rest of M365.

The full path deliberately uses the directory role rather than `Organization Management` membership, because directory role assignments are discoverable by tenant-wide privileged access reporting (including [IDEA-002](../IDEA-002-FindAllAdmins/README.md), which enumerates directory roles only). An app hidden inside Exchange RBAC would be an audit blind spot.

> **Unattended runs:** choosing view-only requires a second interactive browser sign-in, so that path cannot run unattended.

### Step 4 — App Naming

Enter a prefix (default: `M365-PS`). A preview table of all names and output files is shown before confirming:

```
App Registrations (in Entra ID):
  • Contoso-PS-MicrosoftGraph
  • Contoso-PS-ExchangeOnline

Connection Scripts (in .\exports\):
  • Contoso-PS-Connect-MicrosoftGraph.ps1
  • Contoso-PS-Connect-ExchangeOnline.ps1

Config JSON: Contoso-PS-Config.json
```

### Step 5 — Confirm & Create

A full summary is displayed — app names, permissions per service, and output file names. Confirm with Y to proceed.

The script then:
1. Connects interactively to Microsoft Graph (browser sign-in)
2. Derives the `onmicrosoft.com` domain and SharePoint admin URL from the tenant
3. Creates each app registration, attaches the certificate, assigns permissions and consent
4. Assigns the Teams admin role, and applies the chosen Exchange access level — prompting for a
   second Exchange Online sign-in if view-only was selected
5. Generates all connection scripts
6. Writes the config JSON

## Generated Output Files

All files are written to `.\exports\`:

| File | Description |
|---|---|
| `{Prefix}-Connect-MicrosoftGraph.ps1` | Connects with `Connect-MgGraph` |
| `{Prefix}-Connect-MicrosoftTeams.ps1` | Connects with `Connect-MicrosoftTeams` |
| `{Prefix}-Connect-ExchangeOnline.ps1` | Connects with `Connect-ExchangeOnline` |
| `{Prefix}-Connect-SharePointOnline.ps1` | Connects with `Connect-PnPOnline` |
| `{Prefix}-Config.json` | ClientIds, TenantId, thumbprint for all services |
| `{CertName}.cer` | Public key of self-signed certificate (if created) |

### Example: `Contoso-PS-Connect-ExchangeOnline.ps1`

```powershell
$ExchangeConnectionParams = @{
    Organization          = 'contoso.onmicrosoft.com'
    AppId                 = '<ClientId>'
    CertificateThumbPrint = '<Thumbprint>'
}
Connect-ExchangeOnline @ExchangeConnectionParams
```

### Example: `Contoso-PS-Config.json`

```json
{
  "Prefix": "Contoso-PS",
  "TenantId": "<guid>",
  "Certificate": { "Thumbprint": "<thumbprint>" },
  "Applications": {
    "MicrosoftGraph": { "ClientId": "...", "ConnectScript": "Contoso-PS-Connect-MicrosoftGraph.ps1" },
    "ExchangeOnline": { "ClientId": "...", "ConnectScript": "Contoso-PS-Connect-ExchangeOnline.ps1" }
  }
}
```

## After Running the Script

1. **Verify the certificate is installed with its private key:**
   ```powershell
   gci Cert:\CurrentUser\My | where Thumbprint -eq '<thumbprint>' | select Thumbprint, Subject, HasPrivateKey
   ```
   Result must show `HasPrivateKey: True`. If using an existing `.cer`, you need the corresponding `.pfx` installed — see [importing a PFX certificate](https://learn.microsoft.com/en-us/dotnet/framework/wcf/feature-details/how-to-create-temporary-certificates-for-use-during-development).

2. **Test a connection:**
   ```powershell
   .\exports\Contoso-PS-Connect-MicrosoftGraph.ps1
   Get-MgContext
   ```

3. **Verify the granted access:**

   *Teams, and Exchange with full access* — Entra portal → **Roles & admins** → search for
   `Teams Administrator` or `Exchange Administrator` → confirm the app is listed.

   *Exchange with view-only* — the app will **not** appear under Roles & admins. Verify in Exchange instead:
   ```powershell
   Connect-ExchangeOnline -Organization '<tenant>.onmicrosoft.com'
   Get-RoleGroupMember -Identity 'View-Only Organization Management'
   ```
   The app's service principal object ID should be listed with `RecipientType: User`.

> Role and role group assignments can take a few minutes to take effect. If a connection is denied immediately after running the script, wait and retry before troubleshooting.

## Security Considerations

- **Certificate storage:** The private key must remain in `Cert:\CurrentUser\My` on the machine running scripts. Never share `.pfx` files unsecured.
- **Certificate duration:** The default is 180 days. Implement a renewal process before expiry.
- **Permissions:** Start with the minimal defaults and only add extra permissions your use case requires.
- **Exchange access level:** View-only is the default and should stay the default. Only choose full
  Exchange access when the automation genuinely writes to Exchange — it is equivalent to the
  `Organization Management` role group.
- **Admin roles:** Teams Administrator and Exchange Administrator are powerful roles. Only assign them when automation requires it.
- **PIM does not help here:** service principals cannot perform interactive PIM activation, so both
  the directory role and the role group grant standing access. Review these apps periodically.
- **One certificate, multiple apps:** Using the same certificate across multiple app registrations is supported and simplifies management — one renewal updates all apps.
- **Logs:** `.\Logs\` contains execution logs. Review after each run. Logs are not pushed to the repository.

## Troubleshooting

| Issue | Resolution |
|---|---|
| `Certificate private key not found` | Run the connect script as the same user who created/installed the cert |
| `Teams cmdlet not supported for app-only` | Check [supported cmdlets](https://learn.microsoft.com/en-us/microsoftteams/teams-powershell-application-authentication#cmdlets-supported) |
| `Exchange admin role not assigned` | Assign manually: Entra portal → Roles & admins → Exchange Administrator → Add assignments |
| Exchange view-only assignment failed | The log prints the exact `New-ServicePrincipal` and `Add-RoleGroupMember` commands to run manually after `Connect-ExchangeOnline` |
| `The "..." management role can't be found` | Role *groups* are not valid for `New-ManagementRoleAssignment -App`; that cmdlet only accepts `Application *` mailbox-data roles. Use role group membership or a directory role instead |
| Exchange cmdlets return access denied despite assignment | Assignments take a few minutes to propagate; also confirm the app is not relying on a cached token |
| `Could not load file or assembly 'Microsoft.Identity.Client'` | You are on Windows PowerShell 5.1 — rerun in PowerShell 7 |
| `Could not grant consent` | Grant manually: Entra portal → App registrations → {AppName} → API permissions → Grant admin consent |
| `onmicrosoft.com domain not found` | Ensure a verified `.onmicrosoft.com` domain exists on the tenant |

## File Structure

```
IDEA-003-CertAppRegistration/
├── New-M365CertAppRegistration.ps1   # Main script
├── README.md
├── exports/                          # Generated files (gitignored)
│   ├── {Prefix}-Connect-*.ps1
│   ├── {Prefix}-Config.json
│   └── {CertName}.cer
└── Logs/                             # Execution logs (gitignored)
```

## Reference

- [Blog post: Connect PowerShell to M365 using Certificate-based Authentication](https://agderinthe.cloud/2024/04/09/how-to-connect-powershell-to-various-m365-services-using-certificate-based-authentication/)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
- [Teams PowerShell app-only auth](https://learn.microsoft.com/en-us/microsoftteams/teams-powershell-application-authentication)
- [Exchange app-only auth](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2)
- [Exchange Online role groups](https://learn.microsoft.com/en-us/exchange/permissions-exo/role-groups)
- [RBAC for Applications in Exchange Online](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)
- [PnP PowerShell](https://pnp.github.io/powershell/)
- [Self-signed certificates for app auth](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-self-signed-certificate)

## Author

Per-Torben Sørensen  
Version: 1.1 | September 2026
