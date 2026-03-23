# I.D.E.A. 003 – M365 Certificate App Registration

Interactive, menu-driven tool that creates Microsoft Entra ID app registrations with certificate-based authentication for one or more M365 services — and generates ready-to-use connection scripts for each.

## Overview

Connecting PowerShell non-interactively to M365 services requires app registrations with certificate authentication. Setting these up manually is repetitive and error-prone. This tool automates the entire process in a single guided session.

The script registers one app per selected service, attaches a shared certificate, assigns the correct API permissions with admin consent, assigns required admin roles (Teams/Exchange), and exports ready-to-use `.ps1` connection scripts.

## Supported Services

| # | Service | Module | Admin Role Assigned |
|---|---------|--------|---------------------|
| 1 | Microsoft Graph / Entra ID | `Microsoft.Graph.Authentication` | — |
| 2 | Microsoft Teams | `MicrosoftTeams` | Teams Administrator |
| 3 | Exchange Online | `ExchangeOnlineManagement` | Exchange Administrator |
| 4 | SharePoint Online | `PnP.PowerShell` | — |

## Prerequisites

- **PowerShell 7.0 or later**
- **Microsoft Graph PowerShell SDK** — auto-installed if missing (`Microsoft.Graph.Authentication`, `Microsoft.Graph.Applications`)
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
| `Exchange.ManageAsApp` | Full Exchange Online app-only access |

**SharePoint Online (via PnP):**
| Permission | Description |
|---|---|
| `Sites.FullControl.All` | Full control of all site collections |

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
4. Assigns admin roles for Teams and Exchange
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

3. **For Teams and Exchange:** Verify the admin role assignment in the Entra portal before connecting:
   - Entra portal → **Roles & admins** → search for `Teams Administrator` or `Exchange Administrator` → confirm the app is listed

## Security Considerations

- **Certificate storage:** The private key must remain in `Cert:\CurrentUser\My` on the machine running scripts. Never share `.pfx` files unsecured.
- **Certificate duration:** The default is 180 days. Implement a renewal process before expiry.
- **Permissions:** Start with the minimal defaults and only add extra permissions your use case requires.
- **Admin roles:** Teams Administrator and Exchange Administrator are powerful roles. Only assign them when automation requires it.
- **One certificate, multiple apps:** Using the same certificate across multiple app registrations is supported and simplifies management — one renewal updates all apps.
- **Logs:** `.\Logs\` contains execution logs. Review after each run. Logs are not pushed to the repository.

## Troubleshooting

| Issue | Resolution |
|---|---|
| `Certificate private key not found` | Run the connect script as the same user who created/installed the cert |
| `Teams cmdlet not supported for app-only` | Check [supported cmdlets](https://learn.microsoft.com/en-us/microsoftteams/teams-powershell-application-authentication#cmdlets-supported) |
| `Exchange admin role not assigned` | Assign manually: Entra portal → Roles & admins → Exchange Administrator → Add assignments |
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
- [PnP PowerShell](https://pnp.github.io/powershell/)
- [Self-signed certificates for app auth](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-self-signed-certificate)

## Author

Per-Torben Sørensen  
Version: 1.0 | March 2026
