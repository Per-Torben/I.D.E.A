# I.D.E.A.
A curated collection of small, practical **Identity Engineering Artifacts** (I.D.E.A.) for Entra and identity security.  
Each artifact is a self‑contained script with clear documentation, secure defaults, and real‑world usefulness.

## Repository Structure
Each I.D.E.A. is organized in its own folder and includes:
- One or more PowerShell scripts
- A dedicated README.md with usage examples
- Documentation of prerequisites and security considerations

## Available I.D.E.A.s

### [I.D.E.A. 001 – Break‑Glass Emergency Access Accounts](IDEA-001-BreakGlass/)
Interactive, menu‑driven tool for creating and configuring break‑glass emergency access accounts in Microsoft Entra ID.  
Break‑glass accounts provide guaranteed administrative access when normal access paths fail or are blocked by Conditional Access.

**Key Capabilities**
- Settings menu for account count, FIDO2 keys, and naming conventions  
- Detects existing break‑glass accounts or creates new ones  
- Registers FIDO2 security keys for passwordless MFA  
- Automatically excludes accounts from all Conditional Access policies  
- Assigns Global Administrator role with validation  
- Adds accounts to Restricted Management Administrative Units (RMAU)  

**Use Case:** Prevents tenant lockout by ensuring at least one reliable administrative access path bypasses all Conditional Access restrictions.

📖 **[Full Documentation](IDEA-001-BreakGlass/README.md)**

---

### [I.D.E.A. 002 – Privileged Account Security Audit](IDEA-002-FindAllAdmins/)
Comprehensive security audit tool that discovers **administrative privilege assignments and paths** in Entra ID and performs automated risk assessment.  
Resolves complex PIM chains, nested groups, and group eligibility scenarios to provide visibility into privileged access.

**Key Capabilities**
- Discovers privilege paths: direct roles, PIM eligible, group-based, and complex multi-level PIM chains
- Automated security risk assessment based on MFA strength and RMAU protection
- Resolves 3+ level PIM chains (groups eligible for groups that grant roles)
- Complete nested group resolution with circular reference prevention
- Deduplication logic prevents counting same permission multiple times
- Includes service principals with administrative roles
- Detailed MFA method analysis (FIDO2, Authenticator, Phone/SMS detection)
- Checks Restricted Administrative Unit (RMAU) protection status
- Exports to CSV: RoleDistribution and UserStatus reports

**Security Risk Levels**
- 🚨 **CRITICAL**: No MFA enabled (immediate action required)
- 🚨 **HIGH**: Phone/SMS MFA + No RMAU (SIM swap vulnerable + lateral movement risk)
- ⚠️ **MEDIUM**: Single weakness (phone MFA with RMAU OR strong MFA without RMAU)
- ✅ **LOW**: Fully secured (strong MFA + RMAU protected)

**Use Case:** Complete privileged access inventory with automated security scoring. Identifies high-risk admin accounts requiring immediate MFA upgrades or RMAU protection. Essential for compliance reporting, security audits, and zero-trust implementation.

📖 **[Full Documentation](IDEA-002-FindAllAdmins/README.md)**

---

### [I.D.E.A. 003 – M365 Certificate App Registration](IDEA-003-CertAppRegistration/)
Interactive, menu-driven tool that creates Microsoft Entra ID app registrations with **certificate-based authentication** for one or more M365 services — and generates ready-to-use PowerShell connection scripts for each.

**Key Capabilities**
- Service selection menu: Microsoft Graph / Entra ID, Microsoft Teams, Exchange Online, SharePoint Online (single or all)
- Certificate menu: create new self-signed (4096-bit RSA, configurable duration, default 180 days) or use an existing `.cer` file
- Per-service permission review with toggle menu — defaults are minimal/read-only, optional extras can be enabled
- App name prefix prompt with full preview table of app names and output file names before creating
- Creates one app registration per service, attaches shared certificate, grants admin consent
- Automatically assigns Teams Administrator and Exchange Administrator roles to respective apps
- Generates service-specific connection `.ps1` scripts and a unified config JSON in `.\exports\`

**Generated Files (per prefix)**
- `{Prefix}-Connect-MicrosoftGraph.ps1` — `Connect-MgGraph` with cert params filled in
- `{Prefix}-Connect-MicrosoftTeams.ps1` — `Connect-MicrosoftTeams` with cert params filled in
- `{Prefix}-Connect-ExchangeOnline.ps1` — `Connect-ExchangeOnline` with cert params filled in
- `{Prefix}-Connect-SharePointOnline.ps1` — `Connect-PnPOnline` with cert params filled in
- `{Prefix}-Config.json` — all ClientIds, TenantId and thumbprint in one file

**Use Case:** Eliminates the manual, repetitive work of setting up multiple app registrations for certificate-based PowerShell automation across M365 services. Produces connection scripts that are ready to use immediately after the script completes.

📖 **[Full Documentation](IDEA-003-CertAppRegistration/README.md)**

---

## Getting Started
1. Browse the I.D.E.A. folders above  
2. Read the specific README.md for prerequisites and usage  
3. Run scripts with appropriate permissions  
4. Follow the security best practices included in each artifact  

## Prerequisites
- PowerShell 7.0 or later  
- Microsoft Graph PowerShell SDK  
- Appropriate permissions in Microsoft Entra ID  

## Contributing
Each I.D.E.A. is developed with security and practical utility in mind. Scripts include:
- Comprehensive error handling  
- Detailed logging and validation  
- Interactive menu‑driven configuration  
- Secure defaults and best‑practice implementations  

## Author
Per‑Torben Sørensen with contributions from GitHub Copilot

## License
Use at your own risk. Review and test thoroughly before production use.
