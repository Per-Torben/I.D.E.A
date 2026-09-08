#Requires -Version 7.0

<#
.SYNOPSIS
    Creates Entra ID app registrations with certificate authentication for M365 services.

.DESCRIPTION
    Interactive, menu-driven tool that creates one Entra ID application registration per
    selected M365 service:
      - Microsoft Graph / Entra ID
      - Microsoft Teams
      - Exchange Online
      - SharePoint Online (PnP.PowerShell)

    For each selected service the script:
      1. Creates an app registration and service principal in Entra ID
      2. Attaches a shared certificate (new self-signed or existing .cer file)
      3. Assigns required API permissions and grants admin consent
      4. Assigns required admin roles (Teams Administrator) and, for Exchange Online, the
         chosen access level: 'View-Only Organization Management' role group (view-only,
         default) or the Exchange Administrator directory role
      5. Exports a ready-to-use connection .ps1 script to .\exports\

    A config JSON file ({Prefix}-Config.json) is written to .\exports\ as a consolidated
    reference for everything created in the session. It contains the TenantId, certificate
    thumbprint, and the ClientId + connection script name for each registered service.

    Use cases for the config JSON:
      • Quick reference — look up any ClientId or thumbprint without opening the Entra portal
      • Script reuse   — other scripts can load it with ConvertFrom-Json to retrieve connection
                         parameters dynamically instead of hardcoding GUIDs
      • Onboarding     — share with a colleague so they know which app connects to which service
      • Certificate renewal — when the cert expires, the file shows exactly which apps to update

    App Registration names:
      {Prefix}-MicrosoftGraph
      {Prefix}-MicrosoftTeams
      {Prefix}-ExchangeOnline
      {Prefix}-SharePointOnline

    Generated connection scripts (in .\exports\):
      {Prefix}-Connect-MicrosoftGraph.ps1
      {Prefix}-Connect-MicrosoftTeams.ps1
      {Prefix}-Connect-ExchangeOnline.ps1
      {Prefix}-Connect-SharePointOnline.ps1

.NOTES
    Author  : Per-Torben Sørensen
    Version : 1.0
    Created : March 2026

    Prerequisites
    ─────────────
    • PowerShell 7.0 or later — required. The Graph SDK isolates its dependencies in a
      separate assembly load context, which lets it coexist with the Exchange Online
      module's different MSAL version. Windows PowerShell 5.1 has no such isolation.
    • Global Administrator or Privileged Role Administrator in Entra ID
    • Internet access to Microsoft Graph

.EXAMPLE
    .\New-M365CertAppRegistration.ps1
    Launches the interactive menu to select services and configure the registrations.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Module Installation ──────────────────────────────────────────────────
$requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications')

Write-Host ''
Write-Host '╔════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
Write-Host '║  Checking Required Modules                                 ║' -ForegroundColor Cyan
Write-Host '╚════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
Write-Host ''

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "  Installing $module ..." -ForegroundColor Yellow
        try {
            Install-Module $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Host "  ✓ Installed $module" -ForegroundColor Green
        }
        catch {
            Write-Host "  ✗ Failed to install $module : $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "  ✓ $module" -ForegroundColor Green
    }
}
Write-Host ''
#endregion

#region ── Directories & Logging ────────────────────────────────────────────────
$script:LogDir    = Join-Path $PSScriptRoot 'Logs'
$script:ExportDir = Join-Path $PSScriptRoot 'exports'

foreach ($dir in @($script:LogDir, $script:ExportDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

$script:LogFile = Join-Path $script:LogDir "New-M365CertAppRegistration-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
#endregion

#region ── Service Definitions ──────────────────────────────────────────────────
# Ordered hashtable preserves display order in menus.
$script:ServiceMap = [ordered]@{
    '1' = 'MicrosoftGraph'
    '2' = 'MicrosoftTeams'
    '3' = 'ExchangeOnline'
    '4' = 'SharePointOnline'
}

$script:ServiceDefinitions = @{
    MicrosoftGraph    = @{
        DisplayName   = 'Microsoft Graph / Entra ID'
        ResourceAppId = '00000003-0000-0000-c000-000000000000'
        Permissions   = @(
            @{ Name = 'User.Read.All';                       Type = 'Application'; Default = $true;  Description = 'Read all users'                     }
            @{ Name = 'Directory.Read.All';                  Type = 'Application'; Default = $true;  Description = 'Read directory data'                }
            @{ Name = 'User.ReadWrite.All';                  Type = 'Application'; Default = $false; Description = 'Read and write all users'           }
            @{ Name = 'Group.ReadWrite.All';                 Type = 'Application'; Default = $false; Description = 'Read and write all groups'          }
            @{ Name = 'Directory.ReadWrite.All';             Type = 'Application'; Default = $false; Description = 'Full directory read/write'          }
            @{ Name = 'Policy.Read.All';                     Type = 'Application'; Default = $false; Description = 'Read all policies'                  }
            @{ Name = 'Policy.ReadWrite.ConditionalAccess';  Type = 'Application'; Default = $false; Description = 'Manage Conditional Access policies' }
            @{ Name = 'AuditLog.Read.All';                   Type = 'Application'; Default = $false; Description = 'Read all audit logs'                }
            @{ Name = 'RoleManagement.Read.Directory';       Type = 'Application'; Default = $false; Description = 'Read role assignments'              }
            @{ Name = 'EntitlementManagement.ReadWrite.All'; Type = 'Application'; Default = $false; Description = 'Manage access packages'             }
        )
        AdminRoleId   = $null
        AdminRoleName = $null
        ConnectModule = 'Microsoft.Graph.Authentication'
    }
    MicrosoftTeams    = @{
        DisplayName   = 'Microsoft Teams'
        ResourceAppId = '00000003-0000-0000-c000-000000000000'
        Permissions   = @(
            @{ Name = 'Organization.Read.All';         Type = 'Application'; Default = $true;  Description = 'Read organization info'          }
            @{ Name = 'User.Read.All';                 Type = 'Application'; Default = $true;  Description = 'Read all users'                  }
            @{ Name = 'Group.ReadWrite.All';           Type = 'Application'; Default = $true;  Description = 'Read and write all groups'       }
            @{ Name = 'AppCatalog.ReadWrite.All';      Type = 'Application'; Default = $true;  Description = 'Manage Teams app catalog'        }
            @{ Name = 'TeamSettings.ReadWrite.All';    Type = 'Application'; Default = $true;  Description = 'Manage team settings'            }
            @{ Name = 'Channel.Delete.All';            Type = 'Application'; Default = $true;  Description = 'Delete Teams channels'           }
            @{ Name = 'ChannelSettings.ReadWrite.All'; Type = 'Application'; Default = $true;  Description = 'Manage channel settings'         }
            @{ Name = 'ChannelMember.ReadWrite.All';   Type = 'Application'; Default = $true;  Description = 'Manage channel members'          }
            @{ Name = 'TeamsActivity.Send';            Type = 'Application'; Default = $false; Description = 'Send Teams activity notifications' }
            @{ Name = 'Chat.ReadWrite.All';            Type = 'Application'; Default = $false; Description = 'Read and write all chats'         }
        )
        AdminRoleId   = '69091246-20e8-4a56-aa4d-066075b2a7a8'
        AdminRoleName = 'Teams Administrator'
        ConnectModule = 'MicrosoftTeams'
    }
    ExchangeOnline    = @{
        DisplayName   = 'Exchange Online'
        ResourceAppId = '00000002-0000-0ff1-ce00-000000000000'
        Permissions   = @(
            @{ Name = 'Exchange.ManageAsApp'; Type = 'Application'; Default = $true; Description = 'Required app-only permission (actual access is scoped by the directory role below)' }
        )
        # Access level for EXO PowerShell app-only auth is set by the Entra directory role
        # assigned to the service principal — chosen at runtime via Show-ExchangeAccessLevelMenu.
        AdminRoleId   = $null
        AdminRoleName = $null
        ConnectModule = 'ExchangeOnlineManagement'
    }
    SharePointOnline  = @{
        DisplayName   = 'SharePoint Online'
        ResourceAppId = '00000003-0000-0ff1-ce00-000000000000'
        Permissions   = @(
            @{ Name = 'Sites.FullControl.All'; Type = 'Application'; Default = $true;  Description = 'Full control of all site collections'      }
            @{ Name = 'Sites.ReadWrite.All';   Type = 'Application'; Default = $false; Description = 'Read and write all site collections'       }
            @{ Name = 'Sites.Manage.All';      Type = 'Application'; Default = $false; Description = 'Manage (not full control) site collections' }
        )
        AdminRoleId   = $null
        AdminRoleName = $null
        ConnectModule = 'PnP.PowerShell'
    }
}
#endregion

#region ── Functions ────────────────────────────────────────────────────────────

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry     = "[$timestamp] [$Level] $Message"

    if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $entry }

    switch ($Level) {
        'SUCCESS' { Write-Host $Message -ForegroundColor Green  }
        'WARNING' { Write-Host $Message -ForegroundColor Yellow }
        'ERROR'   { Write-Host $Message -ForegroundColor Red    }
        default   { Write-Host $Message -ForegroundColor White  }
    }
}


function Show-Banner {
    Clear-Host
    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║        I.D.E.A. 003 - M365 Certificate App Registration              ║' -ForegroundColor Cyan
    Write-Host '║                                                                      ║' -ForegroundColor Cyan
    Write-Host '║  Creates Entra ID app registrations with certificate authentication  ║' -ForegroundColor Cyan
    Write-Host '║  for Microsoft Graph, Teams, Exchange Online and SharePoint Online   ║' -ForegroundColor Cyan
    Write-Host '╚══════════════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
}


function Show-ServiceSelectionMenu {
    <#
    .SYNOPSIS
        Prompts the user to select one or more M365 services to register.
    .OUTPUTS
        [string[]] Array of selected service keys, e.g. @('MicrosoftGraph','MicrosoftTeams')
    #>
    param()

    Write-Host '  Select services to register (comma-separated, e.g. 1,3):' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '    [1]  Microsoft Graph / Entra ID' -ForegroundColor White
    Write-Host '    [2]  Microsoft Teams' -ForegroundColor White
    Write-Host '    [3]  Exchange Online' -ForegroundColor White
    Write-Host '    [4]  SharePoint Online (PnP.PowerShell)' -ForegroundColor White
    Write-Host '    [A]  All services' -ForegroundColor White
    Write-Host '    [Q]  Quit' -ForegroundColor White
    Write-Host ''

    while ($true) {
        Write-Host '  Your selection: ' -NoNewline -ForegroundColor Cyan
        $userInput = Read-Host

        if ($userInput -match '^[Qq]$') {
            Write-Log 'User chose to quit.' -Level 'INFO'
            exit 0
        }

        if ($userInput -match '^[Aa]$') {
            return @('MicrosoftGraph', 'MicrosoftTeams', 'ExchangeOnline', 'SharePointOnline')
        }

        $tokens   = @($userInput -split ',' | ForEach-Object { $_.Trim() })
        $valid    = @($script:ServiceMap.Keys)
        $invalid  = @($tokens | Where-Object { $_ -notin $valid })

        if ($invalid.Count -gt 0) {
            Write-Host "  ✗ Invalid selection: $($invalid -join ', '). Enter numbers 1–4, A or Q." -ForegroundColor Red
            continue
        }

        $selected = @($tokens | ForEach-Object { $script:ServiceMap[$_] } | Select-Object -Unique)

        if ($selected.Count -eq 0) {
            Write-Host '  ✗ No valid services selected. Please try again.' -ForegroundColor Red
            continue
        }

        return [string[]]$selected
    }
}


function New-AppCertificate {
    <#
    .SYNOPSIS
        Creates a 4096-bit RSA self-signed certificate in Cert:\CurrentUser\My and
        exports the public key (.cer) to the specified export directory.
    .PARAMETER CertName
        Subject CN for the certificate.
    .PARAMETER DurationDays
        Validity period in days (1–3650).
    .PARAMETER ExportDir
        Directory to export the .cer file into.
    .OUTPUTS
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
    #>
    param(
        [Parameter(Mandatory)]
        [string]$CertName,

        [Parameter(Mandatory)]
        [ValidateRange(1, 3650)]
        [int]$DurationDays,

        [Parameter(Mandatory)]
        [string]$ExportDir
    )

    Write-Log "Creating self-signed certificate '$CertName' (valid $DurationDays days)..." -Level 'INFO'

    $cert = New-SelfSignedCertificate `
        -Subject           "CN=$CertName" `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy   Exportable `
        -KeySpec           Signature `
        -KeyLength         4096 `
        -KeyAlgorithm      RSA `
        -HashAlgorithm     SHA256 `
        -NotAfter          (Get-Date).AddDays($DurationDays)

    Write-Log "✓ Certificate created — Thumbprint: $($cert.Thumbprint)" -Level 'SUCCESS'

    $cerPath = Join-Path $ExportDir "$CertName.cer"
    Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
    Write-Log "  Public key (.cer) exported to: $cerPath" -Level 'INFO'

    return $cert
}


function Import-ExistingCertificate {
    <#
    .SYNOPSIS
        Loads a public-key .cer file, validates it, displays details, and warns
        if the certificate is expired or not yet valid.
    .PARAMETER CertificatePath
        Full path to the .cer file.
    .OUTPUTS
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
    #>
    param(
        [Parameter(Mandatory)]
        [string]$CertificatePath
    )

    if (-not (Test-Path $CertificatePath)) {
        throw "Certificate file not found: $CertificatePath"
    }

    $ext = [System.IO.Path]::GetExtension($CertificatePath)
    if ($ext -ne '.cer') {
        Write-Log "⚠ Warning: Expected .cer file, got '$ext'. Continuing..." -Level 'WARNING'
    }

    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
    }
    catch {
        throw "Failed to read certificate file: $($_.Exception.Message)"
    }

    Write-Log '✓ Certificate loaded' -Level 'SUCCESS'
    Write-Host "    Subject    : $($cert.Subject)" -ForegroundColor Gray
    Write-Host "    Thumbprint : $($cert.Thumbprint)" -ForegroundColor Gray
    Write-Host "    Valid from : $($cert.NotBefore.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
    Write-Host "    Valid until: $($cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
    Write-Host ''

    if ($cert.NotBefore -gt (Get-Date)) {
        throw "Certificate is not yet valid (valid from $($cert.NotBefore.ToString('yyyy-MM-dd')))."
    }

    if ($cert.NotAfter -lt (Get-Date)) {
        Write-Log '⚠ WARNING: This certificate has EXPIRED!' -Level 'WARNING'
        Write-Host '  Continue with expired certificate? (Y/N): ' -NoNewline -ForegroundColor Yellow
        $answer = (Read-Host).Trim()
        if ($answer -notmatch '^[Yy]$') {
            throw 'Operation cancelled by user — expired certificate.'
        }
    }

    return $cert
}


function Show-PermissionsMenu {
    <#
    .SYNOPSIS
        Shows the permission list for a service, allows the user to toggle optional
        permissions on/off, and returns the final selected permission array.
    .PARAMETER Service
        Key from $script:ServiceDefinitions (e.g. 'MicrosoftGraph').
    .OUTPUTS
        [hashtable[]] Array of selected permissions with keys AppId, Name, Type.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Service
    )

    $def         = $script:ServiceDefinitions[$Service]
    $permissions = $def.Permissions
    # Parallel bool array; starts with each permission's Default value
    [bool[]]$selected = $permissions | ForEach-Object { $_.Default }

    while ($true) {
        Write-Host ''
        Write-Host "  Permissions for $($def.DisplayName):" -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  Review the permissions below. Pre-selected [✓] items are the recommended defaults.' -ForegroundColor White
        Write-Host '  To add or remove a permission, type its number and press Enter.' -ForegroundColor White
        Write-Host '  When you are done, type A and press Enter to accept and move on.' -ForegroundColor White
        Write-Host ''
        Write-Host ('  {0,-4} {1,-6}  {2,-44}  {3}' -f '#', 'On/Off', 'Permission', 'Description') -ForegroundColor DarkGray
        Write-Host ('  {0,-4} {1,-6}  {2,-44}  {3}' -f '─', '──────', '────────────────────────────────────────────', '──────────────────────') -ForegroundColor DarkGray

        for ($i = 0; $i -lt $permissions.Count; $i++) {
            $p    = $permissions[$i]
            $tick = if ($selected[$i]) { '[✓]' } else { '[ ]' }
            $tag  = if ($p.Default) { '' } else { '(optional)' }
            Write-Host ('  [{0,2}]  {1}  {2,-44}  {3} {4}' -f ($i + 1), $tick, $p.Name, $p.Description, $tag) -ForegroundColor White
        }

        Write-Host ''
        Write-Host '  ─────────────────────────────────────────────────────────────' -ForegroundColor DarkGray
        Write-Host "  [A] Accept and continue   [R] Reset to defaults   [1-$($permissions.Count)] Toggle permission" -ForegroundColor DarkGray
        Write-Host '  ─────────────────────────────────────────────────────────────' -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '  Action: ' -NoNewline -ForegroundColor Cyan
        $userInput = (Read-Host).Trim()

        if ($userInput -match '^[Aa]$') { break }

        if ($userInput -match '^[Rr]$') {
            [bool[]]$selected = $permissions | ForEach-Object { $_.Default }
            Write-Host '  ↺ Permissions reset to defaults.' -ForegroundColor Yellow
            continue
        }

        $num = 0
        if ([int]::TryParse($userInput, [ref]$num) -and $num -ge 1 -and $num -le $permissions.Count) {
            $selected[$num - 1] = -not $selected[$num - 1]
        }
        else {
            Write-Host "  ✗ Invalid input. Type a number (1–$($permissions.Count)) to toggle, A to accept, or R to reset." -ForegroundColor Red
        }
    }

    $result = [System.Collections.Generic.List[hashtable]]::new()
    for ($i = 0; $i -lt $permissions.Count; $i++) {
        if ($selected[$i]) {
            $result.Add(@{
                AppId = $def.ResourceAppId
                Name  = $permissions[$i].Name
                Type  = $permissions[$i].Type
            })
        }
    }
    return $result.ToArray()
}


function Show-ExchangeAccessLevelMenu {
    <#
    .SYNOPSIS
        Prompts for the Exchange Online access level to grant the app.
    .DESCRIPTION
        Exchange.ManageAsApp is the only Graph app permission for Exchange app-only auth —
        it does not distinguish read vs. write. The effective access level of an app-only
        Exchange Online PowerShell session comes from either an Exchange role group
        membership or an Entra directory role assigned to the app's service principal.

        View-only uses the 'View-Only Organization Management' role group so read access
        stays scoped to Exchange, rather than the tenant-wide Global Reader directory role.
        Reference: https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2
    .OUTPUTS
        [hashtable] Level, Method ('ExchangeRoleGroup'/'EntraRole'), RoleName and (for
        EntraRole) RoleId.
    #>
    param()

    Write-Host ''
    Write-Host '  Exchange Online Access Level' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Both options are applied automatically by this script.' -ForegroundColor White
    Write-Host ''
    Write-Host "    [1]  View-only — 'View-Only Organization Management' role group (default)" -ForegroundColor White
    Write-Host '         Read-only, scoped to Exchange only. Requires an extra Exchange sign-in.' -ForegroundColor DarkGray
    Write-Host '    [2]  Full      — Exchange Administrator directory role' -ForegroundColor White
    Write-Host '         Full Exchange management access.' -ForegroundColor DarkGray
    Write-Host ''

    while ($true) {
        Write-Host '  Choice [1]: ' -NoNewline -ForegroundColor Cyan
        $userInput = (Read-Host).Trim()

        if ([string]::IsNullOrWhiteSpace($userInput) -or $userInput -eq '1') {
            return @{
                Level    = 'ViewOnly'
                Method   = 'ExchangeRoleGroup'
                RoleName = 'View-Only Organization Management'
            }
        }
        if ($userInput -eq '2') {
            return @{
                Level    = 'Full'
                Method   = 'EntraRole'
                RoleId   = '29232cdf-9323-42fd-ade2-1d097af3e4de'
                RoleName = 'Exchange Administrator'
            }
        }
        Write-Host '  ✗ Enter 1 or 2.' -ForegroundColor Red
    }
}


function Get-AppNamePrefix {
    <#
    .SYNOPSIS
        Prompts for a name prefix and shows a preview of all names that will be created.
    .PARAMETER SelectedServices
        Services the user has chosen, used only for preview display.
    .OUTPUTS
        [string] The confirmed prefix.
    #>
    param(
        [Parameter(Mandatory)]
        [string[]]$SelectedServices
    )

    Write-Host ''
    Write-Host '  App Registration Naming' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Enter a prefix for all app registrations and connection scripts.' -ForegroundColor White
    Write-Host '  Example: "Contoso-PS" → Contoso-PS-MicrosoftGraph, Contoso-PS-Connect-MicrosoftGraph.ps1' -ForegroundColor DarkGray
    Write-Host ''

    while ($true) {
        Write-Host '  Prefix [M365-PS]: ' -NoNewline -ForegroundColor Cyan
        $userInput = (Read-Host).Trim()
        $prefix    = if ([string]::IsNullOrWhiteSpace($userInput)) { 'M365-PS' } else { $userInput }

        Write-Host ''
        Write-Host '  Preview — the following will be created:' -ForegroundColor Yellow
        Write-Host ''
        foreach ($svc in $SelectedServices) {
            $def = $script:ServiceDefinitions[$svc]
            Write-Host "  $($def.DisplayName)" -ForegroundColor White
            Write-Host "    App name : $prefix-$svc" -ForegroundColor Gray
            Write-Host "    File name: $prefix-Connect-$svc.ps1" -ForegroundColor Gray
            Write-Host ''
        }
        Write-Host "  Config file : $prefix-Config.json" -ForegroundColor Gray
        Write-Host '              (stores all ClientIds, TenantId and certificate thumbprint in one place,' -ForegroundColor DarkGray
        Write-Host '               useful as a reference or for scripting against multiple services)' -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '  Confirm prefix? [Y] Accept  [N] Enter different prefix: ' -NoNewline -ForegroundColor Cyan
        $answer = (Read-Host).Trim()

        if ($answer -match '^[Yy]$' -or [string]::IsNullOrWhiteSpace($answer)) {
            return $prefix
        }
        # If user typed N (or anything else), loop back to ask again
    }
}


function Show-ConfirmationSummary {
    <#
    .SYNOPSIS
        Displays a full summary of what will be created and prompts Y/N to proceed.
    .OUTPUTS
        [bool] $true to proceed.
    #>
    param(
        [Parameter(Mandatory)] [string[]]$SelectedServices,
        [Parameter(Mandatory)] [string]$Prefix,
        [Parameter(Mandatory)] [hashtable]$SelectedPermissions,
        [Parameter(Mandatory)] [string]$CertMode,
        [Parameter(Mandatory)] [string]$CertThumbprint,
        [hashtable]$ExchangeAccessLevel
    )

    Write-Host ''
    Write-Host '╔════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║  Confirmation — Review Before Creating                     ║' -ForegroundColor Cyan
    Write-Host '╚════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
    Write-Host "  Certificate : $CertMode" -ForegroundColor White
    Write-Host "  Thumbprint  : $CertThumbprint" -ForegroundColor White
    Write-Host ''

    foreach ($svc in $SelectedServices) {
        $def = $script:ServiceDefinitions[$svc]
        Write-Host "  ┌─ $Prefix-$svc ($($def.DisplayName))" -ForegroundColor White
        Write-Host '  │  Permissions:' -ForegroundColor DarkGray
        foreach ($perm in $SelectedPermissions[$svc]) {
            Write-Host "  │    • $($perm.Name)" -ForegroundColor Gray
        }
        if ($def.AdminRoleId) {
            Write-Host "  │  Admin Role : $($def.AdminRoleName) (auto-assigned)" -ForegroundColor DarkGray
        }
        if ($svc -eq 'ExchangeOnline' -and $ExchangeAccessLevel) {
            Write-Host "  │  Access Level : $($ExchangeAccessLevel.Level) — '$($ExchangeAccessLevel.RoleName)' (auto-assigned)" -ForegroundColor DarkGray
        }
        Write-Host "  │  Output     : $Prefix-Connect-$svc.ps1" -ForegroundColor DarkGray
        Write-Host '  └' -ForegroundColor White
        Write-Host ''
    }

    Write-Host '  Proceed and create all app registrations? (Y/N): ' -NoNewline -ForegroundColor Yellow
    $answer = (Read-Host).Trim()
    return $answer -match '^[Yy]$'
}


function Connect-ToMicrosoftGraph {
    <#
    .SYNOPSIS
        Connects interactively to Microsoft Graph with all scopes needed for app registration,
        permission granting, and admin role assignment.
    #>
    param()

    Write-Log 'Connecting to Microsoft Graph (browser sign-in required)...' -Level 'INFO'

    $scopes = @(
        'Application.ReadWrite.All',
        'Directory.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory'
    )

    Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop

    $ctx = Get-MgContext
    if (-not $ctx -or -not $ctx.TenantId) {
        throw 'Microsoft Graph connection failed — unable to retrieve context after sign-in.'
    }

    Write-Log "✓ Connected — Tenant: $($ctx.TenantId)  Account: $($ctx.Account)" -Level 'SUCCESS'
}


function Get-TenantMetadata {
    <#
    .SYNOPSIS
        Derives TenantId, onmicrosoft.com domain and SharePoint admin URL from the connected tenant.
    .OUTPUTS
        [hashtable] TenantId, OrgDomain, SPOAdminUrl
    #>
    param()

    $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
    if (-not $org) { throw 'Unable to retrieve organization information from Microsoft Graph.' }

    $tenantId  = $org.Id
    $omsDomain = ($org.VerifiedDomains |
                  Where-Object { $_.Name -match '\.onmicrosoft\.com$' } |
                  Select-Object -First 1).Name

    if (-not $omsDomain) { throw 'Could not determine the onmicrosoft.com domain for this tenant.' }

    $prefix      = ($omsDomain -split '\.')[0]
    $spoAdminUrl = "https://$prefix-admin.sharepoint.com/"

    Write-Log "  Tenant ID     : $tenantId" -Level 'INFO'
    Write-Log "  Org domain    : $omsDomain" -Level 'INFO'
    Write-Log "  SPO admin URL : $spoAdminUrl" -Level 'INFO'

    return @{
        TenantId    = $tenantId
        OrgDomain   = $omsDomain
        SPOAdminUrl = $spoAdminUrl
    }
}


function New-ServiceAppRegistration {
    <#
    .SYNOPSIS
        Creates an app registration for one service: app + service principal, certificate,
        permissions, and admin consent.
    .PARAMETER AppName
        Display name for the app registration.
    .PARAMETER Service
        Key from $script:ServiceDefinitions.
    .PARAMETER Certificate
        The certificate object to attach to the app.
    .PARAMETER Permissions
        Array of hashtables with keys AppId, Name, Type.
    .OUTPUTS
        [hashtable] AppId, ObjectId, ServicePrincipalId, ConsentSucceeded, ConsentFailed
    #>
    param(
        [Parameter(Mandatory)]
        [string]$AppName,

        [Parameter(Mandatory)]
        [string]$Service,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [hashtable[]]$Permissions
    )

    $def = $script:ServiceDefinitions[$Service]
    Write-Log "Creating: $AppName" -Level 'INFO'

    # Create application
    $app = New-MgApplication `
        -DisplayName    $AppName `
        -Description    "Certificate-based PowerShell access to $($def.DisplayName) — created by I.D.E.A. 003" `
        -SignInAudience  'AzureADMyOrg' `
        -ErrorAction     Stop

    Write-Log "  ✓ App created — AppId: $($app.AppId)" -Level 'SUCCESS'

    # Create service principal
    $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
    Write-Log "  ✓ Service principal — Id: $($sp.Id)" -Level 'SUCCESS'

    Start-Sleep -Seconds 3   # Allow propagation

    # Attach certificate via MicrosoftGraphKeyCredential
    $keyCredential               = New-Object Microsoft.Graph.PowerShell.Models.MicrosoftGraphKeyCredential
    $keyCredential.Type          = 'AsymmetricX509Cert'
    $keyCredential.Usage         = 'Verify'
    $keyCredential.Key           = $Certificate.GetRawCertData()
    $keyCredential.DisplayName   = $Certificate.Subject
    $keyCredential.StartDateTime = $Certificate.NotBefore
    $keyCredential.EndDateTime   = $Certificate.NotAfter

    Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($keyCredential) -ErrorAction Stop
    Write-Log "  ✓ Certificate attached — Thumbprint: $($Certificate.Thumbprint)" -Level 'SUCCESS'

    # Build permissions grouped by resource AppId
    $permsByResource = @{}
    foreach ($perm in $Permissions) {
        if (-not $permsByResource.ContainsKey($perm.AppId)) {
            $permsByResource[$perm.AppId] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $permsByResource[$perm.AppId].Add($perm)
    }

    $requiredResourceAccess = [System.Collections.Generic.List[hashtable]]::new()
    $consentItems           = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($resourceAppId in $permsByResource.Keys) {
        $resourceSp     = Get-MgServicePrincipal -Filter "AppId eq '$resourceAppId'" -ErrorAction Stop
        $resourceAccess = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($perm in $permsByResource[$resourceAppId]) {
            $appRole = $resourceSp.AppRoles |
                       Where-Object { $_.Value -eq $perm.Name -and $_.AllowedMemberTypes -contains 'Application' }

            if ($appRole) {
                $resourceAccess.Add(@{ Id = $appRole.Id; Type = 'Role' })
                $consentItems.Add(@{
                    SpId       = $sp.Id
                    ResourceId = $resourceSp.Id
                    RoleId     = $appRole.Id
                    PermName   = $perm.Name
                })
                Write-Log "    Found: $($perm.Name)" -Level 'INFO'
            }
            else {
                Write-Log "    ⚠ Permission '$($perm.Name)' not found on resource SP — skipping" -Level 'WARNING'
            }
        }

        if ($resourceAccess.Count -gt 0) {
            $requiredResourceAccess.Add(@{
                ResourceAppId  = $resourceAppId
                ResourceAccess = $resourceAccess.ToArray()
            })
        }
    }

    if ($requiredResourceAccess.Count -gt 0) {
        Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $requiredResourceAccess.ToArray() -ErrorAction Stop
        Write-Log "  ✓ Permissions set on application manifest" -Level 'SUCCESS'
    }

    Start-Sleep -Seconds 3   # Allow propagation before granting consent

    # Grant admin consent (with dedup check)
    $consentSucceeded = 0
    $consentFailed    = 0

    foreach ($item in $consentItems) {
        try {
            $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $item.SpId -ErrorAction SilentlyContinue |
                        Where-Object { $_.AppRoleId -eq $item.RoleId -and $_.ResourceId -eq $item.ResourceId }

            if ($existing) {
                Write-Log "    Already consented: $($item.PermName)" -Level 'INFO'
                $consentSucceeded++
                continue
            }

            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $item.SpId `
                -PrincipalId        $item.SpId `
                -ResourceId         $item.ResourceId `
                -AppRoleId          $item.RoleId `
                -ErrorAction Stop | Out-Null

            Write-Log "    ✓ Consent granted: $($item.PermName)" -Level 'SUCCESS'
            $consentSucceeded++
        }
        catch {
            Write-Log "    ⚠ Could not grant consent for $($item.PermName): $($_.Exception.Message)" -Level 'WARNING'
            $consentFailed++
        }
    }

    if ($consentFailed -gt 0) {
        Write-Log "  ⚠ $consentFailed permission(s) require manual admin consent in the Entra portal" -Level 'WARNING'
    }

    return @{
        AppId              = $app.AppId
        ObjectId           = $app.Id
        ServicePrincipalId = $sp.Id
        ConsentSucceeded   = $consentSucceeded
        ConsentFailed      = $consentFailed
    }
}


function Grant-AdminRoleToApp {
    <#
    .SYNOPSIS
        Assigns an Entra ID built-in admin role (Teams Administrator / Exchange Administrator)
        to the app's service principal at tenant scope.
    .PARAMETER ServicePrincipalId
        Object ID of the service principal.
    .PARAMETER RoleDefinitionId
        Role template GUID (globally consistent across tenants).
    .PARAMETER RoleName
        Display name for log messages.
    .OUTPUTS
        [bool] $true if role assigned successfully, $false otherwise.
    #>
    param(
        [Parameter(Mandatory)] [string]$ServicePrincipalId,
        [Parameter(Mandatory)] [string]$RoleDefinitionId,
        [Parameter(Mandatory)] [string]$RoleName
    )

    Write-Log "  Assigning role '$RoleName'..." -Level 'INFO'

    try {
        New-MgRoleManagementDirectoryRoleAssignment `
            -PrincipalId      $ServicePrincipalId `
            -RoleDefinitionId $RoleDefinitionId `
            -DirectoryScopeId '/' `
            -ErrorAction Stop | Out-Null

        Write-Log "  ✓ Role '$RoleName' assigned" -Level 'SUCCESS'
        return $true
    }
    catch {
        Write-Log "  ⚠ Could not assign '$RoleName': $($_.Exception.Message)" -Level 'WARNING'
        Write-Log "    Manual step: Entra portal → Roles & admins → $RoleName → Add assignments → search app by name" -Level 'WARNING'
        return $false
    }
}


function Install-RequiredModule {
    <#
    .SYNOPSIS
        Installs a module for the current user if it is not already available.
    .PARAMETER Name
        Module name to check and install.
    #>
    param(
        [Parameter(Mandatory)] [string]$Name
    )

    if (Get-Module -ListAvailable -Name $Name) {
        Write-Log "  ✓ $Name" -Level 'SUCCESS'
        return
    }

    Write-Log "  Installing $Name ..." -Level 'INFO'
    Install-Module $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    Write-Log "  ✓ Installed $Name" -Level 'SUCCESS'
}


function Connect-ToExchangeOnlineAdmin {
    <#
    .SYNOPSIS
        Connects interactively to Exchange Online PowerShell so the app's service principal
        can be registered and added to an Exchange role group.
    .PARAMETER OrgDomain
        onmicrosoft.com domain of the tenant.
    .NOTES
        Load order relative to Microsoft.Graph does not matter on PowerShell 7: the Graph SDK
        isolates its dependencies in the 'msgraph-load-context' ALC, so its MSAL version and
        the one Exchange loads into the default context coexist. This is not true on Windows
        PowerShell 5.1, hence the #Requires -Version 7.0 at the top of this script.
    #>
    param(
        [Parameter(Mandatory)] [string]$OrgDomain
    )

    Install-RequiredModule -Name 'ExchangeOnlineManagement'
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    Write-Log 'Connecting to Exchange Online (browser sign-in required) to assign the role group...' -Level 'INFO'
    Connect-ExchangeOnline -Organization $OrgDomain -ShowBanner:$false -ErrorAction Stop

    Write-Log '  ✓ Connected to Exchange Online' -Level 'SUCCESS'
}


function Grant-ExchangeRoleGroupMembership {
    <#
    .SYNOPSIS
        Registers the app as an Exchange service principal and adds it to an Exchange
        role group (e.g. 'View-Only Organization Management').
    .PARAMETER AppId
        Application (client) ID of the app registration.
    .PARAMETER ServicePrincipalId
        Object ID of the Entra service principal.
    .PARAMETER DisplayName
        Display name for the Exchange service principal entry.
    .PARAMETER RoleGroupName
        Exchange role group to add the app to.
    .OUTPUTS
        [bool] $true only if membership is verified present, $false otherwise.
    #>
    param(
        [Parameter(Mandatory)] [string]$AppId,
        [Parameter(Mandatory)] [string]$ServicePrincipalId,
        [Parameter(Mandatory)] [string]$DisplayName,
        [Parameter(Mandatory)] [string]$RoleGroupName
    )

    try {
        $existingSp = Get-ServicePrincipal -Identity $AppId -ErrorAction SilentlyContinue

        if (-not $existingSp) {
            Write-Log '  Registering Exchange service principal...' -Level 'INFO'
            New-ServicePrincipal `
                -AppId       $AppId `
                -ObjectId    $ServicePrincipalId `
                -DisplayName $DisplayName `
                -ErrorAction Stop | Out-Null
            Write-Log '  ✓ Exchange service principal registered' -Level 'SUCCESS'
        }
        else {
            Write-Log '  Exchange service principal already registered' -Level 'INFO'
        }

        Write-Log "  Adding app to role group '$RoleGroupName'..." -Level 'INFO'

        $alreadyMember = Get-RoleGroupMember -Identity $RoleGroupName -ErrorAction Stop |
                         Where-Object { $_.Name -eq $ServicePrincipalId }

        if ($alreadyMember) {
            Write-Log "  ✓ Already a member of role group '$RoleGroupName'" -Level 'SUCCESS'
            return $true
        }

        Add-RoleGroupMember `
            -Identity    $RoleGroupName `
            -Member      $ServicePrincipalId `
            -Confirm:$false `
            -ErrorAction Stop | Out-Null

        $member = Get-RoleGroupMember -Identity $RoleGroupName -ErrorAction Stop |
                  Where-Object { $_.Name -eq $ServicePrincipalId }

        if (-not $member) {
            throw "Membership not found in '$RoleGroupName' after the add operation"
        }

        Write-Log "  ✓ Added to role group '$RoleGroupName'" -Level 'SUCCESS'
        return $true
    }
    catch {
        Write-Log "  ⚠ Could not add app to '$RoleGroupName': $($_.Exception.Message)" -Level 'WARNING'
        Write-Log "    Manual step: Connect-ExchangeOnline, then run:" -Level 'WARNING'
        Write-Log "      New-ServicePrincipal -AppId $AppId -ObjectId $ServicePrincipalId -DisplayName '$DisplayName'" -Level 'WARNING'
        Write-Log "      Add-RoleGroupMember -Identity '$RoleGroupName' -Member $ServicePrincipalId" -Level 'WARNING'
        return $false
    }
}


function Export-ConnectionScript {
    <#
    .SYNOPSIS
        Generates a service-specific ready-to-use connection .ps1 script in the exports folder.
    .PARAMETER Service
        Service key (MicrosoftGraph, MicrosoftTeams, ExchangeOnline, SharePointOnline).
    .PARAMETER Prefix
        App name prefix used to name the file.
    .PARAMETER ClientId
        Application (client) ID of the registered app.
    .PARAMETER TenantId
        Entra ID tenant GUID.
    .PARAMETER Thumbprint
        Certificate thumbprint.
    .PARAMETER ExportDir
        Destination directory for the generated file.
    .PARAMETER OrgDomain
        onmicrosoft.com domain (required for Exchange).
    .PARAMETER SPOAdminUrl
        SharePoint admin URL (required for SharePoint).
    .OUTPUTS
        [string] Full path to the generated .ps1 file.
    #>
    param(
        [Parameter(Mandatory)] [string]$Service,
        [Parameter(Mandatory)] [string]$Prefix,
        [Parameter(Mandatory)] [string]$ClientId,
        [Parameter(Mandatory)] [string]$TenantId,
        [Parameter(Mandatory)] [string]$Thumbprint,
        [Parameter(Mandatory)] [string]$ExportDir,
        [string]$OrgDomain   = '',
        [string]$SPOAdminUrl = ''
    )

    $fileName  = "$Prefix-Connect-$Service.ps1"
    $filePath  = Join-Path $ExportDir $fileName
    $generated = "Generated by I.D.E.A. 003 on $(Get-Date -Format 'yyyy-MM-dd HH:mm')"

    switch ($Service) {
        'MicrosoftGraph' {
            $content = @"
<#
.SYNOPSIS
    Connects PowerShell to Microsoft Graph / Entra ID using certificate-based authentication.
    $generated
.NOTES
    Requires: Microsoft.Graph.Authentication module.
    Prerequisite: Certificate (private key) installed in Cert:\CurrentUser\My.
#>

# Install module if not present
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}

`$GraphConnectionParams = @{
    TenantId              = '$TenantId'
    ClientId              = '$ClientId'
    CertificateThumbprint = '$Thumbprint'
}

Connect-MgGraph @GraphConnectionParams -NoWelcome
Write-Host "Connected to Microsoft Graph (Tenant: $TenantId)" -ForegroundColor Green
"@
        }

        'MicrosoftTeams' {
            $content = @"
<#
.SYNOPSIS
    Connects PowerShell to Microsoft Teams using certificate-based authentication.
    $generated
.NOTES
    Requires: MicrosoftTeams module.
    Prerequisite: Certificate (private key) installed in Cert:\CurrentUser\My.
    Not all Teams cmdlets support app-only authentication.
    Reference: https://learn.microsoft.com/en-us/microsoftteams/teams-powershell-application-authentication
#>

# Install module if not present
if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
    Install-Module MicrosoftTeams -Scope CurrentUser -Force -AllowClobber
}

`$TeamsConnectionParams = @{
    TenantId              = '$TenantId'
    ApplicationId         = '$ClientId'
    CertificateThumbprint = '$Thumbprint'
}

Connect-MicrosoftTeams @TeamsConnectionParams
Write-Host "Connected to Microsoft Teams (Tenant: $TenantId)" -ForegroundColor Green
"@
        }

        'ExchangeOnline' {
            $content = @"
<#
.SYNOPSIS
    Connects PowerShell to Exchange Online using certificate-based authentication.
    $generated
.NOTES
    Requires: ExchangeOnlineManagement module.
    Prerequisite: Certificate (private key) installed in Cert:\CurrentUser\My.
    Exchange Online uses the onmicrosoft.com domain, NOT the Tenant GUID, for Organization.
    Not all Exchange cmdlets support app-only authentication.
    Reference: https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2
#>

# Install module if not present
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
}

`$ExchangeConnectionParams = @{
    Organization          = '$OrgDomain'
    AppId                 = '$ClientId'
    CertificateThumbPrint = '$Thumbprint'
}

Connect-ExchangeOnline @ExchangeConnectionParams
Write-Host "Connected to Exchange Online (Organization: $OrgDomain)" -ForegroundColor Green
"@
        }

        'SharePointOnline' {
            $content = @"
<#
.SYNOPSIS
    Connects PowerShell to SharePoint Online using certificate-based authentication (PnP).
    $generated
.NOTES
    Requires: PnP.PowerShell module.
    Prerequisite: Certificate (private key) installed in Cert:\CurrentUser\My.
    Adjust `$SiteUrl to connect to a specific site instead of the Admin Center.
    Reference: https://pnp.github.io/powershell/
#>

# Install module if not present
if (-not (Get-Module -ListAvailable -Name PnP.PowerShell)) {
    Install-Module PnP.PowerShell -Scope CurrentUser -Force -AllowClobber
}

`$SPOConnectionParams = @{
    Tenant    = '$TenantId'
    ClientId  = '$ClientId'
    Thumbprint = '$Thumbprint'
}

# Connect to the SharePoint Admin Center
`$AdminSiteUrl = '$SPOAdminUrl'
Connect-PnPOnline -Url `$AdminSiteUrl @SPOConnectionParams
Write-Host "Connected to SharePoint Online Admin Center ($SPOAdminUrl)" -ForegroundColor Green

# To connect to a specific site instead, use:
# Connect-PnPOnline -Url 'https://contoso.sharepoint.com/sites/MySite' @SPOConnectionParams
"@
        }

        default {
            throw "Unknown service key: $Service"
        }
    }

    Set-Content -Path $filePath -Value $content -Encoding UTF8
    Write-Log "  ✓ Connection script: $fileName" -Level 'SUCCESS'
    return $filePath
}


function Export-ConfigJson {
    <#
    .SYNOPSIS
        Writes a JSON config file with all app ClientIds, TenantId and cert thumbprint.
    .PARAMETER Prefix
        App name prefix.
    .PARAMETER TenantId
        Tenant GUID.
    .PARAMETER Thumbprint
        Certificate thumbprint.
    .PARAMETER AppResults
        Hashtable of service → result hashtable from New-ServiceAppRegistration.
    .PARAMETER ExportDir
        Destination directory.
    .OUTPUTS
        [string] Full path to the JSON file.
    #>
    param(
        [Parameter(Mandatory)] [string]$Prefix,
        [Parameter(Mandatory)] [string]$TenantId,
        [Parameter(Mandatory)] [string]$Thumbprint,
        [Parameter(Mandatory)] [hashtable]$AppResults,
        [Parameter(Mandatory)] [string]$ExportDir
    )

    $config = [ordered]@{
        GeneratedBy  = 'I.D.E.A. 003 – M365 Certificate App Registration'
        CreatedDate  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Prefix       = $Prefix
        TenantId     = $TenantId
        Certificate  = @{ Thumbprint = $Thumbprint }
        Applications = [ordered]@{}
    }

    foreach ($svc in $AppResults.Keys) {
        $config.Applications[$svc] = [ordered]@{
            ClientId      = $AppResults[$svc].AppId
            ObjectId      = $AppResults[$svc].ObjectId
            ConnectScript = "$Prefix-Connect-$svc.ps1"
        }
    }

    $jsonPath = Join-Path $ExportDir "$Prefix-Config.json"
    $config | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Log "✓ Config JSON written: $Prefix-Config.json" -Level 'SUCCESS'
    return $jsonPath
}


function Show-CompletionSummary {
    <#
    .SYNOPSIS
        Displays the final summary with per-service ClientIds, script locations and next steps.
    #>
    param(
        [Parameter(Mandatory)] [string]$Prefix,
        [Parameter(Mandatory)] [string]$TenantId,
        [Parameter(Mandatory)] [string]$Thumbprint,
        [Parameter(Mandatory)] [string[]]$SelectedServices,
        [Parameter(Mandatory)] [hashtable]$AppResults,
        [Parameter(Mandatory)] [string]$ExportDir
    )

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════════════╗' -ForegroundColor Green
    Write-Host '║  ✓  Registration Complete                                            ║' -ForegroundColor Green
    Write-Host '╚══════════════════════════════════════════════════════════════════════╝' -ForegroundColor Green
    Write-Host ''
    Write-Host "  Tenant ID   : $TenantId" -ForegroundColor White
    Write-Host "  Thumbprint  : $Thumbprint" -ForegroundColor White
    Write-Host ''

    foreach ($svc in $SelectedServices) {
        if (-not $AppResults.ContainsKey($svc)) { continue }
        $def    = $script:ServiceDefinitions[$svc]
        $result = $AppResults[$svc]

        Write-Host "  ┌─ $Prefix-$svc ($($def.DisplayName))" -ForegroundColor Green
        Write-Host "  │  Client ID : $($result.AppId)" -ForegroundColor Gray
        Write-Host "  │  Script    : $Prefix-Connect-$svc.ps1" -ForegroundColor Gray

        if ($result.ConsentFailed -gt 0) {
            Write-Host "  │  ⚠  $($result.ConsentFailed) permission(s) require manual consent in Entra portal" -ForegroundColor Yellow
        }
        if ($result.ContainsKey('AccessLevel')) {
            Write-Host "  │  Access Level : $($result.AccessLevel)" -ForegroundColor Gray
        }
        if ($result.ContainsKey('RoleName') -and $result.RoleName) {
            if ($result.RoleAssigned) {
                Write-Host "  │  Role       : $($result.RoleName) (assigned)" -ForegroundColor Gray
            }
            else {
                Write-Host "  │  ⚠  '$($result.RoleName)' requires manual assignment — see log for commands" -ForegroundColor Yellow
            }
        }
        Write-Host '  └' -ForegroundColor Green
        Write-Host ''
    }

    Write-Host "  All files written to: $ExportDir" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Next steps:' -ForegroundColor Yellow

    $step = 1
    Write-Host "    $step. Verify the certificate (with private key) is in Cert:\CurrentUser\My." -ForegroundColor White
    Write-Host "       Run: gci Cert:\CurrentUser\My | where Thumbprint -eq '$Thumbprint'" -ForegroundColor DarkGray
    $step++
    Write-Host "    $step. Copy the connection scripts to your working directory." -ForegroundColor White
    $step++
    Write-Host "    $step. Run a connection script to test: .\<script>.ps1" -ForegroundColor White

    if ($SelectedServices -contains 'MicrosoftTeams' -or $SelectedServices -contains 'ExchangeOnline') {
        $step++
        Write-Host "    $step. Directory role assignments can take a few minutes to take effect." -ForegroundColor White
        Write-Host '       Verify in Entra portal > Roles & admins if a connection is denied.' -ForegroundColor DarkGray
    }
    Write-Host ''

    Write-Log 'I.D.E.A. 003 completed successfully.' -Level 'SUCCESS'
}

#endregion

#region ── Main Execution ────────────────────────────────────────────────────────
# Guard: only run when script is executed directly (not dot-sourced for testing)
if ($MyInvocation.InvocationName -ne '.') {

    Show-Banner

    # ── Step 1: Service Selection ──────────────────────────────────────────────
    Write-Host '  Step 1 of 5 — Select Services' -ForegroundColor Yellow
    Write-Host ''
    $selectedServices = Show-ServiceSelectionMenu
    Write-Log "Selected services: $($selectedServices -join ', ')" -Level 'INFO'

    # ── Step 2: Certificate ────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '  Step 2 of 5 — Certificate' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '    [1]  Create new self-signed certificate (4096-bit RSA, default 180 days)' -ForegroundColor White
    Write-Host '    [2]  Use existing .cer file' -ForegroundColor White
    Write-Host ''

    $certChoice = ''
    while ($certChoice -notin @('1', '2')) {
        Write-Host '  Choice: ' -NoNewline -ForegroundColor Cyan
        $certChoice = (Read-Host).Trim()
        if ($certChoice -notin @('1', '2')) {
            Write-Host '  ✗ Enter 1 or 2.' -ForegroundColor Red
        }
    }

    $certificate = $null
    $certMode    = ''

    if ($certChoice -eq '2') {
        Write-Host ''

        # Try Windows file picker first; fall back to manual entry if not available
        $cerPathInput = $null
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
            $dialog                  = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.Title            = 'Select certificate file (.cer)'
            $dialog.Filter           = 'Certificate files (*.cer)|*.cer|All files (*.*)|*.*'
            $dialog.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
            $dialog.Multiselect      = $false

            Write-Host '  Opening file browser — select your .cer file...' -ForegroundColor Cyan
            $result = $dialog.ShowDialog()

            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                $cerPathInput = $dialog.FileName
                Write-Host "  Selected: $cerPathInput" -ForegroundColor Gray
            }
            else {
                Write-Log 'File selection cancelled.' -Level 'WARNING'
                exit 0
            }
        }
        catch {
            # Windows Forms not available — fall back to manual entry
            Write-Host '  Path to .cer file: ' -NoNewline -ForegroundColor Cyan
            while ([string]::IsNullOrWhiteSpace($cerPathInput)) {
                $cerPathInput = (Read-Host).Trim().Trim('"')
                if ([string]::IsNullOrWhiteSpace($cerPathInput)) {
                    Write-Host '  ✗ Path cannot be empty. Try again: ' -NoNewline -ForegroundColor Red
                }
            }
        }

        Write-Host ''
        $certificate = Import-ExistingCertificate -CertificatePath $cerPathInput
        $certMode    = "Existing .cer file ($([System.IO.Path]::GetFileName($cerPathInput)))"
    }

    # ── Step 3: Permissions per service ───────────────────────────────────────
    Write-Host ''
    Write-Host '  Step 3 of 5 — Review Permissions' -ForegroundColor Yellow
    $selectedPermissions = @{}
    foreach ($svc in $selectedServices) {
        $selectedPermissions[$svc] = Show-PermissionsMenu -Service $svc
    }

    $exchangeAccessLevel = $null
    if ($selectedServices -contains 'ExchangeOnline') {
        $exchangeAccessLevel = Show-ExchangeAccessLevelMenu
        Write-Log "Exchange Online access level: $($exchangeAccessLevel.Level) ('$($exchangeAccessLevel.RoleName)')" -Level 'INFO'

        # Installed up front so a missing module fails before any app registrations exist.
        if ($exchangeAccessLevel.Method -eq 'ExchangeRoleGroup') {
            Write-Host ''
            Install-RequiredModule -Name 'ExchangeOnlineManagement'
        }
    }

    # ── Step 4: App Name Prefix ────────────────────────────────────────────────
    Write-Host ''
    Write-Host '  Step 4 of 5 — App Naming' -ForegroundColor Yellow
    $prefix = Get-AppNamePrefix -SelectedServices $selectedServices

    # Create self-signed certificate now that we have the prefix for naming
    if ($certChoice -eq '1') {
        Write-Host ''
        $dateStamp   = Get-Date -Format 'yyyy.MM.dd'
        $defaultName = "PSAppCert-$prefix-$dateStamp"

        Write-Host "  Certificate name [$defaultName]: " -NoNewline -ForegroundColor Cyan
        $nameInput = (Read-Host).Trim()
        $certName  = if ([string]::IsNullOrWhiteSpace($nameInput)) { $defaultName } else { $nameInput }

        Write-Host '  Validity in days [180]: ' -NoNewline -ForegroundColor Cyan
        $durInput = (Read-Host).Trim()
        $duration = 180

        if (-not [string]::IsNullOrWhiteSpace($durInput)) {
            if (-not [int]::TryParse($durInput, [ref]$duration) -or $duration -lt 1 -or $duration -gt 3650) {
                throw "Invalid certificate duration '$durInput'. Must be between 1 and 3650 days."
            }
        }

        $certificate = New-AppCertificate -CertName $certName -DurationDays $duration -ExportDir $script:ExportDir
        $certMode    = "New self-signed ($certName, $duration days)"
    }

    # ── Step 5: Confirmation ───────────────────────────────────────────────────
    Write-Host ''
    Write-Host '  Step 5 of 5 — Confirm & Create' -ForegroundColor Yellow
    $proceed = Show-ConfirmationSummary `
        -SelectedServices     $selectedServices `
        -Prefix               $prefix `
        -SelectedPermissions  $selectedPermissions `
        -CertMode             $certMode `
        -CertThumbprint       $certificate.Thumbprint `
        -ExchangeAccessLevel  $exchangeAccessLevel

    if (-not $proceed) {
        Write-Log 'User cancelled. No changes were made.' -Level 'WARNING'
        exit 0
    }

    # ── Connect to Graph ───────────────────────────────────────────────────────
    Write-Host ''
    Connect-ToMicrosoftGraph

    # ── Derive tenant metadata ─────────────────────────────────────────────────
    Write-Host ''
    Write-Log 'Retrieving tenant metadata...' -Level 'INFO'
    $tenantMeta = Get-TenantMetadata

    # ── Create app registrations ───────────────────────────────────────────────
    $appResults = @{}
    $script:ExchangeOnlineConnected = $false

    foreach ($svc in $selectedServices) {
        $appName = "$prefix-$svc"
        Write-Host ''
        Write-Log "── Processing $appName ──────────────────────────────" -Level 'INFO'

        try {
            $result = New-ServiceAppRegistration `
                -AppName     $appName `
                -Service     $svc `
                -Certificate $certificate `
                -Permissions $selectedPermissions[$svc]

            # Assign admin role where applicable
            $def           = $script:ServiceDefinitions[$svc]
            $adminRoleId   = $def.AdminRoleId
            $adminRoleName = $def.AdminRoleName

            $result['RoleAssigned'] = $null
            $result['RoleName']     = $adminRoleName

            if ($svc -eq 'ExchangeOnline' -and $exchangeAccessLevel) {
                $result['AccessLevel'] = $exchangeAccessLevel.Level
                $result['RoleName']    = $exchangeAccessLevel.RoleName

                if ($exchangeAccessLevel.Method -eq 'ExchangeRoleGroup') {
                    if (-not $script:ExchangeOnlineConnected) {
                        Connect-ToExchangeOnlineAdmin -OrgDomain $tenantMeta.OrgDomain
                        $script:ExchangeOnlineConnected = $true
                    }

                    Start-Sleep -Seconds 10   # Allow the new service principal to reach Exchange

                    $result['RoleAssigned'] = Grant-ExchangeRoleGroupMembership `
                        -AppId              $result.AppId `
                        -ServicePrincipalId $result.ServicePrincipalId `
                        -DisplayName        $appName `
                        -RoleGroupName      $exchangeAccessLevel.RoleName

                    $adminRoleId = $null   # Handled by the role group instead
                }
                else {
                    $adminRoleId   = $exchangeAccessLevel.RoleId
                    $adminRoleName = $exchangeAccessLevel.RoleName
                }
            }

            if ($adminRoleId) {
                $result['RoleAssigned'] = Grant-AdminRoleToApp `
                    -ServicePrincipalId $result.ServicePrincipalId `
                    -RoleDefinitionId   $adminRoleId `
                    -RoleName           $adminRoleName
            }

            # Generate the connection script for this service
            Export-ConnectionScript `
                -Service     $svc `
                -Prefix      $prefix `
                -ClientId    $result.AppId `
                -TenantId    $tenantMeta.TenantId `
                -Thumbprint  $certificate.Thumbprint `
                -ExportDir   $script:ExportDir `
                -OrgDomain   $tenantMeta.OrgDomain `
                -SPOAdminUrl $tenantMeta.SPOAdminUrl | Out-Null

            $appResults[$svc] = $result
            Write-Log "✓ $appName completed successfully" -Level 'SUCCESS'
        }
        catch {
            Write-Log "✗ Failed to create $appName : $($_.Exception.Message)" -Level 'ERROR'
            Write-Log "  StackTrace: $($_.ScriptStackTrace)" -Level 'ERROR'
        }
    }

    if ($script:ExchangeOnlineConnected) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log 'Disconnected from Exchange Online.' -Level 'INFO'
    }

    # ── Export config JSON ─────────────────────────────────────────────────────
    if ($appResults.Count -gt 0) {
        Write-Host ''
        Export-ConfigJson `
            -Prefix     $prefix `
            -TenantId   $tenantMeta.TenantId `
            -Thumbprint $certificate.Thumbprint `
            -AppResults $appResults `
            -ExportDir  $script:ExportDir | Out-Null
    }

    # ── Final summary ──────────────────────────────────────────────────────────
    $completedServices = @($selectedServices | Where-Object { $appResults.ContainsKey($_) })

    Show-CompletionSummary `
        -Prefix           $prefix `
        -TenantId         $tenantMeta.TenantId `
        -Thumbprint       $certificate.Thumbprint `
        -SelectedServices $completedServices `
        -AppResults       $appResults `
        -ExportDir        $script:ExportDir
}
#endregion
