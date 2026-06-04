<#
.SYNOPSIS
    Interactive menu-driven MFA report for Microsoft Entra ID with HTML output.

.DESCRIPTION
    Provides an interactive menu experience for generating comprehensive MFA reports.
    Analyzes MFA status for all users in the tenant using Microsoft Graph Beta API.
    
    Features:
    - Interactive menu for connecting to services and generating reports
    - Microsoft Graph connection (required) and Exchange Online (optional)
    - Selectable output formats: Console, HTML, CSV, or any combination
    - Risk assessment with 5 levels (Critical/High/Medium/Good/Secure)
    - Phone number country distribution analysis
    - Self-contained interactive HTML report with sorting, filtering, and search
    - Account category detection (user/room/shared/equipment)
    - Admin status, licensing, and sign-in activity tracking

.PARAMETER LogDirectory
    Directory path for log files. Defaults to .\Logs

.EXAMPLE
    .\Get-EntraMFAReport.ps1
    Launches the interactive menu to connect to services and generate the MFA report.

.EXAMPLE
    .\Get-EntraMFAReport.ps1 -LogDirectory "C:\Logs"
    Launches with a custom log directory.

.NOTES
    Requires a Microsoft Graph connection with these scopes:
    - User.Read.All
    - Directory.Read.All
    - UserAuthenticationMethod.Read.All
    - AuditLog.Read.All (for sign-in activity data)
    
    Also requires Exchange Online connectivity (Connect-ExchangeOnline) for authoritative
    mailbox-type detection (shared/room/equipment). The script will connect automatically
    if no existing EXO session is found.

    TROUBLESHOOTING:
    If the report fails with permission errors, run Connect-MgGraph manually with the
    required scopes and check whether admin consent is missing:
        Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All","UserAuthenticationMethod.Read.All","AuditLog.Read.All"
    If the consent prompt does not show "Consent on behalf of your organization", a
    Global Admin must grant admin consent via the Entra admin center:
        Enterprise Applications > Microsoft Graph Command Line Tools > Permissions > Grant admin consent
    
    Author: Per-Torben Sørensen
    Version: 2.1
    Created: October 2025
    Updated: June 2026 - Added HTML report, risk levels, account categories, sign-in activity
                       - Replaced usage-report mailbox detection with Exchange Online RecipientTypeDetails
                       - Edge now opens report in normal window instead of guest mode

    DATA PRIVACY / GDPR NOTICE:
    Output files (HTML and CSV) contain personal data including names, email addresses,
    phone numbers, and sign-in activity. Handle in accordance with your organisation's
    data protection policy and applicable regulations (e.g. GDPR, CCPA).
    - Store in a secure, access-controlled location
    - Do not distribute beyond authorised recipients
    - Retain only as long as operationally required
    - Dispose of securely when no longer needed
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$LogDirectory = ".\Logs"
)

# ============================================================================
# Module Auto-Installation
# ============================================================================
$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Beta.Identity.SignIns',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'ExchangeOnlineManagement'
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing module: $module" -ForegroundColor Yellow
        Install-Module $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "✓ Installed $module" -ForegroundColor Green
    }
}

# ============================================================================
# Logging
# ============================================================================
if (!(Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

$LogFile = Join-Path $LogDirectory "Get-EntraMFAReport-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    if ($LogFile) {
        Add-Content -Path $LogFile -Value $logEntry
    }
    
    switch ($Level) {
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "ERROR"   { Write-Host $Message -ForegroundColor Red }
        default   { Write-Host $Message -ForegroundColor White }
    }
}

# ============================================================================
# Phone Country Code Mapping
# ============================================================================
$CountryCodes = @{
    '1'='US/Canada'; '7'='Russia'; '20'='Egypt'; '27'='South Africa'; '30'='Greece';
    '31'='Netherlands'; '32'='Belgium'; '33'='France'; '34'='Spain'; '36'='Hungary';
    '39'='Italy'; '40'='Romania'; '41'='Switzerland'; '43'='Austria'; '44'='UK';
    '45'='Denmark'; '46'='Sweden'; '47'='Norway'; '48'='Poland'; '49'='Germany';
    '51'='Peru'; '52'='Mexico'; '53'='Cuba'; '54'='Argentina'; '55'='Brazil';
    '56'='Chile'; '57'='Colombia'; '58'='Venezuela'; '60'='Malaysia'; '61'='Australia';
    '62'='Indonesia'; '63'='Philippines'; '64'='New Zealand'; '65'='Singapore';
    '66'='Thailand'; '81'='Japan'; '82'='South Korea'; '84'='Vietnam'; '86'='China';
    '90'='Turkey'; '91'='India'; '92'='Pakistan'; '93'='Afghanistan'; '94'='Sri Lanka';
    '95'='Myanmar'; '98'='Iran'; '211'='South Sudan'; '212'='Morocco'; '213'='Algeria';
    '216'='Tunisia'; '218'='Libya'; '220'='Gambia'; '221'='Senegal'; '222'='Mauritania';
    '223'='Mali'; '224'='Guinea'; '225'='Ivory Coast'; '226'='Burkina Faso';
    '227'='Niger'; '228'='Togo'; '229'='Benin'; '230'='Mauritius'; '231'='Liberia';
    '232'='Sierra Leone'; '233'='Ghana'; '234'='Nigeria'; '235'='Chad'; '236'='CAR';
    '237'='Cameroon'; '238'='Cape Verde'; '239'='Sao Tome'; '240'='Eq. Guinea';
    '241'='Gabon'; '242'='Congo'; '243'='DRC'; '244'='Angola'; '245'='Guinea-Bissau';
    '248'='Seychelles'; '249'='Sudan'; '250'='Rwanda'; '251'='Ethiopia'; '252'='Somalia';
    '253'='Djibouti'; '254'='Kenya'; '255'='Tanzania'; '256'='Uganda'; '257'='Burundi';
    '258'='Mozambique'; '260'='Zambia'; '261'='Madagascar'; '262'='Reunion';
    '263'='Zimbabwe'; '264'='Namibia'; '265'='Malawi'; '266'='Lesotho';
    '267'='Botswana'; '268'='Eswatini'; '269'='Comoros'; '290'='St Helena';
    '291'='Eritrea'; '297'='Aruba'; '298'='Faroe Islands'; '299'='Greenland';
    '350'='Gibraltar'; '351'='Portugal'; '352'='Luxembourg'; '353'='Ireland';
    '354'='Iceland'; '355'='Albania'; '356'='Malta'; '357'='Cyprus'; '358'='Finland';
    '359'='Bulgaria'; '370'='Lithuania'; '371'='Latvia'; '372'='Estonia';
    '373'='Moldova'; '374'='Armenia'; '375'='Belarus'; '376'='Andorra';
    '377'='Monaco'; '378'='San Marino'; '380'='Ukraine'; '381'='Serbia';
    '382'='Montenegro'; '383'='Kosovo'; '385'='Croatia'; '386'='Slovenia';
    '387'='Bosnia'; '389'='North Macedonia'; '420'='Czech Republic'; '421'='Slovakia';
    '423'='Liechtenstein'; '852'='Hong Kong'; '853'='Macau'; '855'='Cambodia';
    '856'='Laos'; '880'='Bangladesh'; '886'='Taiwan'; '960'='Maldives';
    '961'='Lebanon'; '962'='Jordan'; '963'='Syria'; '964'='Iraq'; '965'='Kuwait';
    '966'='Saudi Arabia'; '967'='Yemen'; '968'='Oman'; '970'='Palestine';
    '971'='UAE'; '972'='Israel'; '973'='Bahrain'; '974'='Qatar'; '975'='Bhutan';
    '976'='Mongolia'; '977'='Nepal'; '992'='Tajikistan'; '993'='Turkmenistan';
    '994'='Azerbaijan'; '995'='Georgia'; '996'='Kyrgyzstan'; '998'='Uzbekistan'
}

function Get-CountryFromPhone {
    param([string]$PhoneNumber)
    if (-not $PhoneNumber -or $PhoneNumber -eq 'False') { return $null }
    $cleaned = $PhoneNumber -replace '[^\d+]', ''
    if ($cleaned -notmatch '^\+') { return 'Unknown' }
    $digits = $cleaned.TrimStart('+')
    # Try 3-digit, then 2-digit, then 1-digit country codes
    for ($len = 3; $len -ge 1; $len--) {
        if ($digits.Length -ge $len) {
            $code = $digits.Substring(0, $len)
            if ($CountryCodes.ContainsKey($code)) { return "$($CountryCodes[$code]) (+$code)" }
        }
    }
    return "Unknown (+$($digits.Substring(0, [Math]::Min(3, $digits.Length)))...)"
}

# ============================================================================
# Menu Functions
# ============================================================================
function Show-Banner {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  I.D.E.A. 004 - Entra ID MFA Report" -ForegroundColor Cyan
    Write-Host "  Identity Engineering Artifacts" -ForegroundColor DarkCyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

function Show-ConnectionStatus {
    $graphStatus = "Not connected"
    $graphColor = "Red"
    $exoStatus = "Not connected"
    $exoColor = "Red"

    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if ($ctx) {
        # Prefer the *.onmicrosoft.com initial domain over the raw tenant GUID
        try {
            $initialDomain = (Get-MgDomain -ErrorAction SilentlyContinue |
                Where-Object { $_.IsInitial -eq $true } |
                Select-Object -First 1).Id
        } catch { $initialDomain = $null }
        $domainLabel = if ($initialDomain) { $initialDomain } else { $ctx.TenantId }
        $graphStatus = "Connected ($domainLabel)"
        $graphColor = "Green"
    }

    $exoSession = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if ($exoSession) {
        # Show the default accepted domain (e.g. contoso.com) when available
        try {
            $defaultDomain = (Get-AcceptedDomain -ErrorAction SilentlyContinue |
                Where-Object { $_.Default -eq $true } |
                Select-Object -First 1).DomainName
        } catch { $defaultDomain = $null }
        $exoStatus = if ($defaultDomain) { "Connected ($defaultDomain)" } else { "Connected" }
        $exoColor = "Green"
    }

    Write-Host "  Connection Status:" -ForegroundColor Yellow
    Write-Host "    Microsoft Graph:    " -NoNewline; Write-Host $graphStatus -ForegroundColor $graphColor
    Write-Host "    Exchange Online:    " -NoNewline; Write-Host $exoStatus -ForegroundColor $exoColor
    Write-Host ""
}

function Show-StaleFilesWarning {
    $cutoff = (Get-Date).AddHours(-24)
    $dirs = @(".\exports", $LogDirectory) | Where-Object { Test-Path $_ }

    $staleFiles = foreach ($dir in $dirs) {
        Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoff }
    }

    if ($staleFiles) {
        $count = @($staleFiles).Count
        $paths = ($dirs | ForEach-Object { (Resolve-Path $_ -ErrorAction SilentlyContinue).Path }) -join ', '
        Write-Host ("  " + "-" * 74) -ForegroundColor DarkYellow
        Write-Host "  ! $count file(s) older than 24 hours found in: $paths" -ForegroundColor Yellow
        Write-Host "    These may contain personal data. Delete them if no longer needed." -ForegroundColor Yellow
        Write-Host ("  " + "-" * 74) -ForegroundColor DarkYellow
        Write-Host ""
    }
}

function Show-MainMenu {
    Clear-Host
    Show-Banner
    Show-ConnectionStatus
    Show-StaleFilesWarning
    Write-Host "  [1] Connect to Microsoft Graph" -ForegroundColor Green
    Write-Host "  [2] Connect to Exchange Online (optional)" -ForegroundColor Green
    Write-Host "  [3] Generate MFA Report" -ForegroundColor Green
    Write-Host "  [Q] Quit" -ForegroundColor Gray
    Write-Host ""
}

function Show-OutputMenu {
    Write-Host ""
    Write-Host "  Select output format(s):" -ForegroundColor Yellow
    Write-Host "  [1] Console + HTML report (default)" -ForegroundColor Green
    Write-Host "  [2] Console + HTML + CSV" -ForegroundColor Green
    Write-Host "  [3] Console only" -ForegroundColor Green
    Write-Host "  [4] CSV only (no HTML)" -ForegroundColor Green
    Write-Host ""
    
    $choice = Read-Host "  Enter choice (1-4, default=1)"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }
    
    switch ($choice) {
        '1' { return @{ Html = $true; Csv = $false; Console = $true } }
        '2' { return @{ Html = $true; Csv = $true; Console = $true } }
        '3' { return @{ Html = $false; Csv = $false; Console = $true } }
        '4' { return @{ Html = $false; Csv = $true; Console = $true } }
        default { 
            Write-Host "  Invalid choice, using default (Console + HTML)" -ForegroundColor Yellow
            return @{ Html = $true; Csv = $false; Console = $true }
        }
    }
}

function Connect-Graph {
    $requiredScopes = @(
        "User.Read.All",
        "Directory.Read.All",
        "UserAuthenticationMethod.Read.All",
        "AuditLog.Read.All",
        "Reports.Read.All"
    )

    Write-Host ""
    Write-Host "  Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Write-Host "  Required scopes: $($requiredScopes -join ', ')" -ForegroundColor Gray
    Write-Host ""

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ContextScope Process -ErrorAction Stop
        $ctx = Get-MgContext
        if ($ctx) {
            Write-Host "  ✓ Connected (Tenant: $($ctx.TenantId))" -ForegroundColor Green
            Write-Log "Connected to Microsoft Graph (Tenant: $($ctx.TenantId))" -Level "SUCCESS"
        }
        else {
            Write-Host "  ✗ Connection failed - no context established" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  ✗ Connection failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Graph connection failed: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Connect-Exo {
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │  Exchange Online is OPTIONAL.                                    │" -ForegroundColor Yellow
    Write-Host "  │  Without it, shared/room/equipment mailbox detection will use    │" -ForegroundColor Yellow
    Write-Host "  │  heuristics instead of authoritative RecipientTypeDetails.       │" -ForegroundColor Yellow
    Write-Host "  │  MFA data and risk analysis are NOT affected.                    │" -ForegroundColor Yellow
    Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
    Write-Host ""
    
    $confirm = Read-Host "  Connect to Exchange Online? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "  Skipped Exchange Online connection." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Connecting to Exchange Online..." -ForegroundColor Yellow
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Host "  ✓ Connected to Exchange Online" -ForegroundColor Green
        Write-Log "Connected to Exchange Online" -Level "SUCCESS"
    }
    catch {
        Write-Host "  ✗ Connection failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Exchange Online connection failed: $($_.Exception.Message)" -Level "ERROR"
    }
}

# ============================================================================
# HTML Report Generation Function
# ============================================================================
function New-HtmlReport {
    param(
        [Parameter(Mandatory)]
        [array]$UserData,
        [Parameter(Mandatory)]
        [PSCustomObject]$Summary,
        [Parameter(Mandatory)]
        [string]$OutputPath,
        [string]$TenantName = "Unknown"
    )

    $totalUsers = $Summary.TotalUsers
    $mfaEnabledPct = $Summary.MFAEnabledInteractivePct  # Entra-equivalent: enabled Members only
    $mfaInteractiveCount = $Summary.InteractiveAccounts
    $mfaDisabledPct = $Summary.MFADisabledPercentage
    $criticalCount = ($UserData | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $highCount = ($UserData | Where-Object { $_.RiskLevel -eq 'High' }).Count
    $mediumCount = ($UserData | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    $goodCount = ($UserData | Where-Object { $_.RiskLevel -eq 'Good' }).Count
    $secureCount = ($UserData | Where-Object { $_.RiskLevel -eq 'Secure' }).Count

    # Build phone country summary for HTML
    $phoneCountryHtml = ""
    $phoneUsers = $UserData | Where-Object { $_.phoneNumber -and $_.phoneNumber -ne $false }
    if ($phoneUsers.Count -gt 0) {
        $countryCounts = @{}
        foreach ($pu in $phoneUsers) {
            $country = Get-CountryFromPhone -PhoneNumber $pu.phoneNumber
            if ($country) {
                if ($countryCounts.ContainsKey($country)) { $countryCounts[$country]++ }
                else { $countryCounts[$country] = 1 }
            }
        }
        $countryRows = $countryCounts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            "<tr><td>$($_.Key)</td><td>$($_.Value)</td></tr>"
        }
        $phoneCountryHtml = $countryRows -join "`n"
    }

    # Build JSON data for the table
    $jsonRows = $UserData | ForEach-Object {
        $methods = @()
        if ($_.authApp) { $methods += 'Authenticator' }
        if ($_.phoneSMS) { $methods += 'Phone/SMS' }
        if ($_.fido) { $methods += 'FIDO2' }
        if ($_.helloForBusiness) { $methods += 'Windows Hello' }
        if ($_.passwordLess) { $methods += 'Passwordless' }
        if ($_.softwareAuth) { $methods += 'Software OATH' }
        if ($_.emailAuth) { $methods += 'Email' }
        if ($_.tempPass) { $methods += 'TAP' }
        $methodStr = if ($methods.Count -gt 0) { $methods -join ', ' } else { '-' }

        $phoneStr = if ($_.phoneNumber -and $_.phoneNumber -ne $false) { $_.phoneNumber } else { '' }
        $lastSignInStr = if ($_.lastSignIn) { $_.lastSignIn } else { 'Never' }

        [PSCustomObject]@{
            displayName     = $_.user
            upn             = $_.upn
            userType        = $_.usertype
            accountCategory = $_.accountCategory
            accountStatus   = if ($_.enabled) { 'Enabled' } else { 'Disabled' }
            mfaStatus       = switch ($_.MFAstatus) { 'enabled' { 'Enabled' } 'disabled' { 'Disabled' } default { 'Unknown' } }
            mfaMethods      = $methodStr
            phoneNumber     = $phoneStr
            isAdmin         = if ($_.isAdmin) { 'Yes' } else { 'No' }
            licensed        = if ($_.licensed) { 'Yes' } else { 'No' }
            lastSignIn      = $lastSignInStr
            riskLevel       = $_.RiskLevel
            riskNotes       = $_.RiskNotes
        }
    }

    $jsonData = $jsonRows | ConvertTo-Json -Depth 3 -Compress
    # Escape for embedding in JS
    $jsonData = $jsonData -replace '\\', '\\\\' -replace "'", "\'"

    $generatedDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Entra ID MFA Report - $TenantName - $generatedDate</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; padding: 20px; }
.header { background: linear-gradient(135deg, #1a237e, #0d47a1); color: white; padding: 30px; border-radius: 12px; margin-bottom: 20px; }
.header h1 { font-size: 1.8em; margin-bottom: 5px; }
.header .meta { opacity: 0.8; font-size: 0.9em; }
.dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 20px; }
.card { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }
.card .value { font-size: 2em; font-weight: 700; }
.card .label { font-size: 0.85em; color: #666; margin-top: 5px; }
.card.critical .value { color: #d32f2f; }
.card.high .value { color: #f57c00; }
.card.medium .value { color: #fbc02d; }
.card.good .value { color: #0097a7; }
.card.secure .value { color: #388e3c; }
.card.info .value { color: #1565c0; }
.filters { background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
.filters h3 { margin-bottom: 12px; color: #1a237e; }
.filter-row { display: flex; flex-wrap: wrap; gap: 12px; align-items: end; }
.filter-group { display: flex; flex-direction: column; }
.filter-group label { font-size: 0.8em; font-weight: 600; color: #555; margin-bottom: 4px; }
.filter-group select, .filter-group input { padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 0.9em; min-width: 140px; }
.filter-group input[type="text"] { min-width: 200px; }
.method-filters { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 10px; padding-top: 10px; border-top: 1px solid #eee; }
.method-filters label { font-size: 0.8em; font-weight: 600; color: #555; margin-right: 8px; }
.method-logic-toggle { display: inline-flex; align-items: center; gap: 6px; margin-left: 12px; padding: 4px 10px; background: #f5f5f5; border-radius: 16px; font-size: 0.75em; font-weight: 600; border: 1px solid #ddd; }
.method-logic-toggle span { padding: 2px 8px; border-radius: 10px; cursor: pointer; color: #777; }
.method-logic-toggle span.active { background: #1565c0; color: white; }
.method-chip { display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px; background: #e3f2fd; border-radius: 16px; font-size: 0.8em; cursor: pointer; user-select: none; border: 1px solid #bbdefb; }
.method-chip.active { background: #1565c0; color: white; border-color: #1565c0; }
.btn-reset { padding: 8px 16px; background: #e0e0e0; border: none; border-radius: 6px; cursor: pointer; font-size: 0.85em; font-weight: 600; }
.btn-reset:hover { background: #bdbdbd; }
.table-container { background: white; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); overflow: hidden; }
.table-info { padding: 12px 20px; background: #fafafa; border-bottom: 1px solid #eee; font-size: 0.85em; color: #666; }
table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
thead { background: #1a237e; color: white; position: sticky; top: 0; }
th { padding: 12px 10px; text-align: left; cursor: pointer; user-select: none; white-space: nowrap; }
th:hover { background: #283593; }
th .sort-icon { margin-left: 4px; opacity: 0.5; }
th.sorted-asc .sort-icon::after { content: ' ▲'; opacity: 1; }
th.sorted-desc .sort-icon::after { content: ' ▼'; opacity: 1; }
td { padding: 10px; border-bottom: 1px solid #f0f0f0; }
tr:hover { background: #f5f5f5; }
tr.risk-critical { border-left: 4px solid #d32f2f; }
tr.risk-high { border-left: 4px solid #f57c00; }
tr.risk-medium { border-left: 4px solid #fbc02d; }
tr.risk-good { border-left: 4px solid #0097a7; }
tr.risk-secure { border-left: 4px solid #388e3c; }
tr.risk-na { border-left: 4px solid #9e9e9e; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.8em; font-weight: 600; }
.badge-critical { background: #ffebee; color: #c62828; }
.badge-high { background: #fff3e0; color: #e65100; }
.badge-medium { background: #fffde7; color: #f57f17; }
.badge-good { background: #e0f7fa; color: #00695c; }
.badge-secure { background: #e8f5e9; color: #2e7d32; }
.badge-na { background: #f5f5f5; color: #616161; }
.badge-enabled { background: #e8f5e9; color: #2e7d32; }
.badge-disabled { background: #ffebee; color: #c62828; }
.badge-guest { background: #e3f2fd; color: #1565c0; }
.badge-member { background: #f3e5f5; color: #6a1b9a; }
.footer { margin-top: 20px; text-align: center; font-size: 0.8em; color: #999; }
.phone-country { background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
.phone-country h3 { color: #1a237e; margin-bottom: 10px; }
.phone-country table { width: auto; border-collapse: collapse; font-size: 0.85em; }
.phone-country td { padding: 4px 16px 4px 0; border: none; }
.phone-country tr td:last-child { font-weight: 600; }
.pii-notice { background: #fff8e1; border: 1px solid #f9a825; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px; font-size: 0.85em; color: #5d4037; display: flex; align-items: flex-start; gap: 12px; }
.pii-notice .pii-icon { font-size: 1.4em; flex-shrink: 0; line-height: 1.2; }
.pii-notice .pii-text strong { display: block; margin-bottom: 4px; color: #e65100; }
.pii-notice .pii-dismiss { margin-left: auto; cursor: pointer; font-size: 1.1em; color: #999; flex-shrink: 0; padding: 0 4px; }
.pii-notice .pii-dismiss:hover { color: #333; }
@media (max-width: 768px) { .filter-row { flex-direction: column; } .filter-group select, .filter-group input { min-width: 100%; } }
</style>
</head>
<body>
<div class="header">
<h1>Entra ID MFA Report</h1>
<div class="meta">Tenant: $TenantName | Generated: $generatedDate | Total Accounts: $totalUsers</div>
</div>

<div class="pii-notice" id="piiNotice">
  <span class="pii-icon">&#9888;</span>
  <div class="pii-text">
    <strong>Data Privacy Notice (GDPR)</strong>
    This report contains personal data: names, email addresses, phone numbers, and sign-in activity.
    Store securely, share only with authorised personnel, retain only as long as operationally required, and dispose of securely when no longer needed.
  </div>
  <span class="pii-dismiss" onclick="document.getElementById('piiNotice').style.display='none'" title="Dismiss">&#x2715;</span>
</div>

<div class="dashboard">
<div class="card info"><div class="value">$totalUsers</div><div class="label">Total Accounts</div></div>
<div class="card info"><div class="value">${mfaEnabledPct}%</div><div class="label">MFA Enabled</div><div class="label" style="font-size:0.7em;color:#888">of $mfaInteractiveCount interactive accounts</div></div>
<div class="card critical"><div class="value">$criticalCount</div><div class="label">Critical</div></div>
<div class="card high"><div class="value">$highCount</div><div class="label">High Risk</div></div>
<div class="card medium"><div class="value">$mediumCount</div><div class="label">Medium Risk</div></div>
<div class="card good"><div class="value">$goodCount</div><div class="label">Good</div></div>
<div class="card secure"><div class="value">$secureCount</div><div class="label">Secure</div></div>
</div>

<div class="phone-country">
<h3>Phone Numbers by Country</h3>
<table>$phoneCountryHtml</table>
</div>

<div class="filters">
<h3>Filters</h3>
<div class="filter-row">
<div class="filter-group"><label>Search (Name / UPN)</label><input type="text" id="searchBox" placeholder="Type to search..."></div>
<div class="filter-group"><label>Risk Level</label><select id="filterRisk"><option value="">All</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Good">Good</option><option value="Secure">Secure</option><option value="N/A">N/A</option></select></div>
<div class="filter-group"><label>MFA Status</label><select id="filterMfa"><option value="">All</option><option value="Enabled">Enabled</option><option value="Disabled">Disabled</option><option value="Unknown">Unknown</option></select></div>
<div class="filter-group"><label>User Type</label><select id="filterType"><option value="">All</option><option value="Member">Member</option><option value="Guest">Guest</option></select></div>
<div class="filter-group"><label>Account Category</label><select id="filterCategory"><option value="">All</option><option value="User">User</option><option value="Room">Room</option><option value="Shared Mailbox">Shared Mailbox</option><option value="Equipment">Equipment</option></select></div>
<div class="filter-group"><label>Account Status</label><select id="filterStatus"><option value="">All</option><option value="Enabled">Enabled</option><option value="Disabled">Disabled</option></select></div>
<div class="filter-group"><label>Is Admin</label><select id="filterAdmin"><option value="">All</option><option value="Yes">Yes</option><option value="No">No</option></select></div>
<div class="filter-group"><label>Licensed</label><select id="filterLicensed"><option value="">All</option><option value="Yes">Yes</option><option value="No">No</option></select></div>
<div class="filter-group"><label>Last Sign-In</label><select id="filterSignIn"><option value="">All</option><option value="Active">Active (30 days)</option><option value="Inactive30">Inactive 30+ days</option><option value="Inactive90">Inactive 90+ days</option><option value="Never">Never</option></select></div>
<div class="filter-group"><button class="btn-reset" onclick="resetFilters()">Reset All</button></div>
</div>
<div class="method-filters">
<label>MFA Methods:</label>
<span class="method-chip" data-method="Authenticator" onclick="toggleMethod(this)">Authenticator</span>
<span class="method-chip" data-method="Phone/SMS" onclick="toggleMethod(this)">Phone/SMS</span>
<span class="method-chip" data-method="FIDO2" onclick="toggleMethod(this)">FIDO2</span>
<span class="method-chip" data-method="Windows Hello" onclick="toggleMethod(this)">Windows Hello</span>
<span class="method-chip" data-method="Passwordless" onclick="toggleMethod(this)">Passwordless</span>
<span class="method-chip" data-method="Software OATH" onclick="toggleMethod(this)">Software OATH</span>
<span class="method-chip" data-method="Email" onclick="toggleMethod(this)">Email</span>
<span class="method-chip" data-method="TAP" onclick="toggleMethod(this)">TAP</span>
<div class="method-logic-toggle"><span id="modeOr" class="active" onclick="setMethodMode('or')">OR</span><span id="modeAnd" onclick="setMethodMode('and')">AND</span></div>
</div>
</div>

<div class="table-container">
<div class="table-info">Showing <span id="visibleCount">0</span> of <span id="totalCount">0</span> accounts</div>
<div style="overflow-x:auto; max-height: 70vh; overflow-y: auto;">
<table id="mfaTable">
<thead>
<tr>
<th data-col="displayName" onclick="sortTable('displayName')">Display Name<span class="sort-icon"></span></th>
<th data-col="upn" onclick="sortTable('upn')">UPN<span class="sort-icon"></span></th>
<th data-col="userType" onclick="sortTable('userType')">Type<span class="sort-icon"></span></th>
<th data-col="accountCategory" onclick="sortTable('accountCategory')">Category<span class="sort-icon"></span></th>
<th data-col="accountStatus" onclick="sortTable('accountStatus')">Account<span class="sort-icon"></span></th>
<th data-col="mfaStatus" onclick="sortTable('mfaStatus')">MFA<span class="sort-icon"></span></th>
<th data-col="mfaMethods" onclick="sortTable('mfaMethods')">MFA Methods<span class="sort-icon"></span></th>
<th data-col="isAdmin" onclick="sortTable('isAdmin')">Admin<span class="sort-icon"></span></th>
<th data-col="licensed" onclick="sortTable('licensed')">Licensed<span class="sort-icon"></span></th>
<th data-col="lastSignIn" onclick="sortTable('lastSignIn')">Last Sign-In<span class="sort-icon"></span></th>
<th data-col="riskLevel" onclick="sortTable('riskLevel')">Risk<span class="sort-icon"></span></th>
<th data-col="riskNotes" onclick="sortTable('riskNotes')">Risk Notes<span class="sort-icon"></span></th>
</tr>
</thead>
<tbody id="tableBody"></tbody>
</table>
</div>
</div>

<div class="footer">
Generated by I.D.E.A. 004 - Entra ID MFA Report | Per-Torben Sørensen
</div>

<script>
const DATA = JSON.parse('$jsonData');
let sortCol = 'riskLevel';
let sortDir = 'asc';
let activeMethodFilters = [];
let methodFilterMode = 'or';
const riskOrder = {Critical:0, High:1, Medium:2, Good:3, Secure:4, 'N/A':5};

function getRiskClass(r) { return 'risk-' + (r === 'N/A' ? 'na' : r.toLowerCase()); }
function getBadgeClass(r) { return 'badge-' + (r === 'N/A' ? 'na' : r.toLowerCase()); }

function renderTable() {
    const search = document.getElementById('searchBox').value.toLowerCase();
    const fRisk = document.getElementById('filterRisk').value;
    const fMfa = document.getElementById('filterMfa').value;
    const fType = document.getElementById('filterType').value;
    const fCat = document.getElementById('filterCategory').value;
    const fStatus = document.getElementById('filterStatus').value;
    const fAdmin = document.getElementById('filterAdmin').value;
    const fLic = document.getElementById('filterLicensed').value;
    const fSignIn = document.getElementById('filterSignIn').value;

    let filtered = DATA.filter(r => {
        if (search && !r.displayName.toLowerCase().includes(search) && !r.upn.toLowerCase().includes(search)) return false;
        if (fRisk && r.riskLevel !== fRisk) return false;
        if (fMfa && r.mfaStatus !== fMfa) return false;
        if (fType && r.userType !== fType) return false;
        if (fCat && r.accountCategory !== fCat) return false;
        if (fStatus && r.accountStatus !== fStatus) return false;
        if (fAdmin && r.isAdmin !== fAdmin) return false;
        if (fLic && r.licensed !== fLic) return false;
        if (fSignIn) {
            if (fSignIn === 'Never' && r.lastSignIn !== 'Never') return false;
            if (fSignIn === 'Active') {
                if (r.lastSignIn === 'Never') return false;
                const d = new Date(r.lastSignIn);
                if (isNaN(d) || (Date.now() - d) > 30*86400000) return false;
            }
            if (fSignIn === 'Inactive30') {
                if (r.lastSignIn === 'Never') return true;
                const d = new Date(r.lastSignIn);
                if (isNaN(d) || (Date.now() - d) <= 30*86400000) return false;
            }
            if (fSignIn === 'Inactive90') {
                if (r.lastSignIn === 'Never') return true;
                const d = new Date(r.lastSignIn);
                if (isNaN(d) || (Date.now() - d) <= 90*86400000) return false;
            }
        }
        if (activeMethodFilters.length > 0) {
            const userMethods = r.mfaMethods.toLowerCase();
            if (methodFilterMode === 'and') {
                if (!activeMethodFilters.every(m => userMethods.includes(m.toLowerCase()))) return false;
            } else {
                if (!activeMethodFilters.some(m => userMethods.includes(m.toLowerCase()))) return false;
            }
        }
        return true;
    });

    filtered.sort((a, b) => {
        let va = a[sortCol] || '';
        let vb = b[sortCol] || '';
        if (sortCol === 'riskLevel') { va = riskOrder[va] ?? 5; vb = riskOrder[vb] ?? 5; }
        else { va = va.toString().toLowerCase(); vb = vb.toString().toLowerCase(); }
        if (va < vb) return sortDir === 'asc' ? -1 : 1;
        if (va > vb) return sortDir === 'asc' ? 1 : -1;
        return 0;
    });

    document.getElementById('visibleCount').textContent = filtered.length;
    document.getElementById('totalCount').textContent = DATA.length;

    const tbody = document.getElementById('tableBody');
    tbody.innerHTML = filtered.map(r => {
        const rc = getRiskClass(r.riskLevel);
        const bc = getBadgeClass(r.riskLevel);
        return '<tr class="' + rc + '">' +
            '<td>' + esc(r.displayName) + '</td>' +
            '<td>' + esc(r.upn) + '</td>' +
            '<td><span class="badge badge-' + r.userType.toLowerCase() + '">' + esc(r.userType) + '</span></td>' +
            '<td>' + esc(r.accountCategory) + '</td>' +
            '<td><span class="badge badge-' + r.accountStatus.toLowerCase() + '">' + esc(r.accountStatus) + '</span></td>' +
            '<td><span class="badge badge-' + r.mfaStatus.toLowerCase() + '">' + esc(r.mfaStatus) + '</span></td>' +
            '<td>' + esc(r.mfaMethods) + '</td>' +
            '<td>' + esc(r.isAdmin) + '</td>' +
            '<td>' + esc(r.licensed) + '</td>' +
            '<td>' + esc(r.lastSignIn) + '</td>' +
            '<td><span class="badge ' + bc + '">' + esc(r.riskLevel) + '</span></td>' +
            '<td>' + esc(r.riskNotes) + '</td></tr>';
    }).join('');

    document.querySelectorAll('th').forEach(th => { th.classList.remove('sorted-asc','sorted-desc'); });
    const th = document.querySelector('th[data-col="'+sortCol+'"]');
    if (th) th.classList.add(sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc');
}

function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function sortTable(col) {
    if (sortCol === col) { sortDir = sortDir === 'asc' ? 'desc' : 'asc'; }
    else { sortCol = col; sortDir = 'asc'; }
    renderTable();
}

function toggleMethod(el) {
    const m = el.dataset.method;
    el.classList.toggle('active');
    if (el.classList.contains('active')) { activeMethodFilters.push(m); }
    else { activeMethodFilters = activeMethodFilters.filter(x => x !== m); }
    renderTable();
}

function setMethodMode(mode) {
    methodFilterMode = mode;
    document.getElementById('modeOr').classList.toggle('active', mode === 'or');
    document.getElementById('modeAnd').classList.toggle('active', mode === 'and');
    renderTable();
}

function resetFilters() {
    document.getElementById('searchBox').value = '';
    document.getElementById('filterRisk').value = '';
    document.getElementById('filterMfa').value = '';
    document.getElementById('filterType').value = '';
    document.getElementById('filterCategory').value = '';
    document.getElementById('filterStatus').value = '';
    document.getElementById('filterAdmin').value = '';
    document.getElementById('filterLicensed').value = '';
    document.getElementById('filterSignIn').value = '';
    activeMethodFilters = [];
    methodFilterMode = 'or';
    document.getElementById('modeOr').classList.add('active');
    document.getElementById('modeAnd').classList.remove('active');
    document.querySelectorAll('.method-chip').forEach(c => c.classList.remove('active'));
    renderTable();
}

document.getElementById('searchBox').addEventListener('input', renderTable);
document.querySelectorAll('.filters select').forEach(s => s.addEventListener('change', renderTable));
renderTable();
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Log "HTML report exported to: $OutputPath" -Level "SUCCESS"
}

# ============================================================================
# Report Generation Function
# ============================================================================
function Invoke-MFAReport {
    param(
        [hashtable]$OutputOptions
    )
    
    $ExportToCsv = $OutputOptions.Csv
    $ExportToHtml = $OutputOptions.Html

try {
    Write-Log "Starting Entra MFA Report generation" -Level "INFO"

    # Check for existing Microsoft Graph connection
    $context = Get-MgContext
    if (-not $context) {
        Write-Host ""
        Write-Host "  ✗ No active Microsoft Graph connection." -ForegroundColor Red
        Write-Host "    Use menu option [1] to connect first." -ForegroundColor Yellow
        Write-Host ""
        return
    }

    Write-Log "Using existing Microsoft Graph connection (Tenant: $($context.TenantId))" -Level "INFO"

    # ========================================================================
    # Retrieve Users with extended properties
    # ========================================================================
    Write-Log "Retrieving all users from Entra ID..." -Level "INFO"
    $signInActivityAvailable = $true
    try {
        [System.Collections.ArrayList]$allusers = Get-MgUser -All -Property DisplayName, UserPrincipalName, UserType, AccountEnabled, AssignedLicenses, SignInActivity, CreatedDateTime, Mail -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -match "LocationConditionEvaluationSatisfied|InvalidAuthenticationToken|Continuous access evaluation") {
            Write-Log "Conditional Access policy is blocking user retrieval due to location restrictions." -Level "ERROR"
            Write-Host "`nConditional Access Error:" -ForegroundColor Red
            Write-Host "Your tenant has location-based Conditional Access policies blocking this operation." -ForegroundColor Yellow
            Write-Host "`nPossible solutions:" -ForegroundColor Cyan
            Write-Host "1. Run script from a trusted network location" -ForegroundColor White
            Write-Host "2. Use certificate-based authentication with service principal" -ForegroundColor White
            Write-Host "3. Request admin to add current location to trusted locations" -ForegroundColor White
            Write-Host "4. Use Azure Cloud Shell or trusted workstation" -ForegroundColor White
            Write-Host "`nError details logged to: $LogFile" -ForegroundColor Gray
            return
        }
        elseif ($_.Exception.Message -match "AuditLog.Read.All|Authentication_MSGraphPermissionMissing|Authorization_RequestDenied|Insufficient privileges") {
            Write-Log "AuditLog.Read.All permission not available - sign-in activity will be omitted. Reconnect via menu option [1] to include it." -Level "WARNING"
            Write-Host "  ! Sign-in activity permission not granted - last sign-in data will not be available." -ForegroundColor Yellow
            Write-Host "    To include sign-in activity, use menu option [1] to reconnect and consent to all scopes." -ForegroundColor Gray
            Write-Host ""
            $signInActivityAvailable = $false
            [System.Collections.ArrayList]$allusers = Get-MgUser -All -Property DisplayName, UserPrincipalName, UserType, AccountEnabled, AssignedLicenses, CreatedDateTime, Mail -ErrorAction Stop
        }
        else {
            Write-Log "Unexpected error retrieving users: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }

    $export = New-Object -TypeName "System.Collections.ArrayList"
    $i = 0
    $count = $allusers.Count

    Write-Log "Retrieved $count users from Entra ID" -Level "INFO"

    if ($count -eq 0) {
        Write-Log "No users found. Check permissions and connection." -Level "WARNING"
        return
    }

    # ========================================================================
    # Get directory role assignments (lightweight admin check)
    # ========================================================================
    Write-Log "Retrieving directory role assignments..." -Level "INFO"
    $adminUserIds = @{}
    try {
        $directoryRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        foreach ($role in $directoryRoles) {
            try {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue
                foreach ($member in $members) {
                    $adminUserIds[$member.Id] = $true
                }
            }
            catch { }
        }
        Write-Log "Found $($adminUserIds.Count) users with admin role assignments" -Level "INFO"
    }
    catch {
        Write-Log "Could not retrieve admin roles: $($_.Exception.Message)" -Level "WARNING"
    }

    # ========================================================================
    # Detect account categories via Exchange Online RecipientTypeDetails
    # ========================================================================
    $mailboxTypes = @{}  # UPN -> RecipientTypeDetails
    $exoConnected = $false
    $exoSession = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if ($exoSession) {
        Write-Log "Retrieving mailbox types from Exchange Online..." -Level "INFO"
        try {
            $mailboxes = Get-EXOMailbox -ResultSize Unlimited -Properties RecipientTypeDetails -ErrorAction Stop
            foreach ($mbx in $mailboxes) {
                if ($mbx.UserPrincipalName) {
                    $mailboxTypes[$mbx.UserPrincipalName.ToLower()] = $mbx.RecipientTypeDetails
                }
            }

        $typeSummary = $mailboxes | Group-Object RecipientTypeDetails | ForEach-Object { "$($_.Name): $($_.Count)" }
        Write-Log "Mailbox types retrieved: $($typeSummary -join ', ')" -Level "INFO"
        }
        catch {
            Write-Log "Could not retrieve mailbox types from Exchange Online: $($_.Exception.Message). Using heuristic detection." -Level "WARNING"
        }
    }
    else {
        Write-Log "Exchange Online not connected. Using heuristic detection for mailbox types." -Level "WARNING"
        Write-Host "  ⚠ Exchange Online not connected - using heuristic mailbox detection" -ForegroundColor Yellow
    }

    # Also try Places API for room/equipment detection (requires Place.Read.All - optional)
    $roomEmails = @{}
    try {
        $roomsResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/places/microsoft.graph.room" -Method GET -ErrorAction Stop
        if ($roomsResponse.value) {
            foreach ($room in $roomsResponse.value) {
                if ($room.emailAddress) { $roomEmails[$room.emailAddress.ToLower()] = $true }
            }
        }
        while ($roomsResponse.'@odata.nextLink') {
            $roomsResponse = Invoke-MgGraphRequest -Uri $roomsResponse.'@odata.nextLink' -Method GET -ErrorAction Stop
            if ($roomsResponse.value) {
                foreach ($room in $roomsResponse.value) {
                    if ($room.emailAddress) { $roomEmails[$room.emailAddress.ToLower()] = $true }
                }
            }
        }
        if ($roomEmails.Count -gt 0) {
            Write-Log "Found $($roomEmails.Count) room resources via Places API" -Level "INFO"
        }
    }
    catch {
        # Place.Read.All may not be consented - this is optional
    }

    # ========================================================================
    # Known Room/Equipment license SKU IDs (fallback detection)
    # ========================================================================
    $roomSkuIds = @(
        "4b585984-651b-448a-9e53-3b10f069cf7f"  # Microsoft Teams Rooms Standard
        "6070a4c8-34c6-4937-8dfb-39a3b87bed76"  # Microsoft Teams Rooms Pro
        "c25e2b36-e161-4946-bef2-69239729f690"  # Microsoft Teams Rooms Basic
    )

    # ========================================================================
    # Process each user
    # ========================================================================
    Write-Log "Analyzing MFA status for $count users..." -Level "INFO"
    $psstyle.progress.view = "Classic"
    $errorCount = 0
    $caErrorCount = 0
    $rmauCount = 0

    foreach ($user in $allusers) {
        $i++
        $percentcomplete = [math]::Round((($i / $count) * 100), 2)
        Write-Progress -Activity "Checking [$count] user accounts..." -Status "$($i) - $($percentcomplete)% - $($user.DisplayName)" -PercentComplete $percentcomplete

        # Determine account category
        $accountCategory = "User"
        if (-not $user.UserPrincipalName) {
            Write-Log "Skipping user '$($user.DisplayName)' - null UserPrincipalName" -Level "WARNING"
            continue
        }
        $upnLower = $user.UserPrincipalName.ToLower()
        $mailLower = if ($user.Mail) { $user.Mail.ToLower() } else { "" }
        $displayLower = if ($user.DisplayName) { $user.DisplayName.ToLower() } else { "" }

        # 1. Check Exchange Online RecipientTypeDetails
        if ($mailboxTypes.Count -gt 0 -and $mailboxTypes.ContainsKey($upnLower)) {
            $mbType = $mailboxTypes[$upnLower]
            switch ($mbType) {
                "SharedMailbox"    { $accountCategory = "Shared Mailbox" }
                "RoomMailbox"      { $accountCategory = "Room" }
                "EquipmentMailbox" { $accountCategory = "Equipment" }
                "UserMailbox"      { $accountCategory = "User" }
                default            { $accountCategory = "User" }
            }
        }
        # 2. Check Places API results (for rooms not in report)
        elseif ($roomEmails.ContainsKey($upnLower) -or $roomEmails.ContainsKey($mailLower)) {
            $accountCategory = "Room"
        }
        # 3. Check Room/Equipment license SKUs
        elseif ($user.AssignedLicenses) {
            $userSkus = $user.AssignedLicenses | ForEach-Object { $_.SkuId }
            foreach ($sku in $roomSkuIds) {
                if ($userSkus -contains $sku) { $accountCategory = "Room"; break }
            }
        }
        # 4. Heuristic fallback based on UPN and display name patterns
        if ($accountCategory -eq "User") {
            # Room patterns
            if ($upnLower -match '^(room|meetingroom|conf|conference|board|huddle|res[-_])' -or
                $upnLower -match '[-_.](room|conf|meeting)@' -or
                $displayLower -match '^(room|meeting room|conference|board room|huddle)') {
                $accountCategory = "Room"
            }
            # Shared mailbox patterns
            elseif ($upnLower -match '^(shared[-_.]|info@|noreply@|no-reply@|mailbox[-_.]|reception@|helpdesk@|support@|admin@|accounts@|hr@|finance@|sales@|marketing@)' -or
                    $upnLower -match '[-_.]shared@' -or
                    $displayLower -match '^(shared mailbox|shared -|info |noreply)') {
                $accountCategory = "Shared Mailbox"
            }
            # Equipment patterns
            elseif ($upnLower -match '^(equip|equipment|projector|av[-_]|printer|display|kiosk|lobby)' -or
                    $displayLower -match '^(equipment|projector|printer|display|kiosk)') {
                $accountCategory = "Equipment"
            }
        }

        # Last sign-in (requires AuditLog.Read.All; omitted gracefully if unavailable)
        $lastSignIn = $null
        if ($signInActivityAvailable -and $user.SignInActivity -and $user.SignInActivity.LastSignInDateTime) {
            $lastSignIn = $user.SignInActivity.LastSignInDateTime.ToString("yyyy-MM-dd")
        }

        # Licensed check
        $isLicensed = ($user.AssignedLicenses -and $user.AssignedLicenses.Count -gt 0)

        # Admin check
        $isAdmin = $adminUserIds.ContainsKey($user.Id)

        try {
            $UserAuth = Get-MgBetaUserAuthenticationMethod -UserId $user.UserPrincipalName -ErrorAction Stop
            $output = [PSCustomObject]@{
                user              = $user.DisplayName
                upn               = $user.UserPrincipalName
                usertype          = $user.UserType
                accountCategory   = $accountCategory
                enabled           = $user.AccountEnabled
                MFAstatus         = "disabled"
                authApp           = $false
                phoneSMS          = $false
                fido              = $false
                helloForBusiness  = $false
                emailAuth         = $false
                tempPass          = $false
                passwordLess      = $false
                softwareAuth      = $false
                appPassword       = $false
                authDevice        = $false
                authPhoneNr       = $false
                phoneNumber       = $false
                SSPREmail         = $false
                isAdmin           = $isAdmin
                licensed          = $isLicensed
                lastSignIn        = $lastSignIn
                RiskLevel         = "N/A"
                RiskNotes         = ""
            }

            foreach ($method in $UserAuth) {
                Switch ($method.AdditionalProperties["@odata.type"]) {
                    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                        $output.authApp = $true
                        $output.authDevice = $method.AdditionalProperties["displayName"]
                        $output.MFAstatus = "enabled"
                    }
                    "#microsoft.graph.phoneAuthenticationMethod" {
                        $output.phoneSMS = $true
                        $phoneType = $method.AdditionalProperties["phoneType"]
                        $phoneNum = $method.AdditionalProperties["phoneNumber"]
                        $output.authPhoneNr = "$phoneType $phoneNum"
                        $output.phoneNumber = $phoneNum
                        $output.MFAstatus = "enabled"
                    }
                    "#microsoft.graph.fido2AuthenticationMethod" {
                        $output.fido = $true
                        $output.MFAstatus = "enabled"
                    }
                    "#microsoft.graph.passwordAuthenticationMethod" {
                        if ($method.AdditionalProperties.ContainsKey("displayName") -and
                            $method.AdditionalProperties["displayName"] -like "*App Password*") {
                            $output.appPassword = $true
                        }
                        if ($output.MFAstatus -ne "enabled") { $output.MFAstatus = "disabled" }
                    }
                    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
                        $output.helloForBusiness = $true
                        $output.MFAstatus = "enabled"
                    }
                    "#microsoft.graph.emailAuthenticationMethod" {
                        $output.emailAuth = $true
                        $output.SSPREmail = $method.AdditionalProperties["emailAddress"]
                        $output.MFAstatus = "enabled"
                    }
                    "#microsoft.graph.temporaryAccessPassAuthenticationMethod" {
                        # Only count TAP if it's still usable (not expired)
                        $isUsable = $method.AdditionalProperties["isUsable"]
                        if ($isUsable -eq $true) {
                            $output.tempPass = $true
                            $output.MFAstatus = "enabled"
                        }
                    }
                    "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod" {
                        $output.passwordLess = $true
                        $output.MFAstatus = "enabled"
                    }
                    "#microsoft.graph.softwareOathAuthenticationMethod" {
                        $output.softwareAuth = $true
                        $output.MFAstatus = "enabled"
                    }
                }
            }

            # Calculate Risk Level
            if (-not $output.enabled) {
                $output.RiskLevel = "N/A"
                $output.RiskNotes = "Account disabled"
            }
            elseif ($output.MFAstatus -eq "disabled") {
                $output.RiskLevel = "Critical"
                $output.RiskNotes = "No MFA registered"
            }
            elseif ($output.phoneSMS -and -not $output.authApp -and -not $output.fido -and -not $output.helloForBusiness -and -not $output.passwordLess -and -not $output.softwareAuth) {
                $output.RiskLevel = "High"
                $output.RiskNotes = "SMS-only (SIM-swap vulnerable)"
            }
            elseif (-not $output.fido -and -not $output.helloForBusiness) {
                $output.RiskLevel = "Medium"
                $output.RiskNotes = "No phishing-resistant method"
            }
            elseif ($output.phoneSMS -or $output.emailAuth -or $output.softwareAuth -or $output.authApp) {
                # Has phishing-resistant but also weak methods registered
                $weakMethods = @()
                if ($output.phoneSMS) { $weakMethods += "Phone/SMS" }
                if ($output.emailAuth) { $weakMethods += "Email" }
                if ($output.softwareAuth) { $weakMethods += "Software OATH" }
                if ($output.authApp) { $weakMethods += "Authenticator" }
                $output.RiskLevel = "Good"
                $output.RiskNotes = "Phishing-resistant + weak methods: $($weakMethods -join ', ')"
            }
            else {
                $output.RiskLevel = "Secure"
                $output.RiskNotes = "All methods phishing-resistant"
            }

            $export.Add($output) | Out-Null
        }
        catch {
            $errorCount++
            if ($_.Exception.Message -match "accessDenied") {
                # Restricted Management AU - cannot read auth methods
                $rmauCount++
                $output = [PSCustomObject]@{
                    user              = $user.DisplayName
                    upn               = $user.UserPrincipalName
                    usertype          = $user.UserType
                    accountCategory   = $accountCategory
                    enabled           = $user.AccountEnabled
                    MFAstatus         = "unknown"
                    authApp           = $false
                    phoneSMS          = $false
                    fido              = $false
                    helloForBusiness  = $false
                    emailAuth         = $false
                    tempPass          = $false
                    passwordLess      = $false
                    softwareAuth      = $false
                    appPassword       = $false
                    authDevice        = "RMAU Protected"
                    authPhoneNr       = $false
                    phoneNumber       = $false
                    SSPREmail         = $false
                    isAdmin           = $isAdmin
                    licensed          = $isLicensed
                    lastSignIn        = $lastSignIn
                    RiskLevel         = "N/A"
                    RiskNotes         = "Restricted Management AU (access denied)"
                }
                $export.Add($output) | Out-Null
            }
            elseif ($_.Exception.Message -match "LocationConditionEvaluationSatisfied|InvalidAuthenticationToken|Continuous access evaluation") {
                $caErrorCount++
                $output = [PSCustomObject]@{
                    user              = $user.DisplayName
                    upn               = $user.UserPrincipalName
                    usertype          = $user.UserType
                    accountCategory   = $accountCategory
                    enabled           = $user.AccountEnabled
                    MFAstatus         = "unknown"
                    authApp           = $false
                    phoneSMS          = $false
                    fido              = $false
                    helloForBusiness  = $false
                    emailAuth         = $false
                    tempPass          = $false
                    passwordLess      = $false
                    softwareAuth      = $false
                    appPassword       = $false
                    authDevice        = "CA Policy Blocked"
                    authPhoneNr       = $false
                    phoneNumber       = $false
                    SSPREmail         = $false
                    isAdmin           = $isAdmin
                    licensed          = $isLicensed
                    lastSignIn        = $lastSignIn
                    RiskLevel         = "N/A"
                    RiskNotes         = "CA policy blocked assessment"
                }
                $export.Add($output) | Out-Null
            }
            else {
                Write-Log "Error processing user $($user.UserPrincipalName): $($_.Exception.Message)" -Level "WARNING"
            }
        }
    }

    Write-Progress -Activity "Processing complete" -Completed
    Write-Log "User analysis completed. Processed $($export.Count) users." -Level "SUCCESS"

    if ($errorCount -gt 0) {
        Write-Log "Processing completed with $errorCount errors (RMAU protected: $rmauCount, CA blocked: $caErrorCount)" -Level "WARNING"
    }

    # ========================================================================
    # Console Summary
    # ========================================================================
    $date = Get-Date -Format "yyyy-MM-dd"
    $totalUsers = $export.Count
    $enabledAccounts = ($export | Where-Object { $_.enabled -eq $true }).Count
    $mfaEnabled = ($export | Where-Object { $_.MFAstatus -eq "enabled" }).Count
    $mfaDisabled = ($export | Where-Object { $_.MFAstatus -eq "disabled" }).Count
    $mfaUnknown = ($export | Where-Object { $_.MFAstatus -eq "unknown" }).Count
    $appPasswordUsers = ($export | Where-Object { $_.appPassword -eq $true }).Count

    # Interactive account pool: enabled Members + enabled Admins (excludes guests,
    # disabled accounts, and service account categories like room/shared/equipment).
    # This matches the denominator used by Entra's Authentication Methods monitoring view.
    $serviceCategories = @('Shared Mailbox', 'Room Mailbox', 'Equipment Mailbox')
    $interactiveAccounts = $export | Where-Object {
        $_.enabled -eq $true -and
        $_.usertype -eq 'Member' -and
        $_.accountCategory -notin $serviceCategories
    }
    $interactiveCount = $interactiveAccounts.Count
    $mfaEnabledInteractive = ($interactiveAccounts | Where-Object { $_.MFAstatus -eq "enabled" }).Count
    $mfaPctInteractive = if ($interactiveCount -gt 0) { [math]::Round(($mfaEnabledInteractive / $interactiveCount) * 100, 1) } else { 0 }

    # Segment by type
    $memberAccounts = $export | Where-Object { $_.usertype -eq 'Member' -and -not $_.isAdmin }
    $guestAccounts = $export | Where-Object { $_.usertype -eq 'Guest' }
    $adminAccounts = $export | Where-Object { $_.isAdmin }

    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host "Entra ID MFA Report - Generated: $date" -ForegroundColor Green
    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host "`nACCOUNT SCOPE:" -ForegroundColor Yellow
    Write-Host "  Total accounts (all types):        $totalUsers" -ForegroundColor White
    Write-Host "  Interactive accounts (Entra view): $interactiveCount  (enabled Members, excl. room/shared/equipment)" -ForegroundColor White
    Write-Host "  MFA coverage - all accounts:       $([math]::Round(($mfaEnabled / $totalUsers) * 100, 1))%  ($mfaEnabled / $totalUsers)" -ForegroundColor White
    Write-Host "  MFA coverage - interactive only:   ${mfaPctInteractive}%  ($mfaEnabledInteractive / $interactiveCount)  [matches Entra portal view]" -ForegroundColor Cyan

    # --- USERS (Members, non-admin) ---
    Write-Host "`nUSERS (Members, non-admin):" -ForegroundColor Yellow
    $mEnabled = ($memberAccounts | Where-Object { $_.enabled }).Count
    $mMfaOn = ($memberAccounts | Where-Object { $_.MFAstatus -eq "enabled" }).Count
    $mMfaOffEnabled = ($memberAccounts | Where-Object { $_.MFAstatus -eq "disabled" -and $_.enabled }).Count
    $mMfaOffDisabled = ($memberAccounts | Where-Object { $_.MFAstatus -eq "disabled" -and -not $_.enabled }).Count
    $mTotal = $memberAccounts.Count
    Write-Host "  Total: $mTotal"
    Write-Host "  Accounts Enabled: $mEnabled" -ForegroundColor White
    Write-Host "  MFA Enabled: $mMfaOn" -ForegroundColor Green
    Write-Host "  MFA Disabled (account enabled): $mMfaOffEnabled" -ForegroundColor Red
    Write-Host "  MFA Disabled (account disabled): $mMfaOffDisabled" -ForegroundColor Gray

    # --- GUEST ACCOUNTS ---
    Write-Host "`nGUEST ACCOUNTS:" -ForegroundColor Yellow
    $gEnabled = ($guestAccounts | Where-Object { $_.enabled }).Count
    $gMfaOn = ($guestAccounts | Where-Object { $_.MFAstatus -eq "enabled" }).Count
    $gMfaOffEnabled = ($guestAccounts | Where-Object { $_.MFAstatus -eq "disabled" -and $_.enabled }).Count
    $gMfaOffDisabled = ($guestAccounts | Where-Object { $_.MFAstatus -eq "disabled" -and -not $_.enabled }).Count
    $gTotal = $guestAccounts.Count
    Write-Host "  Total: $gTotal"
    Write-Host "  Accounts Enabled: $gEnabled" -ForegroundColor White
    Write-Host "  MFA Enabled: $gMfaOn" -ForegroundColor Green
    Write-Host "  MFA Disabled (account enabled): $gMfaOffEnabled" -ForegroundColor Red
    Write-Host "  MFA Disabled (account disabled): $gMfaOffDisabled" -ForegroundColor Gray

    # --- ADMIN ACCOUNTS ---
    Write-Host "`nADMIN ACCOUNTS:" -ForegroundColor Yellow
    $aEnabled = ($adminAccounts | Where-Object { $_.enabled }).Count
    $aMfaOn = ($adminAccounts | Where-Object { $_.MFAstatus -eq "enabled" }).Count
    $aMfaOffEnabled = ($adminAccounts | Where-Object { $_.MFAstatus -eq "disabled" -and $_.enabled }).Count
    $aMfaOffDisabled = ($adminAccounts | Where-Object { $_.MFAstatus -eq "disabled" -and -not $_.enabled }).Count
    $aTotal = $adminAccounts.Count
    Write-Host "  Total: $aTotal"
    Write-Host "  Accounts Enabled: $aEnabled" -ForegroundColor White
    Write-Host "  MFA Enabled: $aMfaOn" -ForegroundColor Green
    Write-Host "  MFA Disabled (account enabled): $aMfaOffEnabled" -ForegroundColor Red
    Write-Host "  MFA Disabled (account disabled): $aMfaOffDisabled" -ForegroundColor Gray

    # --- RISK SUMMARY (all accounts) ---
    Write-Host "`nRISK SUMMARY:" -ForegroundColor Yellow
    $riskCritical = ($export | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $riskHigh = ($export | Where-Object { $_.RiskLevel -eq "High" }).Count
    $riskMedium = ($export | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $riskGood = ($export | Where-Object { $_.RiskLevel -eq "Good" }).Count
    $riskSecure = ($export | Where-Object { $_.RiskLevel -eq "Secure" }).Count
    $riskNA = ($export | Where-Object { $_.RiskLevel -eq "N/A" }).Count
    Write-Host "  Critical (No MFA): $riskCritical" -ForegroundColor Red
    Write-Host "  High (SMS-only): $riskHigh" -ForegroundColor DarkYellow
    Write-Host "  Medium (No phishing-resistant): $riskMedium" -ForegroundColor Yellow
    Write-Host "  Good (Has phishing-resistant + weak methods): $riskGood" -ForegroundColor Cyan
    Write-Host "  Secure (All methods phishing-resistant): $riskSecure" -ForegroundColor Green
    Write-Host "  N/A (Disabled/Blocked): $riskNA" -ForegroundColor Gray

    # --- MFA METHODS ---
    Write-Host "`nMFA METHODS (users with MFA enabled):" -ForegroundColor Yellow
    $mfaUsers = $export | Where-Object { $_.MFAstatus -eq "enabled" }
    if ($mfaUsers.Count -gt 0) {
        $mc = $mfaUsers.Count
        $methodStats = @(
            @{ Name = 'Authenticator App'; Count = ($mfaUsers | Where-Object { $_.authApp }).Count },
            @{ Name = 'Phone/SMS'; Count = ($mfaUsers | Where-Object { $_.phoneSMS }).Count },
            @{ Name = 'FIDO2'; Count = ($mfaUsers | Where-Object { $_.fido }).Count },
            @{ Name = 'Windows Hello'; Count = ($mfaUsers | Where-Object { $_.helloForBusiness }).Count },
            @{ Name = 'Passwordless'; Count = ($mfaUsers | Where-Object { $_.passwordLess }).Count },
            @{ Name = 'Software OATH'; Count = ($mfaUsers | Where-Object { $_.softwareAuth }).Count },
            @{ Name = 'Email'; Count = ($mfaUsers | Where-Object { $_.emailAuth }).Count },
            @{ Name = 'TAP'; Count = ($mfaUsers | Where-Object { $_.tempPass }).Count }
        ) | Sort-Object { $_.Count } -Descending | Where-Object { $_.Count -gt 0 }

        foreach ($method in $methodStats) {
            $pct = [math]::Round(($method.Count / $mc) * 100, 1)
            Write-Host "  $($method.Name): $($method.Count) ($pct%)"
        }
    }

    # --- PHONE NUMBERS BY COUNTRY ---
    $phoneUsers = $export | Where-Object { $_.phoneNumber -and $_.phoneNumber -ne $false }
    if ($phoneUsers.Count -gt 0) {
        Write-Host "`nPHONE NUMBERS BY COUNTRY:" -ForegroundColor Yellow
        $countryCounts = @{}
        foreach ($pu in $phoneUsers) {
            $country = Get-CountryFromPhone -PhoneNumber $pu.phoneNumber
            if ($country) {
                if ($countryCounts.ContainsKey($country)) { $countryCounts[$country]++ }
                else { $countryCounts[$country] = 1 }
            }
        }
        $countryCounts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            Write-Host "  $($_.Key): $($_.Value)"
        }
    }

    Write-Host ("=" * 80) -ForegroundColor Green

    # ========================================================================
    # Build Summary Object
    # ========================================================================
    $enhancedReport = [PSCustomObject]@{
        Date                    = $date
        TotalUsers              = $totalUsers
        EnabledAccounts         = $enabledAccounts
        EnabledAccountsPercentage = [math]::Round(($enabledAccounts / $totalUsers) * 100, 2)
        MFAEnabled              = $mfaEnabled
        MFAEnabledPercentage    = [math]::Round(($mfaEnabled / $totalUsers) * 100, 2)
        MFADisabled             = $mfaDisabled
        MFADisabledPercentage   = [math]::Round(($mfaDisabled / $totalUsers) * 100, 2)
        InteractiveAccounts     = $interactiveCount
        MFAEnabledInteractive   = $mfaEnabledInteractive
        MFAEnabledInteractivePct = $mfaPctInteractive
        RiskCritical            = $riskCritical
        RiskHigh                = $riskHigh
        RiskMedium              = $riskMedium
        RiskGood                = $riskGood
        RiskSecure              = $riskSecure
        RiskNA                  = $riskNA
        AdminCount              = $adminAccounts.Count
        AdminsWithoutMFA        = $aMfaOffEnabled
        AppPasswordUsers        = $appPasswordUsers
    }

    # ========================================================================
    # Export CSV
    # ========================================================================
    if ($ExportToCsv) {
        $ExportDirectory = ".\exports"
        if (!(Test-Path $ExportDirectory)) {
            New-Item -ItemType Directory -Path $ExportDirectory -Force | Out-Null
        }

        $csvFilename = Join-Path $ExportDirectory "MFADetailedReport-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $summaryFilename = Join-Path $ExportDirectory "MFASummaryReport-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"

        Write-Log "Exporting detailed report to: $csvFilename" -Level "INFO"
        $export | Export-Csv $csvFilename -Delimiter ";" -Encoding UTF8 -NoTypeInformation

        Write-Log "Exporting summary to: $summaryFilename" -Level "INFO"
        $enhancedReport | Export-Csv $summaryFilename -Delimiter ";" -Encoding UTF8 -NoTypeInformation
    }

    # ========================================================================
    # Export HTML
    # ========================================================================
    if ($ExportToHtml) {
        $ExportDirectory = ".\exports"
        if (!(Test-Path $ExportDirectory)) {
            New-Item -ItemType Directory -Path $ExportDirectory -Force | Out-Null
        }

        # Get tenant name for filename
        $tenantName = "Unknown"
        try {
            $org = Get-MgOrganization -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($org -and $org.DisplayName) { $tenantName = $org.DisplayName }
        }
        catch { }

        $safetenantName = $tenantName -replace '[^\w\-]', '_'
        $htmlFilename = Join-Path $ExportDirectory "MFAReport-${safetenantName}-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"

        New-HtmlReport -UserData $export -Summary $enhancedReport -OutputPath $htmlFilename -TenantName $tenantName

        # Open report in Edge
        $htmlFullPath = (Resolve-Path $htmlFilename).Path
        $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        if (-not (Test-Path $edgePath)) {
            $edgePath = "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
        }
        if (Test-Path $edgePath) {
            $fileUri = ([System.Uri]$htmlFullPath).AbsoluteUri
            Start-Process -FilePath $edgePath -ArgumentList "--new-window", $fileUri
            Write-Log "Report opened in Edge: $fileUri" -Level "INFO"
        }
        else {
            Write-Log "Edge not found. Open manually: $htmlFullPath" -Level "WARNING"
        }
    }

    # ========================================================================
    # Export Summary
    # ========================================================================
    if ($ExportToCsv -or $ExportToHtml) {
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "EXPORTED FILES:" -ForegroundColor Cyan
        if ($ExportToCsv) {
            Write-Host "  CSV Detail:  $((Resolve-Path $csvFilename).Path)" -ForegroundColor White
            Write-Host "  CSV Summary: $((Resolve-Path $summaryFilename).Path)" -ForegroundColor White
        }
        if ($ExportToHtml) {
            Write-Host "  HTML Report: $htmlFullPath" -ForegroundColor White
        }
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Yellow
        Write-Host "  DATA PRIVACY NOTICE" -ForegroundColor Yellow
        Write-Host ("=" * 80) -ForegroundColor Yellow
        Write-Host "  These files contain personal data (names, email addresses, phone" -ForegroundColor Yellow
        Write-Host "  numbers, sign-in activity). Handle in accordance with your" -ForegroundColor Yellow
        Write-Host "  organisation's data protection policy (GDPR / applicable law):" -ForegroundColor Yellow
        Write-Host "    * Store in a secure, access-controlled location" -ForegroundColor Yellow
        Write-Host "    * Share only with authorised recipients" -ForegroundColor Yellow
        Write-Host "    * Retain only as long as operationally required" -ForegroundColor Yellow
        Write-Host "    * Dispose of securely when no longer needed" -ForegroundColor Yellow
        Write-Host ("=" * 80) -ForegroundColor Yellow
    }

    Write-Log "MFA Report generation completed successfully" -Level "SUCCESS"
}
catch {
    Write-Log "Error during script execution: $($_.Exception.Message)" -Level "ERROR"
    Write-Host "  ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
}

} # End of Invoke-MFAReport function

# ============================================================================
# Main Menu Loop
# ============================================================================
do {
    Show-MainMenu
    $choice = Read-Host "  Enter choice (1-3, Q to quit)"
    $choice = $choice.Trim().ToUpper()

    switch ($choice) {
        '1' { Connect-Graph }
        '2' { Connect-Exo }
        '3' {
            $outputOptions = Show-OutputMenu
            Invoke-MFAReport -OutputOptions $outputOptions
        }
        'Q' {
            # Disconnect services
            $exoSession = Get-ConnectionInformation -ErrorAction SilentlyContinue
            if ($exoSession) {
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
            }
            $ctx = Get-MgContext -ErrorAction SilentlyContinue
            if ($ctx) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            }
            Write-Host ""
            Write-Host "  Goodbye!" -ForegroundColor Cyan
            Write-Host ""
            break
        }
        default {
            Write-Host "  Invalid choice. Please enter 1-3 or Q." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($choice -ne 'Q')
