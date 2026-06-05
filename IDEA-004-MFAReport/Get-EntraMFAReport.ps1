<#
.SYNOPSIS
    Interactive menu-driven MFA report for Microsoft Entra ID with HTML output.

.DESCRIPTION
    Provides an interactive menu experience for generating comprehensive MFA reports.
    Analyzes MFA registration status for all users in the tenant using Microsoft Graph
    Beta API (Get-MgBetaUserAuthenticationMethod).

    OUTPUT — HTML REPORT
    --------------------
    The self-contained HTML report consists of three main sections:

    1. MFA METHOD DISTRIBUTION BAR
       A full-width stacked bar showing how all enabled accounts are distributed across
       four MFA strength tiers, left to right from weakest to strongest:

       - No MFA (red)            : Account is enabled but has no MFA method registered.
       - Weak only (orange)      : Has SMS, voice call, or email OTP registered, but no
                                   Authenticator app and no phishing-resistant method.
       - Authenticator only (amber): Has the Microsoft Authenticator app registered, but
                                   no phishing-resistant method.
       - Phishing-resistant (green): Has at least one of FIDO2 security key, Windows Hello
                                   for Business, or Passwordless phone sign-in registered.

       Note: Categories are mutually exclusive. A user with both Authenticator and FIDO2
       is counted only in the Phishing-resistant segment.

    2. ADMINS AND MEMBERS STAT CARDS
       Two columns of three mini-cards, one column per group:

       - Admins  : Enabled accounts that hold at least one Entra directory or privileged
                   role (as detected by Get-MgDirectoryRole membership).
       - Members : Enabled accounts with userType = Member, excluding admins. Includes
                   all account categories (user, room, shared, equipment) — any enabled
                   member account can be targeted and needs MFA protection.

       Each column shows three cards with counts as X / N (X = matching accounts, N = total
       in that group):

       - Without MFA        : No MFA method registered. Card is red if count > 0, green if 0.
       - Weak MFA           : Has SMS, voice, or email registered (regardless of other methods).
                              Card is orange if count > 0, green if 0. Note: a user with both
                              FIDO2 and SMS counts here, because the weak method can still be
                              targeted by attackers (SIM swap, SS7 interception, email phishing).
       - Phishing-resistant : Has FIDO2, Windows Hello for Business, or Passwordless registered.
                              Always blue. Counts users who have at least one strong method,
                              even if they also have weaker methods registered alongside it.

       A footer line below the cards shows a compact guest summary:
       "Guests (N): X without MFA · Y weak MFA · Z with MFA"

    3. RISK SCORES (pie chart)
       The risk score is assigned per account based on the strongest and weakest methods
       registered. Possible values:

       - Critical : No MFA registered. Account relies solely on password — full compromise
                    risk from credential stuffing, phishing, or brute force.
       - High     : SMS or voice call is the only MFA method. Vulnerable to SIM-swap attacks
                    and SS7 protocol exploitation. Provides weak but non-zero protection.
       - Medium   : Has MFA (e.g. Authenticator, Software OATH, email OTP) but no phishing-
                    resistant method. Vulnerable to real-time phishing proxies (AiTM) that
                    can intercept push approvals or TOTP codes.
       - Good     : Has at least one phishing-resistant method (FIDO2, Hello, Passwordless)
                    but also has weaker methods registered alongside it. The weak methods
                    represent residual attack surface that could be exploited as fallback.
       - Secure   : All registered MFA methods are phishing-resistant. No weak fallback
                    methods registered. Highest assurance level achievable.
       - N/A      : Account is disabled. Risk is not assessed for disabled accounts.

    Other features:
    - Phone number country distribution pie chart (from registered phone MFA numbers)
    - Interactive filters: risk level, MFA status, user type, account category, sign-in
      activity, licensing, admin status, and MFA method presence (AND/OR logic)
    - Sortable table with all accounts and their MFA method details
    - Account category detection (User/Room/Shared Mailbox/Equipment)
    - Admin status, licensing, and last sign-in activity tracking

.PARAMETER LogDirectory
    Directory path for log files. Defaults to .\Logs

.EXAMPLE
    .\Get-EntraMFAReport.ps1
    Launches the interactive menu to connect to services and generate the MFA report.

.EXAMPLE
    .\Get-EntraMFAReport.ps1 -LogDirectory "C:\Logs"
    Launches with a custom log directory.

.EXAMPLE
    .\Get-EntraMFAReport.ps1 -DiagnosticMode
    Launches with diagnostic mode enabled. All output (including errors hidden by
    Clear-Host) is captured to a transcript file in LogDirectory. Write-Verbose
    output is enabled, showing the exact scopes granted by the current token.
    Use this to troubleshoot Graph permission and consent issues.

.NOTES
    Requires a Microsoft Graph connection with these scopes:
    - User.Read.All
    - Directory.Read.All
    - UserAuthenticationMethod.Read.All
    - AuditLog.Read.All (for sign-in activity data)
    
    Also requires Exchange Online connectivity (Connect-ExchangeOnline) for authoritative
    mailbox-type detection (shared/room/equipment). The script will connect automatically
    if no existing EXO session is found.

    TROUBLESHOOTING - PERMISSION / CONSENT ERRORS (403 Authorization_RequestDenied):
    ---------------------------------------------------------------------------------
    These errors are almost always a WAM token cache problem combined with missing
    admin consent. WAM (Windows Account Manager) is the Windows credential broker used
    by the Graph PowerShell SDK on Windows. It caches tokens aggressively and will
    silently return a stale minimal token (openid, profile, User.Read, email) even when
    broader scopes are requested — without showing a browser prompt.

    IMPORTANT: Set-MgGraphOption -DisableLoginByWAM $true only works with a custom
    ClientId (your own Entra app registration). It is silently ignored when using the
    default Microsoft Graph Command Line Tools ClientId (14d82eec-...).

    STEP 1 — Clear the stale WAM token cache:
        Run once in any PowerShell terminal:
            Remove-Item "$env:LOCALAPPDATA\.IdentityService" -Recurse -Force -ErrorAction SilentlyContinue

    STEP 2 — Reconnect using menu option [1]. WAM will now fetch a fresh token from
        Entra that includes the newly consented scopes.

    If the problem persists, run with -DiagnosticMode and check the transcript for
    "Granted scopes" in the VERBOSE output to confirm which scopes the token contains.
    
    Author: Per-Torben Sørensen
    Version: 2.3
    Created: October 2025
    Tested on: PowerShell 7.6
               ExchangeOnlineManagement 3.9.0
               Microsoft.Graph 2.34.0
               Microsoft.Graph.Beta 2.34.0
    Updated: June 2026 - Added HTML report, risk levels, account categories, sign-in activity
                       - Replaced usage-report mailbox detection with Exchange Online RecipientTypeDetails
                       - Edge now opens report in normal window instead of guest mode
                       - Added -DiagnosticMode switch (transcript + verbose logging)
                       - Added pre-flight scope check with actionable consent fix instructions
                       - WAM token cache troubleshooting documented and handled in Connect-Graph
                       - Fixed Authorization_RequestDenied misclassified as AuditLog error
                       - Redesigned HTML dashboard: MFA distribution bar, admin/member/guest
                         stat cards with X/N fractions, risk and phone pie charts
                       - MFA strength model: No MFA / Weak (SMS+voice+email) /
                         Phishing-resistant (FIDO2+Hello+Passwordless)
                       - All dashboard stats computed from DATA array at runtime (JS)

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
    [string]$LogDirectory = ".\Logs",

    # Enable diagnostic mode: starts a transcript and enables Write-Verbose output.
    # The transcript captures everything (including what Clear-Host hides) to a file
    # in LogDirectory. Use this to troubleshoot Graph permission / consent issues.
    [switch]$DiagnosticMode
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

# ============================================================================
# Diagnostic Mode — transcript + verbose
# The transcript captures all console output to a file and is NOT cleared by
# Clear-Host, making it ideal for catching errors that disappear from the screen.
# ============================================================================
$script:DiagnosticTranscriptFile = $null
if ($DiagnosticMode) {
    $script:DiagnosticTranscriptFile = Join-Path $LogDirectory "Get-EntraMFAReport-Diagnostic-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    Start-Transcript -Path $script:DiagnosticTranscriptFile -Append -Force | Out-Null
    $VerbosePreference = 'Continue'
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Magenta
    Write-Host "  DIAGNOSTIC MODE ACTIVE" -ForegroundColor Magenta
    Write-Host "  All output is captured to (survives Clear-Host):" -ForegroundColor Magenta
    Write-Host "  Transcript : $script:DiagnosticTranscriptFile" -ForegroundColor Magenta
    Write-Host "  Log file   : $LogFile" -ForegroundColor Magenta
    Write-Host ("=" * 70) -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  Press any key to continue to the main menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

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
    if ($DiagnosticMode) {
        Write-Host "  [DIAGNOSTIC MODE - transcript active: $script:DiagnosticTranscriptFile]" -ForegroundColor Magenta
    }
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

        # WAM can cause Get-MgContext to return null immediately after connect.
        # Retry briefly to let the token propagate.
        $ctx = $null
        for ($attempt = 1; $attempt -le 5; $attempt++) {
            $ctx = Get-MgContext -ErrorAction SilentlyContinue
            if ($ctx) { break }
            Start-Sleep -Milliseconds 500
        }

        if ($ctx) {
            Write-Host "  ✓ Connected (Tenant: $($ctx.TenantId))" -ForegroundColor Green
            Write-Log "Connected to Microsoft Graph (Tenant: $($ctx.TenantId))" -Level "SUCCESS"
            Write-Verbose "Graph account   : $($ctx.Account)"
            Write-Verbose "Graph auth type : $($ctx.AuthType)"
            Write-Verbose "Graph tenant    : $($ctx.TenantId)"
            Write-Verbose "Granted scopes  : $($ctx.Scopes -join ', ')"
            $missing = $requiredScopes | Where-Object { $ctx.Scopes -notcontains $_ }
            if ($missing) {
                Write-Host ""
                Write-Host "  ⚠ WARNING: The following required scopes were NOT granted:" -ForegroundColor Yellow
                foreach ($s in $missing) { Write-Host "      - $s" -ForegroundColor Yellow }
                Write-Host ""
                Write-Host "  This is a consent issue. To fix it, a Global Admin must:" -ForegroundColor Cyan
                Write-Host "    1. Go to: Entra admin center > Enterprise Applications" -ForegroundColor White
                Write-Host "    2. Search for: 'Microsoft Graph Command Line Tools'" -ForegroundColor White
                Write-Host "    3. Click Permissions > Grant admin consent for your organisation" -ForegroundColor White
                Write-Host "  OR re-run this script and check 'Consent on behalf of your organization'" -ForegroundColor White
                Write-Host "  in the browser login prompt (WAM has been disabled for this session)." -ForegroundColor White
                Write-Host ""
                Write-Log "Missing scopes after connect: $($missing -join ', ')" -Level "WARNING"
            }
            else {
                Write-Host "  ✓ All required scopes granted" -ForegroundColor Green
            }
        }
        else {
            Write-Host "  ✗ Connection failed - no context established" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  ✗ Connection failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Graph connection failed: $($_.Exception.Message)" -Level "ERROR"
        Write-Verbose "Full exception   : $($_.ToString())"
        Write-Verbose "Exception type   : $($_.Exception.GetType().FullName)"
        Write-Verbose "Stack trace      : $($_.ScriptStackTrace)"
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
    $mfaMembersCount = $Summary.MFAEnabledMembers
    $enabledMemberCount = $Summary.EnabledMemberAccounts
    $membersNoMFA = $Summary.MembersNoMFA
    $membersWeakMFA = $Summary.MembersWeakMFA
    $membersPhishingResistant = $Summary.MembersPhishingResistant
    $mfaGuestsCount = $Summary.MFAEnabledGuests
    $guestCount = $Summary.GuestAccounts
    $guestsNoMFA = $Summary.GuestsNoMFA
    $guestsWeakMFA = $Summary.GuestsWeakMFA
    $disabledCount = $Summary.DisabledAccounts
    $adminTotal = $Summary.AdminCount
    $adminsMFA = $Summary.AdminsMFA
    $adminsNoMFA = $Summary.AdminsNoMFA
    $adminsWeakMFA = $Summary.AdminsWeakMFA
    $adminsPhishingResistant = $Summary.AdminsPhishingResistant
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
.pii-notice { background: #fff8e1; border: 1px solid #f9a825; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px; font-size: 0.85em; color: #5d4037; display: flex; align-items: flex-start; gap: 12px; }
.pii-notice .pii-icon { font-size: 1.4em; flex-shrink: 0; line-height: 1.2; }
.pii-notice .pii-text strong { display: block; margin-bottom: 4px; color: #e65100; }
.pii-notice .pii-dismiss { margin-left: auto; cursor: pointer; font-size: 1.1em; color: #999; flex-shrink: 0; padding: 0 4px; }
.pii-notice .pii-dismiss:hover { color: #333; }
@media (max-width: 768px) { .filter-row { flex-direction: column; } .filter-group select, .filter-group input { min-width: 100%; } }
.summary-block { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 20px; }
.mfa-bar-track { display: flex; height: 28px; border-radius: 6px; overflow: hidden; margin-bottom: 10px; background: #eee; }
.mfa-bar-segment { height: 100%; transition: width 0.3s; }
.mfa-bar-legend { display: flex; flex-wrap: wrap; gap: 16px; font-size: 0.8em; color: #444; margin-bottom: 18px; padding-bottom: 14px; border-bottom: 1px solid #eee; }
.mfa-bar-legend-item { display: flex; align-items: center; gap: 5px; }
.mfa-bar-legend-swatch { width: 12px; height: 12px; border-radius: 3px; flex-shrink: 0; }
.summary-columns { display: grid; grid-template-columns: 1fr 1fr; gap: 0; }
.summary-col { padding: 0 20px; }
.summary-col:first-child { padding-left: 0; border-right: 2px solid #e0e0e0; }
.summary-col:last-child { padding-right: 0; }
.summary-col-header { display: flex; align-items: center; gap: 8px; font-size: 0.9em; font-weight: 700; color: #1a237e; margin-bottom: 12px; }
.summary-mini-cards { display: flex; gap: 10px; flex-wrap: wrap; }
.summary-mini-card { background: #f8f9fa; border-radius: 8px; padding: 10px 14px; flex: 1; min-width: 80px; text-align: center; border: 1px solid #e8e8e8; }
.summary-mini-card .smc-value { font-size: 1.6em; font-weight: 700; }
.summary-mini-card .smc-label { font-size: 0.72em; color: #666; margin-top: 2px; }
.summary-footer { margin-top: 14px; padding: 10px 0 4px; border-top: 2px solid #e0e0e0; font-size: 0.88em; font-weight: 500; color: #333; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.risk-dot { display: inline-block; width: 12px; height: 12px; border-radius: 3px; margin-right: 4px; vertical-align: middle; }
.pie-row { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
.pie-box-title { font-size: 0.9em; font-weight: 700; color: #1a237e; margin-bottom: 10px; }
.pie-box-inner { display: flex; align-items: center; gap: 16px; }
.pie-legend { display: flex; flex-direction: column; gap: 5px; }
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

<div class="summary-block" id="summaryBlock">
  <div id="mfaBarLabel" class="summary-col-header" style="margin-bottom:8px;"></div>
  <div class="mfa-bar-track" id="mfaBar"></div>
  <div class="mfa-bar-legend" id="mfaBarLegend"></div>
  <div class="summary-columns">
    <div class="summary-col">
      <div class="summary-col-header" id="adminColHeader">&#128737; Admins</div>
      <div class="summary-mini-cards" id="adminCards"></div>
    </div>
    <div class="summary-col">
      <div class="summary-col-header" id="memberColHeader">&#128101; Members</div>
      <div class="summary-mini-cards" id="memberCards"></div>
    </div>
  </div>
  <div class="summary-footer" id="summaryFooter"></div>
</div>

<div class="summary-block">
  <div class="pie-row">
    <div>
      <div class="pie-box-title">Risk Summary</div>
      <div class="pie-box-inner">
        <svg id="riskPie" width="90" height="90" viewBox="-1 -1 2 2" style="flex-shrink:0"></svg>
        <div class="pie-legend" id="riskPieLegend"></div>
      </div>
    </div>
    <div>
      <div class="pie-box-title">Phone Numbers by Country</div>
      <div class="pie-box-inner">
        <svg id="phonePie" width="90" height="90" viewBox="-1 -1 2 2" style="flex-shrink:0"></svg>
        <div class="pie-legend" id="phonePieLegend"></div>
      </div>
    </div>
  </div>
</div>

<div class="filters">
<h3>Filters</h3>
<div class="filter-row">
<div class="filter-group"><label>Search (Name / UPN / Phone)</label><input type="text" id="searchBox" placeholder="Name, UPN, or phone e.g. +46..."></div>
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
        if (search && !r.displayName.toLowerCase().includes(search) && !r.upn.toLowerCase().includes(search) && !r.phoneNumber.toLowerCase().includes(search)) return false;
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

function toggleSection(header) {
    header.classList.toggle('collapsed');
    const body = header.nextElementSibling;
    body.classList.toggle('hidden');
}

function renderSummary() {
    const isPhishRes  = m => m.includes('FIDO2') || m.includes('Windows Hello') || m.includes('Passwordless');
    const hasAuthApp  = m => m.includes('Authenticator');
    const hasWeakMeth = m => m.includes('Phone/SMS') || m.includes('Email');
    const isWeakOnly  = m => hasWeakMeth(m) && !isPhishRes(m) && !hasAuthApp(m);
    const isAuthOnly  = m => hasAuthApp(m) && !isPhishRes(m);

    const enabled = DATA.filter(r => r.accountStatus === 'Enabled');
    const admins  = enabled.filter(r => r.isAdmin === 'Yes');
    const members = enabled.filter(r => r.userType === 'Member' && r.isAdmin !== 'Yes');
    const guests  = enabled.filter(r => r.userType === 'Guest');
    const total   = enabled.length;

    // Stacked bar
    const barNoMFA   = enabled.filter(r => r.mfaStatus === 'Disabled').length;
    const barWeak    = enabled.filter(r => r.mfaStatus === 'Enabled' && isWeakOnly(r.mfaMethods)).length;
    const barAuth    = enabled.filter(r => r.mfaStatus === 'Enabled' && isAuthOnly(r.mfaMethods)).length;
    const barPhish   = enabled.filter(r => r.mfaStatus === 'Enabled' && isPhishRes(r.mfaMethods)).length;
    const barOther   = total - barNoMFA - barWeak - barAuth - barPhish;
    const pct = n => total > 0 ? (n / total * 100).toFixed(1) : 0;
    const segments = [
        { n: barNoMFA, color: '#d32f2f', label: 'No MFA' },
        { n: barWeak,  color: '#f57c00', label: 'Weak only (SMS/voice/email)' },
        { n: barAuth,  color: '#fbc02d', label: 'Authenticator only' },
        { n: barPhish, color: '#388e3c', label: 'Phishing-resistant' },
    ];
    if (barOther > 0) segments.push({ n: barOther, color: '#9e9e9e', label: 'Other MFA' });
    const bar = document.getElementById('mfaBar');
    document.getElementById('mfaBarLabel').textContent = 'MFA method distribution — all enabled accounts (' + total + ')';
    bar.innerHTML = segments.filter(s => s.n > 0).map(s =>
        '<div class="mfa-bar-segment" style="width:' + pct(s.n) + '%;background:' + s.color + '" title="' + s.label + ': ' + s.n + '"></div>'
    ).join('');
    document.getElementById('mfaBarLegend').innerHTML = segments.filter(s => s.n > 0).map(s =>
        '<span class="mfa-bar-legend-item"><span class="mfa-bar-legend-swatch" style="background:' + s.color + '"></span>' + s.label + ': <strong>' + s.n + '</strong> (' + pct(s.n) + '%)</span>'
    ).join('');

    // Mini card helper — val is X, total is N, renders X<small> / N</small>
    // Colours are applied as inline styles based on card type and count
    const mcStyles = {
        noMfa:  n => n > 0 ? { bg: '#ffebee', fg: '#c62828' } : { bg: '#e8f5e9', fg: '#388e3c' },
        weak:   n => n > 0 ? { bg: '#fff3e0', fg: '#f57c00' } : { bg: '#e8f5e9', fg: '#388e3c' },
        phish:  _  => ({ bg: '#e3f2fd', fg: '#1565c0' })
    };
    const mc = (val, total, lbl, s) => '<div class="summary-mini-card" style="background:' + s.bg + '"><div class="smc-value" style="color:' + s.fg + '">' + val + '<span style="font-size:0.58em;font-weight:400;color:#888"> / ' + total + '</span></div><div class="smc-label">' + lbl + '</div></div>';

    // Admins column
    const aNoMFA = admins.filter(r => r.mfaStatus === 'Disabled').length;
    const aWeak  = admins.filter(r => r.mfaStatus === 'Enabled' && hasWeakMeth(r.mfaMethods)).length;
    const aPhish = admins.filter(r => r.mfaStatus === 'Enabled' && isPhishRes(r.mfaMethods)).length;
    document.getElementById('adminColHeader').innerHTML = '&#128737; Admins (' + admins.length + ' accounts)';
    document.getElementById('adminCards').innerHTML =
        mc(aNoMFA, admins.length, 'Without MFA',        mcStyles.noMfa(aNoMFA)) +
        mc(aWeak,  admins.length, 'Weak MFA',            mcStyles.weak(aWeak)) +
        mc(aPhish, admins.length, 'Phishing-resistant',  mcStyles.phish());

    // Members column
    const mNoMFA = members.filter(r => r.mfaStatus === 'Disabled').length;
    const mWeak  = members.filter(r => r.mfaStatus === 'Enabled' && hasWeakMeth(r.mfaMethods)).length;
    const mPhish = members.filter(r => r.mfaStatus === 'Enabled' && isPhishRes(r.mfaMethods)).length;
    document.getElementById('memberColHeader').innerHTML = '&#128101; Members (' + members.length + ' enabled)';
    document.getElementById('memberCards').innerHTML =
        mc(mNoMFA, members.length, 'Without MFA',        mcStyles.noMfa(mNoMFA)) +
        mc(mWeak,  members.length, 'Weak MFA',            mcStyles.weak(mWeak)) +
        mc(mPhish, members.length, 'Phishing-resistant',  mcStyles.phish());

    // Footer: inline guest summary
    const gNoMFA = guests.filter(r => r.mfaStatus === 'Disabled').length;
    const gWeak  = guests.filter(r => r.mfaStatus === 'Enabled' && hasWeakMeth(r.mfaMethods)).length;
    const gMFA   = guests.filter(r => r.mfaStatus === 'Enabled').length;
    const gText  = 'Guests (' + guests.length + '): ' +
        gNoMFA + ' without MFA \xb7 ' + gWeak + ' weak MFA \xb7 ' + gMFA + ' with MFA';
    document.getElementById('summaryFooter').innerHTML = '<span>' + gText + '</span>';

    // Pie chart helper — draws SVG arc sectors from DATA
    function drawPie(svgId, legendId, segs) {
        const svgEl = document.getElementById(svgId);
        const lgdEl = document.getElementById(legendId);
        const tot = segs.reduce(function(s, d) { return s + d.v; }, 0);
        if (!svgEl || !lgdEl || tot === 0) return;
        let ang = -Math.PI / 2, paths = '', lgd = '';
        segs.forEach(function(s) {
            const frac = s.v / tot;
            const end = ang + frac * 2 * Math.PI;
            if (frac >= 0.9999) {
                paths += '<circle cx="0" cy="0" r="1" fill="' + s.c + '"/>';
            } else {
                const la = frac > 0.5 ? 1 : 0;
                const x1 = Math.cos(ang).toFixed(5), y1 = Math.sin(ang).toFixed(5);
                const x2 = Math.cos(end).toFixed(5),  y2 = Math.sin(end).toFixed(5);
                paths += '<path d="M0,0 L' + x1 + ',' + y1 + ' A1,1,0,' + la + ',1,' + x2 + ',' + y2 + ' Z" fill="' + s.c + '" stroke="white" stroke-width="0.03"/>';
            }
            lgd += '<div style="display:flex;align-items:center;gap:5px;font-size:0.78em;line-height:1.5">' +
                   '<span style="width:10px;height:10px;border-radius:2px;background:' + s.c + ';flex-shrink:0;display:inline-block"></span>' +
                   s.l + ': <strong>' + s.v + '</strong></div>';
            ang = end;
        });
        svgEl.innerHTML = paths;
        lgdEl.innerHTML = lgd;
    }

    // Risk pie
    const rCounts = {};
    DATA.forEach(r => { rCounts[r.riskLevel] = (rCounts[r.riskLevel] || 0) + 1; });
    const rColors = { Critical:'#d32f2f', High:'#f57c00', Medium:'#fbc02d', Good:'#0097a7', Secure:'#388e3c' };
    drawPie('riskPie', 'riskPieLegend',
        ['Critical','High','Medium','Good','Secure'].filter(k => rCounts[k]).map(k => ({ l: k, v: rCounts[k], c: rColors[k] }))
    );

    // Phone countries pie
    const phoneCounts = {};
    DATA.forEach(r => {
        if (r.phoneNumber) {
            const cc = r.phoneNumber.match(/^(\+\d{1,3})/);
            if (cc) { const k = cc[1]; phoneCounts[k] = (phoneCounts[k] || 0) + 1; }
        }
    });
    const phoneColors = ['#1565c0','#0097a7','#6a1b9a','#2e7d32','#f57c00','#c62828','#455a64','#ad1457'];
    const phoneSegs = Object.entries(phoneCounts).sort((a, b) => b[1] - a[1])
        .map(function(e, i) { return { l: e[0], v: e[1], c: phoneColors[i % phoneColors.length] }; });
    drawPie('phonePie', 'phonePieLegend', phoneSegs);
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
renderSummary();
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
    Write-Verbose "Graph account   : $($context.Account)"
    Write-Verbose "Graph auth type : $($context.AuthType)"
    Write-Verbose "Graph tenant    : $($context.TenantId)"
    Write-Verbose "Granted scopes  : $($context.Scopes -join ', ')"

    # ========================================================================
    # Pre-flight: verify all core scopes are present before making any calls.
    # WAM can silently reconnect with only basic OIDC scopes (openid/profile/
    # User.Read/email) even when broader scopes were requested.
    # ========================================================================
    $coreRequiredScopes = @('User.Read.All', 'Directory.Read.All', 'UserAuthenticationMethod.Read.All')
    $missingCoreScopes = $coreRequiredScopes | Where-Object { $context.Scopes -notcontains $_ }
    if ($missingCoreScopes) {
        Write-Host ""
        Write-Host "  ✗ Cannot run report - the following required scopes are missing:" -ForegroundColor Red
        foreach ($s in $missingCoreScopes) { Write-Host "      - $s" -ForegroundColor Red }
        Write-Host ""
        Write-Host "  Granted scopes (current token): $($context.Scopes -join ', ')" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  ROOT CAUSE: Admin consent has not been granted in your tenant." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  FIX - Option A (recommended, one-time):" -ForegroundColor Cyan
        Write-Host "    1. Open: https://entra.microsoft.com" -ForegroundColor White
        Write-Host "    2. Go to: Enterprise Applications > Microsoft Graph Command Line Tools" -ForegroundColor White
        Write-Host "    3. Click: Permissions > Grant admin consent for <your org>" -ForegroundColor White
        Write-Host "    4. Return here and use [1] to reconnect" -ForegroundColor White
        Write-Host ""
        Write-Host "  FIX - Option B (this session only):" -ForegroundColor Cyan
        Write-Host "    1. Clear the WAM token cache from any terminal:" -ForegroundColor White
        Write-Host "       Remove-Item `"`$env:LOCALAPPDATA\.IdentityService`" -Recurse -Force" -ForegroundColor White
        Write-Host "    2. Use menu option [1] to reconnect" -ForegroundColor White
        Write-Host ""
        Write-Log "Pre-flight scope check failed. Missing: $($missingCoreScopes -join ', '). Granted: $($context.Scopes -join ', ')" -Level "ERROR"
        Read-Host "  Press Enter to return to the menu"
        return
    }

    # ========================================================================
    # Retrieve Users with extended properties
    # ========================================================================
    Write-Log "Retrieving all users from Entra ID..." -Level "INFO"
    $signInActivityAvailable = $true
    try {
        [System.Collections.ArrayList]$allusers = Get-MgUser -All -Property DisplayName, UserPrincipalName, UserType, AccountEnabled, AssignedLicenses, SignInActivity, CreatedDateTime, Mail -ErrorAction Stop
    }
    catch {
        Write-Verbose "Get-MgUser failed  : $($_.ToString())"
        Write-Verbose "Exception type     : $($_.Exception.GetType().FullName)"
        Write-Verbose "Stack trace        : $($_.ScriptStackTrace)"
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
        elseif ($_.Exception.Message -match "Authorization_RequestDenied|Insufficient privileges") {
            # This means a core scope (User.Read.All / Directory.Read.All) is missing.
            # The pre-flight check above should have caught this, but handle it defensively.
            Write-Log "Core Graph permission denied on Get-MgUser. This is a consent issue, not an AuditLog issue. Granted scopes: $($context.Scopes -join ', ')" -Level "ERROR"
            Write-Host ""
            Write-Host "  ✗ Access denied reading users from Graph (403 Authorization_RequestDenied)." -ForegroundColor Red
            Write-Host "    This is a consent issue - the token is missing User.Read.All or Directory.Read.All." -ForegroundColor Yellow
            Write-Host "    Granted scopes: $($context.Scopes -join ', ')" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "    Use menu option [1] to reconnect, or grant admin consent in Entra admin center." -ForegroundColor Cyan
            Write-Host "    See the TROUBLESHOOTING section in the script header for full instructions." -ForegroundColor Cyan
            Write-Host ""
            Read-Host "  Press Enter to return to the menu"
            return
        }
        elseif ($_.Exception.Message -match "AuditLog.Read.All|Authentication_MSGraphPermissionMissing") {
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
                Write-Verbose "AUTH METHOD ERROR - UPN       : $($user.UserPrincipalName)"
                Write-Verbose "AUTH METHOD ERROR - Full error : $($_.ToString())"
                Write-Verbose "AUTH METHOD ERROR - Ex. type  : $($_.Exception.GetType().FullName)"
                Write-Verbose "AUTH METHOD ERROR - Stack     : $($_.ScriptStackTrace)"
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

    # Enabled user account pool: all enabled Members regardless of account category.
    # An enabled room/shared/equipment mailbox still needs MFA protection.
    $enabledMemberAccounts = $export | Where-Object {
        $_.enabled -eq $true -and
        $_.usertype -eq 'Member'
    }
    $enabledMemberCount = $enabledMemberAccounts.Count
    $mfaEnabledMembers = ($enabledMemberAccounts | Where-Object { $_.MFAstatus -eq "enabled" }).Count
    $mfaPctMembers = if ($enabledMemberCount -gt 0) { [math]::Round(($mfaEnabledMembers / $enabledMemberCount) * 100, 1) } else { 0 }
    $disabledCount = ($export | Where-Object { $_.enabled -eq $false }).Count

    # Segment by type
    $memberAccounts = $export | Where-Object { $_.usertype -eq 'Member' -and -not $_.isAdmin }
    $guestAccounts = $export | Where-Object { $_.usertype -eq 'Guest' }
    $adminAccounts = $export | Where-Object { $_.isAdmin }

    # MFA quality breakdown
    # Weak               = has SMS/voice or email registered (regardless of other methods)
    # Phishing-resistant = has at least one of FIDO2, Windows Hello, Passwordless
    $membersWeakMFA          = ($enabledMemberAccounts | Where-Object {
        $_.MFAstatus -eq 'enabled' -and
        ($_.phoneSMS -or $_.emailAuth)
    }).Count
    $membersPhishingResistant = ($enabledMemberAccounts | Where-Object {
        $_.fido -or $_.helloForBusiness -or $_.passwordLess
    }).Count
    $membersNoMFA             = ($enabledMemberAccounts | Where-Object { $_.MFAstatus -eq 'disabled' }).Count
    $guestsNoMFA              = ($guestAccounts | Where-Object { $_.MFAstatus -eq 'disabled' }).Count
    $guestsWeakMFA            = ($guestAccounts | Where-Object {
        $_.MFAstatus -eq 'enabled' -and
        ($_.phoneSMS -or $_.emailAuth)
    }).Count
    $enabledAdminAccounts     = $adminAccounts | Where-Object { $_.enabled -eq $true }
    $adminTotal               = $adminAccounts.Count
    $adminsNoMFA              = ($enabledAdminAccounts | Where-Object { $_.MFAstatus -eq 'disabled' }).Count
    $adminsMFA                = ($enabledAdminAccounts | Where-Object { $_.MFAstatus -eq 'enabled' }).Count
    $adminsWeakMFA            = ($enabledAdminAccounts | Where-Object {
        $_.MFAstatus -eq 'enabled' -and
        ($_.phoneSMS -or $_.emailAuth)
    }).Count
    $adminsPhishingResistant  = ($enabledAdminAccounts | Where-Object {
        $_.fido -or $_.helloForBusiness -or $_.passwordLess
    }).Count

    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host "Entra ID MFA Report - Generated: $date" -ForegroundColor Green
    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host "`nACCOUNT SCOPE:" -ForegroundColor Yellow
    Write-Host "  Total accounts (all types):        $totalUsers" -ForegroundColor White
    Write-Host "  Enabled user accounts (Members):   $enabledMemberCount" -ForegroundColor White
    Write-Host "  Disabled accounts:                 $disabledCount" -ForegroundColor White
    Write-Host "  MFA coverage - enabled members:    ${mfaPctMembers}%  ($mfaEnabledMembers / $enabledMemberCount)" -ForegroundColor Cyan
    Write-Host "    Weak MFA (SMS/voice/email only):           $membersWeakMFA" -ForegroundColor Yellow
    Write-Host "    Phishing-resistant MFA (FIDO2/Hello/PL):  $membersPhishingResistant" -ForegroundColor Green

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
        EnabledMemberAccounts   = $enabledMemberCount
        MFAEnabledMembers       = $mfaEnabledMembers
        MFAEnabledMembersPct    = $mfaPctMembers
        MembersNoMFA            = $membersNoMFA
        MembersWeakMFA          = $membersWeakMFA
        MembersPhishingResistant = $membersPhishingResistant
        GuestAccounts           = $gTotal
        MFAEnabledGuests        = $gMfaOn
        MFAEnabledGuestsPct     = if ($gTotal -gt 0) { [math]::Round(($gMfaOn / $gTotal) * 100, 1) } else { 0 }
        GuestsNoMFA             = $guestsNoMFA
        GuestsWeakMFA           = $guestsWeakMFA
        DisabledAccounts        = $disabledCount
        RiskCritical            = $riskCritical
        RiskHigh                = $riskHigh
        RiskMedium              = $riskMedium
        RiskGood                = $riskGood
        RiskSecure              = $riskSecure
        RiskNA                  = $riskNA
        AdminCount              = $adminTotal
        AdminsMFA               = $adminsMFA
        AdminsNoMFA             = $adminsNoMFA
        AdminsWeakMFA           = $adminsWeakMFA
        AdminsPhishingResistant = $adminsPhishingResistant
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
            if ($DiagnosticMode -and $script:DiagnosticTranscriptFile) {
                Write-Host "  Diagnostic transcript saved to: $script:DiagnosticTranscriptFile" -ForegroundColor Magenta
                try { Stop-Transcript -ErrorAction SilentlyContinue } catch { }
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
