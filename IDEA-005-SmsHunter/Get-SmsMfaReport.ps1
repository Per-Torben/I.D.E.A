<#
.SYNOPSIS
    Interactive menu-driven hunt for Entra ID users who have, and use, SMS/voice for MFA,
    plus a posture check of the authentication methods policy, registration campaign and
    passkey profiles.

.DESCRIPTION
    The script answers three questions:

    1. WHO has SMS or voice call registered as an MFA method, and how exposed are they?
       Bulk pre-filter via the user registration details report, then per-user phone method
       detail only for users with a phone method registered. Users missing from the report
       (report lag) are checked directly. Optionally scans sign-in logs for actual SMS/voice use.

    2. WHAT does the tenant policy still allow?
       Authentication methods policy: migration state, system-preferred MFA, every method
       configuration, and SMS/Voice state, targets and SMS sign-in usability.

    3. WILL the tenant push users away from SMS?
       Registration campaign settings, passkey (FIDO2) profiles and Temporary Access Pass.

    Read-only. No changes are made to the tenant.

.PARAMETER LogDirectory
    Directory path for log files. Defaults to .\Logs

.PARAMETER DiagnosticMode
    Enables transcript logging and verbose output for troubleshooting permission and consent
    issues. The transcript survives Clear-Host.

.EXAMPLE
    .\Get-SmsMfaReport.ps1
    Launches the interactive menu.

.EXAMPLE
    .\Get-SmsMfaReport.ps1 -DiagnosticMode
    Launches with transcript and verbose output enabled.

.NOTES
    Required Microsoft Graph scopes / app permissions:
    - User.Read.All
    - Directory.Read.All
    - UserAuthenticationMethod.Read.All
    - AuditLog.Read.All
    - Policy.Read.All

    Graph beta is used for passkey profiles, registration campaign enforcement, system-preferred
    MFA and sign-in log authenticationDetails (v1.0 returns that property empty).

    Existing connections
    --------------------
    Reuses whatever Graph connection is already open in the session (certificate app-only auth
    included). Menu option [1] asks before replacing an existing connection.

    DATA PRIVACY / GDPR NOTICE:
    Output files contain personal data (names, UPNs, phone numbers, sign-in activity).
    Store securely, share only with authorised recipients, delete when no longer needed.

    Author: Per-Torben Sorensen
    Version: 1.0
    Created: October 2026
#>

#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$LogDirectory = ".\Logs",

    [switch]$DiagnosticMode
)

# ============================================================================
# Module Auto-Installation
# Everything below uses Invoke-MgGraphRequest, so only the auth module is needed.
# ============================================================================
$requiredModules = @(
    'Microsoft.Graph.Authentication'
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing module: $module" -ForegroundColor Yellow
        Install-Module $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "[OK] Installed $module" -ForegroundColor Green
    }
}

# Only a connection this script opened is torn down on exit.
$script:GraphConnectedByScript = $false

# Results kept between menu actions so [4] does not re-query what [2] and [3] already fetched.
$script:PolicyFindings = $null
$script:UserFindings   = $null
$script:AuthPolicy     = $null
$script:PolicyScopes   = $null
$script:SignInScanDays = 0
$script:GroupNameCache   = @{}
$script:GroupMemberCache = @{}

$script:SmsRetirementDate = '2027-02-01'
$script:SmsRetirementUrl  = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement#5-after-retirement'

# methodsRegistered values seen live: mobilePhone, passKeyDeviceBound*, passKeySynced, ...
# Patterns rather than enum lists so new variants (alternateMobilePhone, officePhone) still match.
$script:PhoneMethodPattern     = 'Phone$'
$script:PhishResistantPattern  = '^(passKey|fido2|windowsHelloForBusiness|platformCredential|x509Certificate)'
$script:NonMfaMethodPattern    = '^(email|password|temporaryAccessPass)'
# Matches userPreferred (sms, voiceMobile, ...) and systemPreferred (Sms, Voice...). Not PhoneAppNotification.
$script:PhonePreferredPattern  = '^(sms|voice)'
# Sign-in log authenticationDetails.authenticationMethod for phone MFA (e.g. "Text message", "Phone call").
$script:PhoneSignInPattern     = 'text message|\bsms\b|phone call|voice'

$script:MethodDisplayNames = @{
    mobilePhone                       = 'Mobile phone'
    alternateMobilePhone              = 'Alternate mobile phone'
    officePhone                       = 'Office phone'
    microsoftAuthenticatorPush        = 'Authenticator'
    microsoftAuthenticatorPasswordless = 'Authenticator passwordless'
    softwareOneTimePasscode           = 'Software OATH'
    hardwareOneTimePasscode           = 'Hardware OATH'
    passKeyDeviceBound                = 'Passkey (device-bound)'
    passKeyDeviceBoundAuthenticator   = 'Passkey (Authenticator)'
    passKeyDeviceBoundWindowsHello    = 'Passkey (Windows Hello)'
    passKeySynced                     = 'Passkey (synced)'
    fido2                             = 'FIDO2'
    windowsHelloForBusiness           = 'Windows Hello'
    platformCredential                = 'Platform credential'
    email                             = 'Email'
}

# ============================================================================
# Logging
# ============================================================================
if (!(Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

$LogFile = Join-Path $LogDirectory "Get-SmsMfaReport-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

$script:DiagnosticTranscriptFile = $null
if ($DiagnosticMode) {
    $script:DiagnosticTranscriptFile = Join-Path $LogDirectory "Get-SmsMfaReport-Diagnostic-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    Start-Transcript -Path $script:DiagnosticTranscriptFile -Append -Force | Out-Null
    $VerbosePreference = 'Continue'
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Magenta
    Write-Host "  DIAGNOSTIC MODE ACTIVE" -ForegroundColor Magenta
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
# Scope Helpers
# ============================================================================
$script:RequiredScopes = @(
    'User.Read.All',
    'Directory.Read.All',
    'UserAuthenticationMethod.Read.All',
    'AuditLog.Read.All',
    'Policy.Read.All'
)

# A broader scope also satisfies the read scope, so do not flag it as missing.
$ScopeEquivalents = @{
    'User.Read.All'                     = @('User.ReadWrite.All')
    'Directory.Read.All'                = @('Directory.ReadWrite.All')
    'UserAuthenticationMethod.Read.All' = @('UserAuthenticationMethod.ReadWrite.All')
    'AuditLog.Read.All'                 = @('AuditLog.ReadWrite.All')
    'Policy.Read.All'                   = @('Policy.ReadWrite.AuthenticationMethod')
}

function Test-ScopeGranted {
    param(
        [string]$RequiredScope,
        [string[]]$GrantedScopes
    )
    if ($GrantedScopes -contains $RequiredScope) { return $true }
    $equivalents = $ScopeEquivalents[$RequiredScope]
    if ($equivalents) {
        foreach ($equivalent in $equivalents) {
            if ($GrantedScopes -contains $equivalent) { return $true }
        }
    }
    return $false
}

# ============================================================================
# Phone Country Code Mapping (same table as I.D.E.A. 004)
# ============================================================================
$script:CountryCodes = @{
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
    if ([string]::IsNullOrWhiteSpace($PhoneNumber)) { return $null }

    # Graph returns "+47 92445647": the part before the space is the country code.
    if ($PhoneNumber -match '^\s*\+(\d{1,3})\s') {
        $code = $Matches[1]
        if ($script:CountryCodes -and $script:CountryCodes.ContainsKey($code)) { return "$($script:CountryCodes[$code]) (+$code)" }
        return "Unknown (+$code)"
    }

    $cleaned = $PhoneNumber -replace '[^\d+]', ''
    if ($cleaned -notmatch '^\+') { return 'Unknown' }
    $digits = $cleaned.TrimStart('+')
    for ($len = 3; $len -ge 1; $len--) {
        if ($digits.Length -ge $len) {
            $code = $digits.Substring(0, $len)
            if ($script:CountryCodes -and $script:CountryCodes.ContainsKey($code)) { return "$($script:CountryCodes[$code]) (+$code)" }
        }
    }
    return "Unknown (+$($digits.Substring(0, [Math]::Min(3, $digits.Length)))...)"
}

function Get-MethodDisplayName {
    param([string]$Method)
    if ($script:MethodDisplayNames -and $script:MethodDisplayNames.ContainsKey($Method)) { return $script:MethodDisplayNames[$Method] }
    return $Method
}

# ============================================================================
# Menu Functions
# ============================================================================
function Show-Banner {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  I.D.E.A. 005 - SMS MFA Hunter" -ForegroundColor Cyan
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

    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if ($ctx) {
        $authLabel = if ($ctx.AuthType -eq 'AppOnly') { ", app-only" } else { "" }
        $graphStatus = "Connected ($($ctx.TenantId)$authLabel)"
        $graphColor = "Green"
    }

    Write-Host "  Connection Status:" -ForegroundColor Yellow
    Write-Host "    Microsoft Graph:    " -NoNewline; Write-Host $graphStatus -ForegroundColor $graphColor
    $policyState = if ($script:PolicyFindings) { "$(@($script:PolicyFindings).Count) findings cached" } else { "not collected" }
    $userState   = if ($null -ne $script:UserFindings) { "$(@($script:UserFindings).Count) users cached" } else { "not collected" }
    Write-Host "    Policy posture:     $policyState" -ForegroundColor Gray
    Write-Host "    User hunt:          $userState" -ForegroundColor Gray
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
        Write-Host ("  " + "-" * 74) -ForegroundColor DarkYellow
        Write-Host "  ! $count file(s) older than 24 hours found in exports/logs." -ForegroundColor Yellow
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
    Write-Host "  [2] Check policy posture (auth methods, SMS/voice, registration campaign, passkeys)" -ForegroundColor Green
    Write-Host "  [3] Hunt SMS/voice MFA users" -ForegroundColor Green
    Write-Host "  [4] Full report (policy + users, CSV/HTML export)" -ForegroundColor Green
    Write-Host "  [C] Clear cached results" -ForegroundColor Gray
    Write-Host "  [Q] Quit" -ForegroundColor Gray
    Write-Host ""
}

function Show-OutputMenu {
    Write-Host ""
    Write-Host "  Select output format(s):" -ForegroundColor Yellow
    Write-Host "  [1] Console only" -ForegroundColor Green
    Write-Host "  [2] Console + CSV" -ForegroundColor Green
    Write-Host "  [3] Console + HTML (default)" -ForegroundColor Green
    Write-Host "  [4] Console + CSV + HTML" -ForegroundColor Green
    Write-Host ""

    $choice = Read-Host "  Enter choice (1-4, default=3)"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "3" }

    switch ($choice) {
        '1' { return @{ Html = $false; Csv = $false } }
        '2' { return @{ Html = $false; Csv = $true } }
        '3' { return @{ Html = $true;  Csv = $false } }
        '4' { return @{ Html = $true;  Csv = $true } }
        default {
            Write-Host "  Invalid choice, using default (Console + HTML)" -ForegroundColor Yellow
            return @{ Html = $true; Csv = $false }
        }
    }
}

function Read-SignInScanDays {
    Write-Host ""
    Write-Host "  Sign-in log scan finds users who actually completed MFA with SMS/voice." -ForegroundColor Yellow
    Write-Host "  It reads every MFA sign-in in the window (beta endpoint, can be slow in large tenants)." -ForegroundColor Gray
    Write-Host "  Sign-ins from the last few minutes may not be ingested yet." -ForegroundColor Gray
    $answer = Read-Host "  Days to scan (1-30, 0 = skip, default=7)"
    if ([string]::IsNullOrWhiteSpace($answer)) { return 7 }
    $days = 0
    if (-not [int]::TryParse($answer, [ref]$days) -or $days -lt 0 -or $days -gt 30) {
        Write-Host "  Invalid value, skipping the sign-in scan." -ForegroundColor Yellow
        return 0
    }
    return $days
}

function Clear-ResultCache {
    $script:PolicyFindings   = $null
    $script:UserFindings     = $null
    $script:AuthPolicy       = $null
    $script:PolicyScopes     = $null
    $script:SignInScanDays   = 0
    $script:GroupNameCache   = @{}
    $script:GroupMemberCache = @{}
}

# ============================================================================
# Connection
# Not named Connect-Graph: that is an alias for Connect-MgGraph, and aliases outrank
# functions in command resolution.
# ============================================================================
function Connect-ReportGraph {
    Write-Host ""

    # An app-only connection cannot be recreated here, so never discard one silently.
    $existing = Get-MgContext -ErrorAction SilentlyContinue
    if ($existing) {
        $label = if ($existing.AuthType -eq 'AppOnly') { "app-only (AppId $($existing.ClientId))" } else { $existing.Account }
        Write-Host "  Already connected to Microsoft Graph: $label" -ForegroundColor Green
        Write-Host "  Tenant: $($existing.TenantId)" -ForegroundColor Gray
        Write-Host ""
        $replace = Read-Host "  Replace this connection with an interactive sign-in? (Y/N)"
        if ($replace -notmatch '^[Yy]') {
            Write-Host "  Keeping the existing connection." -ForegroundColor DarkGray
            Write-Log "Kept existing Graph connection (AuthType: $($existing.AuthType))" -Level "INFO"
            return
        }
    }

    Write-Host "  Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Write-Host "  Required scopes: $($script:RequiredScopes -join ', ')" -ForegroundColor Gray
    Write-Host ""

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Clear-ResultCache
        Connect-MgGraph -Scopes $script:RequiredScopes -NoWelcome -ContextScope Process -ErrorAction Stop
        $script:GraphConnectedByScript = $true

        # WAM can return a null context right after connect. Retry briefly.
        $ctx = $null
        for ($attempt = 1; $attempt -le 5; $attempt++) {
            $ctx = Get-MgContext -ErrorAction SilentlyContinue
            if ($ctx) { break }
            Start-Sleep -Milliseconds 500
        }

        if (-not $ctx) {
            Write-Log "Connection failed - no context established" -Level "ERROR"
            return
        }

        $missing = $script:RequiredScopes | Where-Object { -not (Test-ScopeGranted -RequiredScope $_ -GrantedScopes $ctx.Scopes) }
        Write-Log "Connected to Microsoft Graph (Tenant: $($ctx.TenantId))" -Level "SUCCESS"
        Write-Verbose "Granted scopes: $($ctx.Scopes -join ', ')"

        if ($missing) {
            Write-Host ""
            Write-Host "  [!] These required scopes were NOT granted:" -ForegroundColor Yellow
            foreach ($s in $missing) { Write-Host "      - $s" -ForegroundColor Yellow }
            Write-Host "  A Global Admin must grant consent for 'Microsoft Graph Command Line Tools'," -ForegroundColor White
            Write-Host "  or you can clear the WAM cache and reconnect (see README troubleshooting)." -ForegroundColor White
            Write-Log "Missing scopes after connect: $($missing -join ', ')" -Level "WARNING"
        }
        else {
            Write-Host "  [OK] All required scopes granted" -ForegroundColor Green
        }
    }
    catch {
        Write-Log "Graph connection failed: $($_.Exception.Message)" -Level "ERROR"
        Write-Verbose "Full exception: $($_.ToString())"
    }
}

function Test-GraphReady {
    <#
    .SYNOPSIS
        Returns $true when a usable Graph connection exists. Prints guidance otherwise.
        Delegated: scope check. App-only: live probe, since app-only contexts do not always
        list granted roles.
    #>
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        Write-Host ""
        Write-Host "  [X] No active Microsoft Graph connection. Use menu option [1] first," -ForegroundColor Red
        Write-Host "      or run Connect-MgGraph yourself (certificate app-only works)." -ForegroundColor Yellow
        Write-Host ""
        return $false
    }

    if ($ctx.AuthType -eq 'AppOnly') {
        try {
            Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=1' -ErrorAction Stop | Out-Null
            Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' -ErrorAction Stop | Out-Null
            return $true
        }
        catch {
            Write-Log "App-only pre-flight failed: $($_.Exception.Message)" -Level "ERROR"
            Write-Host "  Grant the app: $($script:RequiredScopes -join ', ')" -ForegroundColor Yellow
            return $false
        }
    }

    $missing = $script:RequiredScopes | Where-Object { -not (Test-ScopeGranted -RequiredScope $_ -GrantedScopes $ctx.Scopes) }
    if ($missing) {
        Write-Host ""
        Write-Host "  [X] Missing required scopes: $($missing -join ', ')" -ForegroundColor Red
        Write-Host "      Use menu option [1] to reconnect, or grant admin consent in the Entra admin center." -ForegroundColor Yellow
        Write-Host "      If consent is granted but scopes are still missing, clear the WAM cache:" -ForegroundColor Yellow
        Write-Host "      Remove-Item `"`$env:LOCALAPPDATA\.IdentityService`" -Recurse -Force" -ForegroundColor White
        Write-Host ""
        Write-Log "Pre-flight scope check failed. Missing: $($missing -join ', ')" -Level "ERROR"
        return $false
    }
    return $true
}

# ============================================================================
# Graph helpers
# ============================================================================
function Invoke-GraphGet {
    <#
    .SYNOPSIS
        GET with Retry-After backoff on 429/503/504.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri)

    $maxAttempts = 5
    $attempt = 0
    while ($true) {
        try {
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
        }
        catch {
            $status = $null
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -notin 429, 503, 504 -or $attempt -ge $maxAttempts) { throw }

            $attempt++
            $delay = $null
            try { $delay = [int]$_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds } catch { }
            if (-not $delay -or $delay -lt 1) { $delay = [int][math]::Pow(2, $attempt) }
            Write-Log "Graph throttled ($status). Retrying in $delay s (attempt $attempt/$maxAttempts)" -Level "WARNING"
            Start-Sleep -Seconds $delay
        }
    }
}

function Invoke-GraphPaged {
    <#
    .SYNOPSIS
        GET a Graph collection and follow @odata.nextLink. Returns all items.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri)

    $results = [System.Collections.Generic.List[object]]::new()
    while ($Uri) {
        $page = Invoke-GraphGet -Uri $Uri
        if ($page.value) {
            foreach ($item in $page.value) { $results.Add($item) }
        }
        $Uri = $page.'@odata.nextLink'
    }
    return , $results
}

function Test-AccessDenied {
    param($ErrorRecord)
    $text = "$($ErrorRecord.Exception.Message) $($ErrorRecord.ErrorDetails.Message)"
    return ($text -match 'accessDenied|Forbidden|Authorization_RequestDenied')
}

function Get-AuthMethodConfiguration {
    <#
    .SYNOPSIS
        GET one authentication method configuration (Sms, Voice, Fido2, ...) from the policy.
        Returns $null and logs a warning on failure so the posture check can keep going.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$MethodId,
        [ValidateSet('v1.0', 'beta')][string]$ApiVersion = 'v1.0'
    )

    $uri = "https://graph.microsoft.com/$ApiVersion/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$MethodId"
    try {
        return Invoke-GraphGet -Uri $uri
    }
    catch {
        Write-Log "Could not read $MethodId configuration ($ApiVersion): $($_.Exception.Message)" -Level "WARNING"
        return $null
    }
}

function Get-AuthMethodsPolicy {
    <#
    .SYNOPSIS
        Loads the authentication methods policy once (v1.0 + beta extras) and caches it.
    #>
    if ($script:AuthPolicy) { return $script:AuthPolicy }

    Write-Log "Reading authentication methods policy..." -Level "INFO"
    try {
        $v1 = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    }
    catch {
        Write-Log "Could not read the authentication methods policy (needs Policy.Read.All): $($_.Exception.Message)" -Level "ERROR"
        return $null
    }

    $beta = $null
    try {
        $beta = Invoke-GraphGet -Uri 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy'
    }
    catch {
        Write-Log "Beta authentication methods policy unavailable, beta-only checks skipped: $($_.Exception.Message)" -Level "WARNING"
    }

    $fido2Beta = Get-AuthMethodConfiguration -MethodId 'Fido2' -ApiVersion 'beta'

    $script:AuthPolicy = [PSCustomObject]@{
        V1        = $v1
        Beta      = $beta
        Fido2Beta = $fido2Beta
    }
    return $script:AuthPolicy
}

function Get-MethodConfig {
    param($Policy, [string]$MethodId)
    if (-not $Policy -or -not $Policy.V1) { return $null }
    return @($Policy.V1.authenticationMethodConfigurations) | Where-Object { $_.id -eq $MethodId } | Select-Object -First 1
}

function Get-TargetDisplayName {
    <#
    .SYNOPSIS
        Resolves a policy target id to a readable name. Cached.
    #>
    param(
        [string]$Id,
        [string]$TargetType = 'group'
    )

    if ($Id -eq 'all_users') { return 'All users' }
    if ($script:GroupNameCache.ContainsKey($Id)) { return $script:GroupNameCache[$Id] }

    $name = $null
    try {
        if ($TargetType -eq 'user') {
            $u = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/users/$Id`?`$select=userPrincipalName"
            $name = "User: $($u.userPrincipalName)"
        }
        else {
            $g = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/groups/$Id`?`$select=displayName"
            $name = $g.displayName
        }
    }
    catch {
        $name = "Unresolved $TargetType ($Id)"
    }
    $script:GroupNameCache[$Id] = $name
    return $name
}

function Format-Targets {
    param([object[]]$Targets)
    $list = @($Targets | Where-Object { $_ })
    if ($list.Count -eq 0) { return '(none)' }
    return (($list | ForEach-Object { Get-TargetDisplayName -Id $_.id -TargetType "$($_.targetType)" }) -join '; ')
}

function Get-GroupUserIds {
    <#
    .SYNOPSIS
        Transitive user members of a group, so nested groups count. Cached by group id.
    #>
    param([Parameter(Mandatory)][string]$GroupId)

    if ($script:GroupMemberCache.ContainsKey($GroupId)) { return , $script:GroupMemberCache[$GroupId] }

    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $members = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=id&`$top=999"
        foreach ($m in $members) { [void]$ids.Add($m.id) }
    }
    catch {
        Write-Log "Could not resolve members of group $GroupId : $($_.Exception.Message)" -Level "WARNING"
    }
    $script:GroupMemberCache[$GroupId] = $ids
    return , $ids
}

function Resolve-PolicyTargetUsers {
    <#
    .SYNOPSIS
        Turns include/exclude targets from a policy into a user scope.
    .OUTPUTS
        PSCustomObject: AllUsers (bool), Include (HashSet of user ids), Exclude (HashSet of user ids).
        Use Test-UserInScope to evaluate a user.
    #>
    [CmdletBinding()]
    param(
        [object[]]$IncludeTargets,
        [object[]]$ExcludeTargets
    )

    $allUsers = $false
    $include = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $exclude = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($t in @($IncludeTargets | Where-Object { $_ })) {
        if ($t.id -eq 'all_users') { $allUsers = $true; continue }
        if ("$($t.targetType)" -eq 'user') { [void]$include.Add($t.id); continue }
        $include.UnionWith((Get-GroupUserIds -GroupId $t.id))
    }
    foreach ($t in @($ExcludeTargets | Where-Object { $_ })) {
        if ("$($t.targetType)" -eq 'user') { [void]$exclude.Add($t.id); continue }
        $exclude.UnionWith((Get-GroupUserIds -GroupId $t.id))
    }

    [PSCustomObject]@{
        AllUsers = $allUsers
        Include  = $include
        Exclude  = $exclude
    }
}

function Test-UserInScope {
    param($Scope, [string]$UserId)
    if (-not $Scope) { return $false }
    if ($Scope.Exclude.Contains($UserId)) { return $false }
    return ($Scope.AllUsers -or $Scope.Include.Contains($UserId))
}

function Get-PolicyScopes {
    <#
    .SYNOPSIS
        Resolves who is in scope of the SMS, Voice and Fido2 configurations and the registration
        campaign. Only enabled policies are resolved. Cached.
    #>
    if ($script:PolicyScopes) { return $script:PolicyScopes }

    $policy = Get-AuthMethodsPolicy
    if (-not $policy) { return $null }

    Write-Log "Resolving policy target groups..." -Level "INFO"
    $result = @{}
    foreach ($id in 'Sms', 'Voice', 'Fido2') {
        $cfg = Get-MethodConfig -Policy $policy -MethodId $id
        $state = if ($cfg) { "$($cfg.state)" } else { 'missing' }
        $scope = $null
        if ($state -eq 'enabled') {
            $scope = Resolve-PolicyTargetUsers -IncludeTargets $cfg.includeTargets -ExcludeTargets $cfg.excludeTargets
        }
        $result[$id] = [PSCustomObject]@{ State = $state; Scope = $scope }
    }

    $campaign = $policy.V1.registrationEnforcement.authenticationMethodsRegistrationCampaign
    $cState = if ($campaign) { "$($campaign.state)" } else { 'missing' }
    $cScope = $null
    if ($cState -eq 'enabled') {
        $cScope = Resolve-PolicyTargetUsers -IncludeTargets $campaign.includeTargets -ExcludeTargets $campaign.excludeTargets
    }
    $result['Campaign'] = [PSCustomObject]@{ State = $cState; Scope = $cScope }

    $script:PolicyScopes = $result
    return $result
}

function Get-ScopeLabel {
    param($Entry, [string]$UserId)
    if (-not $Entry) { return 'Unknown' }
    switch ($Entry.State) {
        'enabled'  { if (Test-UserInScope -Scope $Entry.Scope -UserId $UserId) { return 'Yes' } else { return 'No' } }
        'default'  { return 'Microsoft-managed' }
        default    { return "No ($($Entry.State))" }
    }
}

# ============================================================================
# Policy posture
# Every check returns rows built by New-PolicyFinding so console, CSV and HTML share one shape.
# ============================================================================
#region Policy posture

function New-PolicyFinding {
    param(
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [ValidateSet('Pass', 'Warn', 'Fail', 'Info')]
        [string]$Status = 'Info',
        [string]$Current = '',
        [string]$Recommended = '',
        [string]$Notes = ''
    )

    [PSCustomObject]@{
        Area        = $Area
        Check       = $Check
        Status      = $Status
        Current     = $Current
        Recommended = $Recommended
        Notes       = $Notes
    }
}

function Get-AuthMethodsOverviewFindings {
    <#
    .SYNOPSIS
        Tenant-level authentication methods policy checks and a row per method configuration.
    #>
    param($Policy)

    $area = 'Authentication methods policy'
    $findings = @()

    $migration = "$($Policy.V1.policyMigrationState)"
    if ($migration -eq 'migrationComplete') {
        $findings += New-PolicyFinding -Area $area -Check 'Policy migration state' -Status Pass -Current $migration `
            -Recommended 'migrationComplete' -Notes 'Legacy MFA and SSPR method settings are ignored. This policy is authoritative.'
    }
    else {
        $findings += New-PolicyFinding -Area $area -Check 'Policy migration state' -Status Warn -Current $migration `
            -Recommended 'migrationComplete' -Notes 'Legacy per-user MFA and SSPR policies still apply. SMS/voice can be allowed there even when disabled here.'
    }

    if ($Policy.Beta -and $Policy.Beta.systemCredentialPreferences) {
        $scp = $Policy.Beta.systemCredentialPreferences
        $state = "$($scp.state)"
        $status = switch ($state) { 'enabled' { 'Pass' } 'disabled' { 'Warn' } default { 'Info' } }
        $findings += New-PolicyFinding -Area $area -Check 'System-preferred MFA' -Status $status `
            -Current "$state; include: $(Format-Targets $scp.includeTargets); exclude: $(Format-Targets $scp.excludeTargets)" `
            -Recommended 'enabled for all users' `
            -Notes 'Prompts the strongest registered method instead of the user default (often SMS).'
    }

    if ($Policy.Beta -and $Policy.Beta.reportSuspiciousActivitySettings) {
        $rsa = $Policy.Beta.reportSuspiciousActivitySettings
        $findings += New-PolicyFinding -Area $area -Check 'Report suspicious activity' -Status Info `
            -Current "$($rsa.state); include: $(Format-Targets @($rsa.includeTarget))" `
            -Recommended 'enabled' -Notes 'Lets users report unexpected MFA prompts.'
    }

    foreach ($cfg in @($Policy.V1.authenticationMethodConfigurations)) {
        if ($cfg.id -in 'Sms', 'Voice', 'Fido2', 'TemporaryAccessPass') { continue }
        $extra = @()
        if ($cfg.id -eq 'MicrosoftAuthenticator' -and $null -ne $cfg.isSoftwareOathEnabled) { $extra += "software OATH in app: $($cfg.isSoftwareOathEnabled)" }
        $current = "$($cfg.state); include: $(Format-Targets $cfg.includeTargets); exclude: $(Format-Targets $cfg.excludeTargets)"
        if ($extra) { $current += "; $($extra -join '; ')" }
        $notes = if ($cfg.id -eq 'MicrosoftAuthenticator' -and $cfg.state -ne 'enabled') { 'Authenticator is the usual migration target away from SMS.' } else { '' }
        $status = if ($cfg.id -eq 'MicrosoftAuthenticator' -and $cfg.state -ne 'enabled') { 'Warn' } else { 'Info' }
        $findings += New-PolicyFinding -Area $area -Check "Method: $($cfg.id)" -Status $status -Current $current -Notes $notes
    }

    return $findings
}

function Get-SmsVoicePolicyFindings {
    <#
    .SYNOPSIS
        Findings for the SMS and Voice authentication method configurations.
    #>
    param($Policy)

    $findings = @()

    $sms = Get-MethodConfig -Policy $Policy -MethodId 'Sms'
    if (-not $sms) {
        $findings += New-PolicyFinding -Area 'SMS' -Check 'Configuration' -Status Info -Current 'Not returned by Graph'
    }
    else {
        $include = @($sms.includeTargets | Where-Object { $_ })
        $exclude = @($sms.excludeTargets | Where-Object { $_ })
        $targetsAll = [bool]($include | Where-Object { $_.id -eq 'all_users' })
        $status = if ($sms.state -ne 'enabled') { 'Pass' } elseif ($targetsAll -and $exclude.Count -eq 0) { 'Fail' } else { 'Warn' }
        $findings += New-PolicyFinding -Area 'SMS' -Check 'State and targets' -Status $status `
            -Current "$($sms.state); include: $(Format-Targets $include); exclude: $(Format-Targets $exclude)" `
            -Recommended 'disabled, or scoped to a small named recovery group' `
            -Notes "SMS MFA is retired for remaining users on $($script:SmsRetirementDate)."

        $signInTargets = @($include | Where-Object { $_.isUsableForSignIn -eq $true })
        if ($signInTargets.Count -eq 0) {
            $findings += New-PolicyFinding -Area 'SMS' -Check 'SMS sign-in (passwordless SMS)' -Status Pass -Current 'Not allowed for any target' -Recommended 'Not allowed'
        }
        elseif ($sms.state -eq 'enabled') {
            $findings += New-PolicyFinding -Area 'SMS' -Check 'SMS sign-in (passwordless SMS)' -Status Warn `
                -Current "Allowed for: $(Format-Targets $signInTargets)" -Recommended 'Not allowed' `
                -Notes 'A phone number plus SMS code becomes a full sign-in credential.'
        }
        else {
            $findings += New-PolicyFinding -Area 'SMS' -Check 'SMS sign-in (passwordless SMS)' -Status Info `
                -Current "Configured for: $(Format-Targets $signInTargets) (method disabled)" -Recommended 'Not allowed' `
                -Notes 'Inactive while SMS is disabled. Becomes active if SMS is re-enabled.'
        }
    }

    $voice = Get-MethodConfig -Policy $Policy -MethodId 'Voice'
    if (-not $voice) {
        $findings += New-PolicyFinding -Area 'Voice' -Check 'Configuration' -Status Info -Current 'Not returned by Graph'
    }
    else {
        $include = @($voice.includeTargets | Where-Object { $_ })
        $exclude = @($voice.excludeTargets | Where-Object { $_ })
        $targetsAll = [bool]($include | Where-Object { $_.id -eq 'all_users' })
        $status = if ($voice.state -ne 'enabled') { 'Pass' } elseif ($targetsAll -and $exclude.Count -eq 0) { 'Fail' } else { 'Warn' }
        $findings += New-PolicyFinding -Area 'Voice' -Check 'State and targets' -Status $status `
            -Current "$($voice.state); include: $(Format-Targets $include); exclude: $(Format-Targets $exclude)" `
            -Recommended 'disabled, or scoped to a small named recovery group' `
            -Notes "Voice call MFA is retired for remaining users on $($script:SmsRetirementDate)."

        if ($null -ne $voice.isOfficePhoneAllowed) {
            $status = if ($voice.state -eq 'enabled' -and $voice.isOfficePhoneAllowed) { 'Warn' } else { 'Info' }
            $findings += New-PolicyFinding -Area 'Voice' -Check 'Office phone allowed' -Status $status `
                -Current "$($voice.isOfficePhoneAllowed)" -Recommended 'False'
        }
    }

    return $findings
}

function Get-RegistrationCampaignFindings {
    <#
    .SYNOPSIS
        Findings for the registration campaign (nudge) settings.
    #>
    param($Policy)

    $area = 'Registration campaign'
    $findings = @()

    $campaign = $Policy.V1.registrationEnforcement.authenticationMethodsRegistrationCampaign
    if (-not $campaign) {
        return @(New-PolicyFinding -Area $area -Check 'Configuration' -Status Info -Current 'Not returned by Graph')
    }
    $betaCampaign = if ($Policy.Beta) { $Policy.Beta.registrationEnforcement.authenticationMethodsRegistrationCampaign } else { $null }

    $state = "$($campaign.state)"
    $status = switch ($state) { 'enabled' { 'Pass' } default { 'Warn' } }
    $notes = switch ($state) {
        'enabled'  { 'Users are nudged to register the targeted method at sign-in.' }
        'default'  { 'Microsoft-managed. Microsoft decides who is nudged and can change it.' }
        'disabled' { 'Nobody is nudged off SMS/voice at sign-in.' }
        default    { '' }
    }
    $findings += New-PolicyFinding -Area $area -Check 'State' -Status $status -Current $state -Recommended 'enabled' -Notes $notes

    $findings += New-PolicyFinding -Area $area -Check 'Snooze duration (days)' -Status Info -Current "$($campaign.snoozeDurationInDays)" `
        -Notes 'How long a user can postpone registration each time.'

    if ($betaCampaign -and $null -ne $betaCampaign.enforceRegistrationAfterAllowedSnoozes) {
        $enforce = [bool]$betaCampaign.enforceRegistrationAfterAllowedSnoozes
        $eStatus = if ($state -ne 'enabled') { 'Info' } elseif ($enforce) { 'Pass' } else { 'Warn' }
        $findings += New-PolicyFinding -Area $area -Check 'Enforce registration after allowed snoozes' -Status $eStatus `
            -Current "$enforce" -Recommended 'True' -Notes 'When False, users can snooze indefinitely.'
    }

    $include = @($campaign.includeTargets | Where-Object { $_ })
    if ($include.Count -eq 0) {
        $iStatus = if ($state -eq 'enabled') { 'Warn' } else { 'Info' }
        $findings += New-PolicyFinding -Area $area -Check 'Include targets' -Status $iStatus -Current '(none)'
    }
    foreach ($t in $include) {
        # Read targetedAuthenticationMethod as returned. The set of values is not hardcoded.
        $method = if ($t.targetedAuthenticationMethod) { "$($t.targetedAuthenticationMethod)" } else { '(not returned)' }
        $findings += New-PolicyFinding -Area $area -Check "Include: $(Get-TargetDisplayName -Id $t.id -TargetType "$($t.targetType)")" `
            -Status Info -Current "Nudges toward: $method"
    }

    $exclude = @($campaign.excludeTargets | Where-Object { $_ })
    $findings += New-PolicyFinding -Area $area -Check 'Exclude targets' -Status Info -Current (Format-Targets $exclude)

    return $findings
}

function Get-PasskeyProfileFindings {
    <#
    .SYNOPSIS
        Findings for the passkey (FIDO2) configuration, its passkey profiles and Temporary Access Pass.
    #>
    param($Policy)

    $area = 'Passkeys (FIDO2)'
    $findings = @()

    $fido = if ($Policy.Fido2Beta) { $Policy.Fido2Beta } else { Get-MethodConfig -Policy $Policy -MethodId 'Fido2' }
    if (-not $fido) {
        return @(New-PolicyFinding -Area $area -Check 'Configuration' -Status Warn -Current 'Not returned by Graph')
    }

    $include = @($fido.includeTargets | Where-Object { $_ })
    $exclude = @($fido.excludeTargets | Where-Object { $_ })
    $status = if ($fido.state -eq 'enabled' -and $include.Count -gt 0) { 'Pass' } else { 'Warn' }
    $findings += New-PolicyFinding -Area $area -Check 'State and targets' -Status $status `
        -Current "$($fido.state); include: $(Format-Targets $include); exclude: $(Format-Targets $exclude)" `
        -Recommended 'enabled for all users' -Notes 'Passkeys are the phishing-resistant replacement for SMS.'

    if ($null -ne $fido.isSelfServiceRegistrationAllowed) {
        $sStatus = if ($fido.isSelfServiceRegistrationAllowed) { 'Pass' } else { 'Warn' }
        $findings += New-PolicyFinding -Area $area -Check 'Self-service registration' -Status $sStatus `
            -Current "$($fido.isSelfServiceRegistrationAllowed)" -Recommended 'True' `
            -Notes 'When False, users cannot register passkeys themselves.'
    }

    $profiles = @($fido.passkeyProfiles | Where-Object { $_ })
    if ($profiles.Count -eq 0) {
        # Tenant not on passkey profiles yet: report the legacy tenant-wide settings.
        $kr = $fido.keyRestrictions
        $krText = if ($kr -and $kr.isEnforced) { "enforced ($($kr.enforcementType), $(@($kr.aaGuids).Count) AAGUIDs)" } else { 'not enforced' }
        $findings += New-PolicyFinding -Area $area -Check 'Passkey profiles' -Status Info `
            -Current "None returned. Attestation enforced: $($fido.isAttestationEnforced); key restrictions: $krText"
    }
    else {
        $defaultId = "$($fido.defaultPasskeyProfile)"
        # Live response ties a profile to a target through includeTargets[].allowedPasskeyProfiles.
        $profileTargets = @{}
        foreach ($t in $include) {
            foreach ($profileId in @($t.allowedPasskeyProfiles | Where-Object { $_ })) {
                if (-not $profileTargets.ContainsKey($profileId)) { $profileTargets[$profileId] = @() }
                $profileTargets[$profileId] += (Get-TargetDisplayName -Id $t.id -TargetType "$($t.targetType)")
            }
        }
        $targetsWithoutProfile = @($include | Where-Object { -not $_.allowedPasskeyProfiles -or @($_.allowedPasskeyProfiles).Count -eq 0 })

        foreach ($p in $profiles) {
            $kr = $p.keyRestrictions
            $krText = if ($kr -and $kr.isEnforced) { "enforced ($($kr.enforcementType), $(@($kr.aaGuids).Count) AAGUIDs)" } else { 'not enforced' }
            $isDefault = ("$($p.id)" -eq $defaultId)
            $targets = if ($profileTargets.ContainsKey("$($p.id)")) { $profileTargets["$($p.id)"] -join '; ' } else { '' }
            if ($isDefault -and $targetsWithoutProfile.Count -gt 0) {
                $extra = ($targetsWithoutProfile | ForEach-Object { Get-TargetDisplayName -Id $_.id -TargetType "$($_.targetType)" }) -join '; '
                $targets = (@($targets, "$extra (default)") | Where-Object { $_ }) -join '; '
            }
            if (-not $targets) { $targets = '(no targets)' }

            $pStatus = if ($targets -eq '(no targets)' -and -not $isDefault) { 'Warn' } else { 'Info' }
            $label = if ($isDefault) { "Profile: $($p.name) (default)" } else { "Profile: $($p.name)" }
            $findings += New-PolicyFinding -Area $area -Check $label -Status $pStatus `
                -Current "types: $($p.passkeyTypes); attestation: $($p.attestationEnforcement); key restrictions: $krText; targets: $targets" `
                -Notes $(if ($pStatus -eq 'Warn') { 'Profile is not assigned to any target.' } else { '' })
        }
    }

    $tap = Get-MethodConfig -Policy $Policy -MethodId 'TemporaryAccessPass'
    if ($tap) {
        $tStatus = if ($tap.state -eq 'enabled') { 'Pass' } else { 'Warn' }
        $findings += New-PolicyFinding -Area $area -Check 'Temporary Access Pass' -Status $tStatus `
            -Current "$($tap.state); one-time use: $($tap.isUsableOnce); default lifetime: $($tap.defaultLifetimeInMinutes) min; include: $(Format-Targets $tap.includeTargets)" `
            -Recommended 'enabled, one-time use' -Notes 'TAP is the onboarding path for passkeys without SMS.'
    }

    return $findings
}

function Get-CrossCheckFindings {
    <#
    .SYNOPSIS
        Findings that combine the user hunt with the policy: who is still allowed SMS, who is
        outside the campaign, who cannot register a passkey.
    #>
    param([array]$Users)

    $area = 'Cross-checks'
    $findings = @()
    $active = @($Users | Where-Object { $_.AccountEnabled -eq $true })
    if ($active.Count -eq 0) { return $findings }

    $phoneOnly = @($active | Where-Object { $_.PhoneOnly })
    $status = if ($phoneOnly.Count -gt 0) { 'Fail' } else { 'Pass' }
    $findings += New-PolicyFinding -Area $area -Check 'Enabled users with SMS/voice as only MFA method' -Status $status `
        -Current "$($phoneOnly.Count) of $($active.Count)" -Recommended '0' `
        -Notes "These users must register another method before $($script:SmsRetirementDate)."

    $inSms = @($active | Where-Object { $_.SmsPolicyTargeted -eq 'Yes' -or $_.VoicePolicyTargeted -eq 'Yes' })
    $status = if ($inSms.Count -gt 0) { 'Warn' } else { 'Pass' }
    $findings += New-PolicyFinding -Area $area -Check 'Phone users still allowed SMS/voice by policy' -Status $status `
        -Current "$($inSms.Count) of $($active.Count)" -Recommended '0'

    $notAllowed = @($active | Where-Object { $_.SmsPolicyTargeted -ne 'Yes' -and $_.VoicePolicyTargeted -ne 'Yes' })
    if ($notAllowed.Count -gt 0) {
        $findings += New-PolicyFinding -Area $area -Check 'Phone registered but blocked by policy' -Status Info `
            -Current "$($notAllowed.Count) of $($active.Count)" `
            -Notes 'Leftover registrations. Cleanup candidates, and a risk if SMS/voice is ever re-enabled.'
    }

    $prefPhone = @($active | Where-Object { "$($_.EffectiveMfaMethod)" -match $script:PhonePreferredPattern })
    $status = if ($prefPhone.Count -gt 0) { 'Warn' } else { 'Pass' }
    $findings += New-PolicyFinding -Area $area -Check 'SMS/voice is the effective default MFA method' -Status $status `
        -Current "$($prefPhone.Count) of $($active.Count)" -Recommended '0'

    $campaignStates = @($active | Select-Object -ExpandProperty InCampaignScope -Unique)
    $outside = @($active | Where-Object { $_.InCampaignScope -ne 'Yes' -and $_.InCampaignScope -ne 'Microsoft-managed' })
    if ($campaignStates -contains 'Microsoft-managed') {
        $findings += New-PolicyFinding -Area $area -Check 'Phone users outside registration campaign' -Status Info `
            -Current 'Campaign is Microsoft-managed' -Notes 'Scope is decided by Microsoft and cannot be evaluated.'
    }
    else {
        $status = if ($outside.Count -gt 0) { 'Warn' } else { 'Pass' }
        $findings += New-PolicyFinding -Area $area -Check 'Phone users outside registration campaign' -Status $status `
            -Current "$($outside.Count) of $($active.Count)" -Recommended '0'
    }

    $noPasskeyPolicy = @($active | Where-Object { $_.PasskeyPolicyTargeted -ne 'Yes' -and -not $_.HasPhishingResistant })
    $status = if ($noPasskeyPolicy.Count -gt 0) { 'Warn' } else { 'Pass' }
    $findings += New-PolicyFinding -Area $area -Check 'Phone users who cannot register a passkey (not in FIDO2 policy)' -Status $status `
        -Current "$($noPasskeyPolicy.Count) of $($active.Count)" -Recommended '0'

    if ($script:SignInScanDays -gt 0) {
        $used = @($active | Where-Object { $_.SmsSignInCount -gt 0 })
        $status = if ($used.Count -gt 0) { 'Warn' } else { 'Pass' }
        $findings += New-PolicyFinding -Area $area -Check "Users who completed MFA with SMS/voice (last $($script:SignInScanDays) days)" -Status $status `
            -Current "$($used.Count)" -Recommended '0'
    }

    return $findings
}

#endregion

# ============================================================================
# User hunt
# ============================================================================
#region User hunt

function Get-UserRegistrationDetails {
    <#
    .SYNOPSIS
        Bulk pull of the authentication methods registration report. One row per user.
        The report can lag behind real registrations; users missing from it are checked directly.
    #>
    [CmdletBinding()]
    param()

    $uri = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
    Write-Log "Retrieving user registration details report..." -Level "INFO"
    try {
        $rows = Invoke-GraphPaged -Uri $uri
        Write-Log "Retrieved $($rows.Count) registration detail rows" -Level "SUCCESS"
        return , $rows
    }
    catch {
        Write-Log "Could not read user registration details (needs AuditLog.Read.All): $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Get-DirectoryUsers {
    <#
    .SYNOPSIS
        All users with account state and last sign-in, keyed by object id.
    #>
    $select = 'id,displayName,userPrincipalName,userType,accountEnabled'
    Write-Log "Retrieving directory users..." -Level "INFO"
    $users = $null
    try {
        $users = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/users?`$select=$select,signInActivity&`$top=999"
    }
    catch {
        Write-Log "Sign-in activity unavailable, continuing without last sign-in: $($_.Exception.Message)" -Level "WARNING"
        try {
            $users = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/users?`$select=$select&`$top=999"
        }
        catch {
            Write-Log "Could not read users: $($_.Exception.Message)" -Level "ERROR"
            return $null
        }
    }

    $map = @{}
    foreach ($u in $users) { $map[$u.id] = $u }
    Write-Log "Retrieved $($map.Count) directory users" -Level "SUCCESS"
    return $map
}

function Get-AdminUserIds {
    <#
    .SYNOPSIS
        Users with an active directory role. Only used for users missing from the registration report.
    #>
    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $roles = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/directoryRoles?$select=id&$expand=members($select=id)'
        foreach ($r in $roles) { foreach ($m in @($r.members)) { if ($m.id) { [void]$ids.Add($m.id) } } }
    }
    catch {
        Write-Log "Could not read directory role members: $($_.Exception.Message)" -Level "WARNING"
    }
    return , $ids
}

function Get-PhoneMethodDetail {
    <#
    .SYNOPSIS
        Per-user phone method detail: number, phoneType and smsSignInState.
    .OUTPUTS
        PSCustomObject: UserId, Status ('Ok' | 'AccessDenied' | 'Error'),
        Phones (array of PSCustomObject PhoneType, PhoneNumber, SmsSignInState), Error.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$UserId)

    try {
        $resp = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/users/$UserId/authentication/phoneMethods"
        $phones = @($resp.value | ForEach-Object {
            [PSCustomObject]@{
                PhoneType      = "$($_.phoneType)"
                PhoneNumber    = "$($_.phoneNumber)"
                SmsSignInState = "$($_.smsSignInState)"
            }
        })
        return [PSCustomObject]@{ UserId = $UserId; Status = 'Ok'; Phones = $phones; Error = '' }
    }
    catch {
        $status = if (Test-AccessDenied $_) { 'AccessDenied' } else { 'Error' }
        return [PSCustomObject]@{ UserId = $UserId; Status = $status; Phones = @(); Error = $_.Exception.Message }
    }
}

function Get-UserMethodsDirect {
    <#
    .SYNOPSIS
        All authentication methods for one user, mapped to registration-report style keys.
        Used for users the registration report does not cover.
    #>
    param([Parameter(Mandatory)][string]$UserId)

    try {
        $resp = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/users/$UserId/authentication/methods"
    }
    catch {
        $status = if (Test-AccessDenied $_) { 'AccessDenied' } else { 'Error' }
        return [PSCustomObject]@{ Status = $status; Methods = @(); Phones = @(); Error = $_.Exception.Message }
    }

    $methods = [System.Collections.Generic.List[string]]::new()
    $phones = @()
    foreach ($m in @($resp.value)) {
        $type = "$($m.'@odata.type')" -replace '^#microsoft\.graph\.', ''
        switch ($type) {
            'phoneAuthenticationMethod' {
                $key = switch ("$($m.phoneType)") { 'mobile' { 'mobilePhone' } 'alternateMobile' { 'alternateMobilePhone' } 'office' { 'officePhone' } default { "$($m.phoneType)Phone" } }
                $methods.Add($key)
                $phones += [PSCustomObject]@{ PhoneType = "$($m.phoneType)"; PhoneNumber = "$($m.phoneNumber)"; SmsSignInState = "$($m.smsSignInState)" }
            }
            'microsoftAuthenticatorAuthenticationMethod'  { $methods.Add('microsoftAuthenticatorPush') }
            'fido2AuthenticationMethod'                   { $methods.Add('fido2') }
            'windowsHelloForBusinessAuthenticationMethod' { $methods.Add('windowsHelloForBusiness') }
            'softwareOathAuthenticationMethod'            { $methods.Add('softwareOneTimePasscode') }
            'hardwareOathAuthenticationMethod'            { $methods.Add('hardwareOneTimePasscode') }
            'emailAuthenticationMethod'                   { $methods.Add('email') }
            'platformCredentialAuthenticationMethod'      { $methods.Add('platformCredential') }
            'passwordAuthenticationMethod'                { }
            'temporaryAccessPassAuthenticationMethod'     { }
            default                                       { if ($type) { $methods.Add($type) } }
        }
    }
    return [PSCustomObject]@{ Status = 'Ok'; Methods = @($methods | Select-Object -Unique); Phones = $phones; Error = '' }
}

function Get-SmsSignInUsage {
    <#
    .SYNOPSIS
        Scans MFA sign-ins (beta, authenticationDetails is empty in v1.0) for SMS/voice use.
    .OUTPUTS
        Hashtable userId -> PSCustomObject Count, Last, Methods. $null when the scan failed.
    #>
    param([Parameter(Mandatory)][int]$Days)

    $since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
    # $select with authenticationDetails returns 400, and authenticationDetails/any() is not filterable.
    $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime ge $since and authenticationRequirement eq 'multiFactorAuthentication'&`$top=999"
    Write-Log "Scanning MFA sign-ins for the last $Days day(s)..." -Level "INFO"

    $usage = @{}
    $scanned = 0
    try {
        while ($uri) {
            $page = Invoke-GraphGet -Uri $uri
            foreach ($s in @($page.value)) {
                $scanned++
                foreach ($d in @($s.authenticationDetails)) {
                    if (-not $d -or -not $d.succeeded) { continue }
                    $method = "$($d.authenticationMethod)"
                    if ($method -notmatch $script:PhoneSignInPattern) { continue }
                    $uid = "$($s.userId)"
                    if (-not $usage.ContainsKey($uid)) {
                        $usage[$uid] = [PSCustomObject]@{ Count = 0; Last = $null; Methods = [System.Collections.Generic.HashSet[string]]::new() }
                    }
                    $entry = $usage[$uid]
                    $entry.Count++
                    [void]$entry.Methods.Add($method)
                    $when = [datetime]$s.createdDateTime
                    if (-not $entry.Last -or $when -gt $entry.Last) { $entry.Last = $when }
                }
            }
            $uri = $page.'@odata.nextLink'
            Write-Progress -Activity "Scanning sign-in logs" -Status "$scanned MFA sign-ins scanned"
        }
    }
    catch {
        Write-Progress -Activity "Scanning sign-in logs" -Completed
        Write-Log "Sign-in log scan failed (needs AuditLog.Read.All and Entra ID P1): $($_.Exception.Message)" -Level "WARNING"
        return $null
    }
    Write-Progress -Activity "Scanning sign-in logs" -Completed
    Write-Log "Scanned $scanned MFA sign-ins. $($usage.Count) user(s) completed MFA with SMS/voice." -Level "SUCCESS"
    return $usage
}

function Get-SmsRiskLevel {
    <#
    .SYNOPSIS
        Scores one user. Returns @{ Level; Notes }.
    .NOTES
        N/A      : Account disabled.
        High     : SMS/voice is the ONLY MFA method, the effective default method, or was used
                   for MFA in the scanned sign-in window.
        Medium   : SMS/voice next to Authenticator/OATH, no phishing-resistant method.
        Low      : SMS/voice next to a phishing-resistant method (cleanup candidate).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$Finding)

    if ($Finding.AccountEnabled -ne $true) {
        return @{ Level = 'N/A'; Notes = 'Account disabled' }
    }

    $notes = @()
    if ($Finding.SmsSignInCount -gt 0) { $notes += "Used SMS/voice for MFA $($Finding.SmsSignInCount)x recently" }
    if ("$($Finding.SmsSignInState)" -match '(^|,\s*)ready') { $notes += 'SMS sign-in ready' }

    if ($Finding.PhoneOnly) {
        return @{ Level = 'High'; Notes = (@("SMS/voice is the only MFA method (retires $($script:SmsRetirementDate))") + $notes) -join '; ' }
    }
    if ("$($Finding.EffectiveMfaMethod)" -match $script:PhonePreferredPattern) {
        return @{ Level = 'High'; Notes = (@("SMS/voice is the default MFA method ($($Finding.EffectiveMfaMethod))") + $notes) -join '; ' }
    }
    if ($Finding.SmsSignInCount -gt 0) {
        return @{ Level = 'High'; Notes = $notes -join '; ' }
    }
    if (-not $Finding.HasPhishingResistant) {
        return @{ Level = 'Medium'; Notes = (@('SMS/voice next to other MFA, no phishing-resistant method') + $notes) -join '; ' }
    }
    return @{ Level = 'Low'; Notes = (@('Has phishing-resistant method; remove SMS/voice') + $notes) -join '; ' }
}

function Find-SmsUsers {
    <#
    .SYNOPSIS
        Orchestrates the hunt and returns one finding object per user with phone MFA registered.
        Users missing from the report whose methods cannot be read are skipped and counted in the log.
    #>
    [CmdletBinding()]
    param([int]$SignInDays = 0)

    $details = Get-UserRegistrationDetails
    if ($null -eq $details) { return $null }

    $directory = Get-DirectoryUsers
    if ($null -eq $directory) { return $null }

    $scopes = Get-PolicyScopes
    if (-not $scopes) { Write-Log "Policy scopes unavailable; policy columns will show Unknown" -Level "WARNING" }

    $usage = $null
    $script:SignInScanDays = 0
    if ($SignInDays -gt 0) {
        $usage = Get-SmsSignInUsage -Days $SignInDays
        if ($null -ne $usage) { $script:SignInScanDays = $SignInDays }
    }

    $reportIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $details) { [void]$reportIds.Add($d.id) }

    $candidates = [System.Collections.Generic.List[object]]::new()
    foreach ($d in $details) {
        $methods = @($d.methodsRegistered | Where-Object { $_ })
        if (-not ($methods -match $script:PhoneMethodPattern)) { continue }
        $sysPref = @($d.systemPreferredAuthenticationMethods | Where-Object { $_ })
        $effective = if ($d.isSystemPreferredAuthenticationMethodEnabled -and $sysPref.Count -gt 0) { "$($sysPref[0])" } else { "$($d.userPreferredMethodForSecondaryAuthentication)" }
        $candidates.Add([PSCustomObject]@{
            Id              = $d.id
            Upn             = $d.userPrincipalName
            DisplayName     = $d.userDisplayName
            Methods         = $methods
            Preferred       = "$($d.userPreferredMethodForSecondaryAuthentication)"
            SystemPreferred = ($sysPref -join ', ')
            Effective       = $effective
            IsAdmin         = [bool]$d.isAdmin
            Source          = 'Registration report'
            Detail          = $null
        })
    }
    Write-Log "$($candidates.Count) of $($details.Count) users in the registration report have a phone method registered" -Level "INFO"

    $gapUsers = @($directory.Values | Where-Object { -not $reportIds.Contains($_.id) })
    $adminIds = $null
    $unreadable = 0
    if ($gapUsers.Count -gt 0) {
        Write-Log "$($gapUsers.Count) directory user(s) missing from the registration report. Checking them directly." -Level "WARNING"
        $adminIds = Get-AdminUserIds
        $i = 0
        foreach ($u in $gapUsers) {
            $i++
            Write-Progress -Activity "Checking users missing from the registration report" -Status "$i of $($gapUsers.Count) - $($u.userPrincipalName)" -PercentComplete ([math]::Round($i / $gapUsers.Count * 100))
            $direct = Get-UserMethodsDirect -UserId $u.id
            if ($direct.Status -ne 'Ok') { $unreadable++; continue }
            if (-not (@($direct.Methods) -match $script:PhoneMethodPattern)) { continue }
            $candidates.Add([PSCustomObject]@{
                Id              = $u.id
                Upn             = $u.userPrincipalName
                DisplayName     = $u.displayName
                Methods         = @($direct.Methods)
                Preferred       = ''
                SystemPreferred = ''
                Effective       = ''
                IsAdmin         = $adminIds.Contains($u.id)
                Source          = 'Direct lookup'
                Detail          = [PSCustomObject]@{ Status = $direct.Status; Phones = $direct.Phones; Error = $direct.Error }
            })
        }
        Write-Progress -Activity "Checking users missing from the registration report" -Completed
    }

    # The registration report lags, so a user can use SMS before the report shows a phone method.
    if ($usage) {
        $candidateIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($c in $candidates) { [void]$candidateIds.Add($c.Id) }
        $missed = @($usage.Keys | Where-Object { -not $candidateIds.Contains($_) })
        if ($missed.Count -gt 0) {
            Write-Log "$($missed.Count) user(s) used SMS/voice in sign-ins but have no phone method in the registration report. Checking them directly." -Level "WARNING"
            if ($null -eq $adminIds) { $adminIds = Get-AdminUserIds }
            foreach ($id in $missed) {
                $direct = Get-UserMethodsDirect -UserId $id
                $dirUser = $directory[$id]
                $reportRow = $details | Where-Object { $_.id -eq $id } | Select-Object -First 1
                $candidates.Add([PSCustomObject]@{
                    Id              = $id
                    Upn             = if ($dirUser) { $dirUser.userPrincipalName } else { $id }
                    DisplayName     = if ($dirUser) { $dirUser.displayName } else { '' }
                    Methods         = @($direct.Methods)
                    Preferred       = if ($reportRow) { "$($reportRow.userPreferredMethodForSecondaryAuthentication)" } else { '' }
                    SystemPreferred = ''
                    Effective       = if ($reportRow) { "$($reportRow.userPreferredMethodForSecondaryAuthentication)" } else { '' }
                    IsAdmin         = if ($reportRow) { [bool]$reportRow.isAdmin } else { $adminIds.Contains($id) }
                    Source          = 'Sign-in log'
                    Detail          = [PSCustomObject]@{ Status = $direct.Status; Phones = $direct.Phones; Error = $direct.Error }
                })
            }
        }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $i = 0
    $total = $candidates.Count
    foreach ($c in $candidates) {
        $i++
        if ($total -gt 0) {
            Write-Progress -Activity "Reading phone methods" -Status "$i of $total - $($c.Upn)" -PercentComplete ([math]::Round($i / $total * 100))
        }

        $detail = if ($c.Detail) { $c.Detail } else { Get-PhoneMethodDetail -UserId $c.Id }
        if ($detail.Status -eq 'Error') {
            Write-Log "Could not read phone methods for $($c.Upn): $($detail.Error)" -Level "WARNING"
        }

        $dirUser = $directory[$c.Id]
        $lastSignIn = $null
        if ($dirUser -and $dirUser.signInActivity -and $dirUser.signInActivity.lastSignInDateTime) {
            $lastSignIn = ([datetime]$dirUser.signInActivity.lastSignInDateTime).ToString('yyyy-MM-dd')
        }

        $otherMethods = @($c.Methods | Where-Object { $_ -notmatch $script:PhoneMethodPattern })
        $mfaAlternatives = @($otherMethods | Where-Object { $_ -notmatch $script:NonMfaMethodPattern })
        $phones = @($detail.Phones)

        $use = if ($usage -and $usage.ContainsKey($c.Id)) { $usage[$c.Id] } else { $null }
        $userType = if ($dirUser -and $dirUser.userType) { "$($dirUser.userType)" } else { 'Unknown' }

        $row = [PSCustomObject]@{
            UserId                = $c.Id
            UserPrincipalName     = $c.Upn
            DisplayName           = $c.DisplayName
            UserType              = $userType
            AccountEnabled        = if ($dirUser) { [bool]$dirUser.accountEnabled } else { $null }
            IsAdmin               = [bool]$c.IsAdmin
            LastSignIn            = $lastSignIn
            PhoneTypes            = (@($phones.PhoneType | Where-Object { $_ }) -join ', ')
            PhoneNumbers          = (@($phones.PhoneNumber | Where-Object { $_ }) -join ', ')
            PhoneCountry          = (@($phones.PhoneNumber | Where-Object { $_ } | ForEach-Object { Get-CountryFromPhone -PhoneNumber $_ }) | Select-Object -Unique) -join ', '
            SmsSignInState        = (@($phones.SmsSignInState | Where-Object { $_ }) | Select-Object -Unique) -join ', '
            PreferredMfaMethod    = $c.Preferred
            SystemPreferredMethod = $c.SystemPreferred
            EffectiveMfaMethod    = $c.Effective
            OtherMethods          = (@($otherMethods | ForEach-Object { Get-MethodDisplayName $_ }) -join ', ')
            MethodsRegistered     = (@($c.Methods) -join ', ')
            PhoneOnly             = ($mfaAlternatives.Count -eq 0)
            HasAuthenticator      = [bool](@($c.Methods) -match '^microsoftAuthenticator')
            HasPhishingResistant  = [bool](@($c.Methods) -match $script:PhishResistantPattern)
            SmsPolicyTargeted     = if ($scopes) { Get-ScopeLabel -Entry $scopes['Sms'] -UserId $c.Id } else { 'Unknown' }
            VoicePolicyTargeted   = if ($scopes) { Get-ScopeLabel -Entry $scopes['Voice'] -UserId $c.Id } else { 'Unknown' }
            InCampaignScope       = if ($scopes) { Get-ScopeLabel -Entry $scopes['Campaign'] -UserId $c.Id } else { 'Unknown' }
            PasskeyPolicyTargeted = if ($scopes) { Get-ScopeLabel -Entry $scopes['Fido2'] -UserId $c.Id } else { 'Unknown' }
            SmsSignInCount        = if ($use) { $use.Count } else { 0 }
            LastSmsSignIn         = if ($use -and $use.Last) { $use.Last.ToString('yyyy-MM-dd HH:mm') } else { '' }
            DataSource            = $c.Source
            DataStatus            = $detail.Status
            RiskLevel             = ''
            RiskNotes             = ''
        }

        $risk = Get-SmsRiskLevel -Finding $row
        $row.RiskLevel = $risk.Level
        $row.RiskNotes = $risk.Notes
        $rows.Add($row)
    }
    if ($total -gt 0) { Write-Progress -Activity "Reading phone methods" -Completed }

    if ($unreadable -gt 0) {
        Write-Log "$unreadable user(s) missing from the registration report could not be read (access denied or error) and were skipped" -Level "WARNING"
    }
    Write-Log "Hunt complete: $($rows.Count) user(s) with SMS/voice registered" -Level "SUCCESS"
    Write-Log "Note: the registration report can lag behind recent registrations." -Level "INFO"
    return , $rows
}

#endregion

# ============================================================================
# Output
# ============================================================================
#region Output

function Show-PolicyConsole {
    param([array]$Findings, [string]$Title = 'POLICY POSTURE')

    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host $Title -ForegroundColor Green
    Write-Host ("=" * 80) -ForegroundColor Green

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Host "  No findings." -ForegroundColor Gray
        return
    }

    foreach ($area in @($Findings.Area | Select-Object -Unique)) {
        Write-Host ""
        Write-Host "  $($area.ToUpper())" -ForegroundColor Yellow
        foreach ($f in @($Findings | Where-Object { $_.Area -eq $area })) {
            $color = switch ($f.Status) { 'Fail' { 'Red' } 'Warn' { 'Yellow' } 'Pass' { 'Green' } default { 'Gray' } }
            Write-Host ("    [{0,-4}] {1}: {2}" -f $f.Status.ToUpper(), $f.Check, $f.Current) -ForegroundColor $color
        }
    }

    $counts = $Findings | Group-Object Status | ForEach-Object { "$($_.Name): $($_.Count)" }
    Write-Host ""
    Write-Host "  Summary: $($counts -join ' | ')" -ForegroundColor Cyan
}

function Show-UserConsole {
    param([array]$Findings)

    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host "SMS / VOICE MFA USERS" -ForegroundColor Green
    Write-Host ("=" * 80) -ForegroundColor Green

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Host "  No users with SMS/voice registered." -ForegroundColor Green
        return
    }

    $enabled = @($Findings | Where-Object { $_.AccountEnabled -eq $true })
    Write-Host "  Users with SMS/voice registered:     $($Findings.Count)" -ForegroundColor White
    Write-Host "    Enabled accounts:                  $($enabled.Count)" -ForegroundColor White
    Write-Host "    Admins:                            $(@($enabled | Where-Object IsAdmin).Count)" -ForegroundColor White
    Write-Host "    SMS/voice is only MFA method:      $(@($enabled | Where-Object PhoneOnly).Count)" -ForegroundColor White
    Write-Host "    SMS/voice is default method:       $(@($enabled | Where-Object { "$($_.EffectiveMfaMethod)" -match $script:PhonePreferredPattern }).Count)" -ForegroundColor White
    Write-Host "    No phishing-resistant method:      $(@($enabled | Where-Object { -not $_.HasPhishingResistant }).Count)" -ForegroundColor White
    Write-Host "    SMS sign-in ready:                 $(@($enabled | Where-Object { "$($_.SmsSignInState)" -match '(^|,\s*)ready' }).Count)" -ForegroundColor White
    Write-Host "    Allowed SMS/voice by policy:       $(@($enabled | Where-Object { $_.SmsPolicyTargeted -eq 'Yes' -or $_.VoicePolicyTargeted -eq 'Yes' }).Count)" -ForegroundColor White
    if ($script:SignInScanDays -gt 0) {
        Write-Host "    Used SMS/voice (last $($script:SignInScanDays) days):      $(@($enabled | Where-Object { $_.SmsSignInCount -gt 0 }).Count)" -ForegroundColor White
    }

    Write-Host ""
    Write-Host "  RISK:" -ForegroundColor Yellow
    foreach ($lvl in @(
        @{ N = 'High'; C = 'DarkYellow' }, @{ N = 'Medium'; C = 'Yellow' },
        @{ N = 'Low'; C = 'Cyan' }, @{ N = 'N/A'; C = 'Gray' })) {
        Write-Host ("    {0,-9} {1}" -f $lvl.N, @($Findings | Where-Object { $_.RiskLevel -eq $lvl.N }).Count) -ForegroundColor $lvl.C
    }

    $countries = $Findings | Where-Object { $_.PhoneCountry } | ForEach-Object { $_.PhoneCountry -split ',\s*' } | Group-Object | Sort-Object Count -Descending
    if ($countries) {
        Write-Host ""
        Write-Host "  PHONE NUMBERS BY COUNTRY:" -ForegroundColor Yellow
        foreach ($c in $countries) { Write-Host "    $($c.Name): $($c.Count)" }
    }

    $top = @($Findings | Where-Object { $_.RiskLevel -eq 'High' } | Sort-Object UserPrincipalName | Select-Object -First 15)
    if ($top.Count -gt 0) {
        Write-Host ""
        Write-Host "  HIGH (first 15):" -ForegroundColor Yellow
        foreach ($u in $top) {
            Write-Host ("    {0} - {1}" -f $u.UserPrincipalName, $u.RiskNotes) -ForegroundColor DarkYellow
        }
    }

    $phoneOnly = @($enabled | Where-Object PhoneOnly).Count
    if ($phoneOnly -gt 0) {
        Write-Host ""
        Write-Host "  SMS/VOICE RETIREMENT NOTICE:" -ForegroundColor DarkYellow
        Write-Host "    $phoneOnly account(s) rely on SMS/voice only and must register another method before $($script:SmsRetirementDate)." -ForegroundColor DarkYellow
        Write-Host "    $($script:SmsRetirementUrl)" -ForegroundColor Yellow
    }
}

function Export-SmsCsv {
    param(
        [array]$PolicyFindings,
        [array]$UserFindings,
        [Parameter(Mandatory)][string]$Timestamp
    )

    $dir = ".\exports"
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $paths = @()
    if ($UserFindings -and $UserFindings.Count -gt 0) {
        $path = Join-Path $dir "SmsMfaUsers-$Timestamp.csv"
        $UserFindings | Export-Csv -Path $path -Delimiter ';' -NoTypeInformation -Encoding UTF8
        Write-Log "User findings exported to: $path" -Level "SUCCESS"
        $paths += $path
    }
    if ($PolicyFindings -and $PolicyFindings.Count -gt 0) {
        $path = Join-Path $dir "SmsMfaPolicyPosture-$Timestamp.csv"
        $PolicyFindings | Export-Csv -Path $path -Delimiter ';' -NoTypeInformation -Encoding UTF8
        Write-Log "Policy findings exported to: $path" -Level "SUCCESS"
        $paths += $path
    }
    return $paths
}

function ConvertTo-EmbeddedJson {
    param([array]$Rows)
    $json = $Rows | ConvertTo-Json -Depth 4 -Compress
    if (-not $json) { $json = '[]' }
    if ($json -notmatch '^\s*\[') { $json = "[$json]" }
    # JSON is valid JS. Only "</" is broken up so data cannot end the <script> block.
    return ($json -replace '</', '<\/')
}

function New-SmsHtmlReport {
    <#
    .SYNOPSIS
        Self-contained HTML report (works offline, no external dependencies). Layout follows I.D.E.A. 004.
    #>
    param(
        [array]$PolicyFindings = @(),
        [array]$UserFindings = @(),
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$TenantName = "Unknown",
        [int]$SignInScanDays = 0
    )

    $userRows = @($UserFindings | Where-Object { $_ } | ForEach-Object {
        $tags = @()
        foreach ($t in @("$($_.PhoneTypes)" -split ',\s*' | Where-Object { $_ })) {
            $tags += switch ($t) { 'mobile' { 'Mobile phone' } 'alternateMobile' { 'Alternate mobile phone' } 'office' { 'Office phone' } default { "$t phone" } }
        }
        foreach ($m in @("$($_.OtherMethods)" -split ',\s*' | Where-Object { $_ })) { $tags += $m }

        [PSCustomObject]@{
            displayName      = "$($_.DisplayName)"
            upn              = "$($_.UserPrincipalName)"
            userType         = "$($_.UserType)"
            accountStatus    = if ($_.AccountEnabled -eq $true) { 'Enabled' } elseif ($_.AccountEnabled -eq $false) { 'Disabled' } else { 'Unknown' }
            isAdmin          = if ($_.IsAdmin) { 'Yes' } else { 'No' }
            phoneTypes       = "$($_.PhoneTypes)"
            phoneNumbers     = "$($_.PhoneNumbers)"
            phoneCountry     = "$($_.PhoneCountry)"
            smsSignInState   = "$($_.SmsSignInState)"
            effectiveMethod  = "$($_.EffectiveMfaMethod)"
            otherMethods     = "$($_.OtherMethods)"
            methodTags       = @($tags)
            phoneOnly        = if ($_.PhoneOnly) { 'Yes' } else { 'No' }
            phishResistant   = if ($_.HasPhishingResistant) { 'Yes' } else { 'No' }
            smsPolicy        = "$($_.SmsPolicyTargeted)"
            voicePolicy      = "$($_.VoicePolicyTargeted)"
            campaign         = "$($_.InCampaignScope)"
            passkeyPolicy    = "$($_.PasskeyPolicyTargeted)"
            smsUseCount      = [int]$_.SmsSignInCount
            lastSmsUse       = "$($_.LastSmsSignIn)"
            lastSignIn       = if ($_.LastSignIn) { "$($_.LastSignIn)" } else { 'Never' }
            dataSource       = "$($_.DataSource)"
            riskLevel        = "$($_.RiskLevel)"
            riskNotes        = "$($_.RiskNotes)"
        }
    })

    $policyRows = @($PolicyFindings | Where-Object { $_ } | ForEach-Object {
        [PSCustomObject]@{ Area = "$($_.Area)"; Check = "$($_.Check)"; Status = "$($_.Status)"; Current = "$($_.Current)"; Recommended = "$($_.Recommended)"; Notes = "$($_.Notes)" }
    })

    $userJson   = ConvertTo-EmbeddedJson -Rows $userRows
    $policyJson = ConvertTo-EmbeddedJson -Rows $policyRows
    $safeTenant = [System.Net.WebUtility]::HtmlEncode($TenantName)
    $generatedDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $scanLabel = if ($SignInScanDays -gt 0) { "Sign-in scan: last $SignInScanDays days" } else { 'Sign-in scan: not run' }

    $phoneOnlyCount = @($UserFindings | Where-Object { $_ -and $_.PhoneOnly -and $_.AccountEnabled -eq $true }).Count
    $retirementHtml = ''
    if ($phoneOnlyCount -gt 0) {
        $label = if ($phoneOnlyCount -eq 1) { 'account relies' } else { 'accounts rely' }
        $retirementHtml = @"
<div class="retirement-notice">
    <div class="retirement-icon">&#9888;</div>
    <div class="retirement-copy">
        <strong>SMS/voice-only MFA retirement notice</strong>
        <div>$phoneOnlyCount enabled $label on SMS or voice call as the only MFA method and must register another method before $($script:SmsRetirementDate).</div>
        <div class="retirement-links">
            <a href="$($script:SmsRetirementUrl)" target="_blank" rel="noopener noreferrer">Microsoft retirement notice</a>
        </div>
    </div>
</div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Entra ID SMS MFA Report - $safeTenant - $generatedDate</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; padding: 20px; }
.header { background: linear-gradient(135deg, #1a237e, #0d47a1); color: white; padding: 30px; border-radius: 12px; margin-bottom: 20px; }
.header h1 { font-size: 1.8em; margin-bottom: 5px; }
.header .meta { opacity: 0.8; font-size: 0.9em; }
.dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
.card { background: white; border-radius: 10px; padding: 18px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; }
.card .value { font-size: 2em; font-weight: 700; }
.card .label { font-size: 0.85em; color: #666; margin-top: 5px; }
.card.alert .value { color: #d32f2f; }
.card.high .value { color: #f57c00; }
.card.medium .value { color: #fbc02d; }
.card.low .value { color: #0097a7; }
.card.info .value { color: #1565c0; }
.section-title { font-size: 1.1em; font-weight: 700; color: #1a237e; margin-bottom: 12px; }
.policy-area { border: 1px solid #e8e8e8; border-radius: 8px; margin-bottom: 10px; overflow: hidden; }
.policy-area-header { display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; background: #f8f9fa; cursor: pointer; font-weight: 600; color: #1a237e; user-select: none; }
.policy-area-header:hover { background: #eef1f6; }
.policy-area-header.collapsed + .policy-area-body { display: none; }
.policy-table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
.policy-table th { background: #e8eaf6; color: #1a237e; padding: 8px 10px; text-align: left; cursor: default; }
.policy-table td { padding: 8px 10px; border-top: 1px solid #f0f0f0; vertical-align: top; }
.status-fail { background: #ffebee; color: #c62828; }
.status-warn { background: #fff3e0; color: #e65100; }
.status-pass { background: #e8f5e9; color: #2e7d32; }
.status-info { background: #e3f2fd; color: #1565c0; }
.filters { background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
.filters h3 { margin-bottom: 12px; color: #1a237e; }
.filter-row { display: flex; flex-wrap: wrap; gap: 12px; align-items: end; }
.filter-group { display: flex; flex-direction: column; }
.filter-group label { font-size: 0.8em; font-weight: 600; color: #555; margin-bottom: 4px; }
.filter-group select, .filter-group input { padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 0.9em; min-width: 140px; }
.filter-group input[type="text"] { min-width: 200px; }
.method-filters { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 10px; padding-top: 10px; border-top: 1px solid #eee; }
.method-filters > label { font-size: 0.8em; font-weight: 600; color: #555; margin-right: 8px; }
.method-logic-toggle { display: inline-flex; align-items: center; gap: 6px; margin-left: 12px; padding: 4px 10px; background: #f5f5f5; border-radius: 16px; font-size: 0.75em; font-weight: 600; border: 1px solid #ddd; }
.method-logic-toggle span { padding: 2px 8px; border-radius: 10px; cursor: pointer; color: #777; }
.method-logic-toggle span.active { background: #1565c0; color: white; }
.method-logic-toggle span.disabled { opacity: 0.45; cursor: not-allowed; pointer-events: none; }
.method-only-toggle { display: inline-flex; align-items: center; gap: 6px; margin-left: 10px; font-size: 0.78em; color: #555; }
.method-chip { display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px; background: #e3f2fd; border-radius: 16px; font-size: 0.8em; cursor: pointer; user-select: none; border: 1px solid #bbdefb; }
.method-chip.active { background: #1565c0; color: white; border-color: #1565c0; }
.btn-reset { padding: 8px 16px; background: #e0e0e0; border: none; border-radius: 6px; cursor: pointer; font-size: 0.85em; font-weight: 600; }
.btn-reset:hover { background: #bdbdbd; }
.table-container { background: white; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); overflow: hidden; }
.table-info { padding: 12px 20px; background: #fafafa; border-bottom: 1px solid #eee; font-size: 0.85em; color: #666; }
#smsTable { width: 100%; border-collapse: collapse; font-size: 0.85em; }
#smsTable thead { background: #1a237e; color: white; position: sticky; top: 0; }
#smsTable th { padding: 12px 10px; text-align: left; cursor: pointer; user-select: none; white-space: nowrap; }
#smsTable th:hover { background: #283593; }
#smsTable th.sorted-asc .sort-icon::after { content: ' \25B2'; }
#smsTable th.sorted-desc .sort-icon::after { content: ' \25BC'; }
#smsTable td { padding: 10px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
#smsTable tr:hover { background: #f5f5f5; }
tr.risk-high { border-left: 4px solid #f57c00; }
tr.risk-medium { border-left: 4px solid #fbc02d; }
tr.risk-low { border-left: 4px solid #0097a7; }
tr.risk-na { border-left: 4px solid #9e9e9e; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.8em; font-weight: 600; white-space: nowrap; }
.badge-high { background: #fff3e0; color: #e65100; }
.badge-medium { background: #fffde7; color: #f57f17; }
.badge-low { background: #e0f7fa; color: #00695c; }
.badge-na { background: #f5f5f5; color: #616161; }
.badge-enabled, .badge-yes { background: #e8f5e9; color: #2e7d32; }
.badge-disabled { background: #ffebee; color: #c62828; }
.badge-guest { background: #e3f2fd; color: #1565c0; }
.badge-member { background: #f3e5f5; color: #6a1b9a; }
.badge-warnyes { background: #fff3e0; color: #e65100; }
.muted { color: #757575; font-size: 0.85em; }
.footer { margin-top: 20px; text-align: center; font-size: 0.8em; color: #999; }
.pii-notice { background: #e8f4fd; border: 1px solid #4f83cc; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px; font-size: 0.85em; color: #17324d; display: flex; align-items: flex-start; gap: 12px; }
.pii-notice .pii-icon { font-size: 1.4em; flex-shrink: 0; line-height: 1.2; color: #1565c0; }
.pii-notice .pii-text strong { display: block; margin-bottom: 4px; color: #0d47a1; }
.pii-notice .pii-dismiss { margin-left: auto; cursor: pointer; font-size: 1.1em; color: #999; flex-shrink: 0; padding: 0 4px; }
.retirement-notice { background: #fff1f0; border: 1px solid #d84315; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px; font-size: 0.88em; color: #5f2120; display: flex; align-items: flex-start; gap: 12px; }
.retirement-notice .retirement-icon { font-size: 1.4em; flex-shrink: 0; line-height: 1.2; color: #c62828; }
.retirement-notice .retirement-copy strong { display: block; margin-bottom: 4px; color: #b71c1c; }
.retirement-links { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 6px; }
.retirement-links a { color: #0d47a1; font-weight: 600; text-decoration: none; }
.summary-block { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 20px; }
.mfa-bar-track { display: flex; height: 28px; border-radius: 6px; overflow: hidden; margin-bottom: 10px; background: #eee; }
.mfa-bar-segment { height: 100%; }
.mfa-bar-legend { display: flex; flex-wrap: wrap; gap: 16px; font-size: 0.8em; color: #444; }
.mfa-bar-legend-item { display: flex; align-items: center; gap: 5px; }
.mfa-bar-legend-swatch { width: 12px; height: 12px; border-radius: 3px; flex-shrink: 0; }
.pie-row { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 24px; }
.pie-box-title { font-size: 0.9em; font-weight: 700; color: #1a237e; margin-bottom: 10px; }
.pie-box-inner { display: flex; align-items: center; gap: 16px; }
.pie-legend { display: flex; flex-direction: column; gap: 5px; }
@media (max-width: 900px) { .pie-row { grid-template-columns: 1fr; } .filter-row { flex-direction: column; } .filter-group select, .filter-group input { min-width: 100%; } }
</style>
</head>
<body>
<div class="header">
<h1>Entra ID SMS / Voice MFA Report</h1>
<div class="meta">Tenant: $safeTenant | Generated: $generatedDate | $scanLabel</div>
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

$retirementHtml

<div class="dashboard" id="dashboard"></div>

<div class="summary-block" id="summaryBlock">
  <div id="barLabel" class="pie-box-title"></div>
  <div class="mfa-bar-track" id="mfaBar"></div>
  <div class="mfa-bar-legend" id="mfaBarLegend"></div>
</div>

<div class="summary-block">
  <div class="pie-row">
    <div>
      <div class="pie-box-title">Risk Summary</div>
      <div class="pie-box-inner"><svg id="riskPie" width="90" height="90" viewBox="-1 -1 2 2" style="flex-shrink:0"></svg><div class="pie-legend" id="riskPieLegend"></div></div>
    </div>
    <div>
      <div class="pie-box-title">Policy Posture</div>
      <div class="pie-box-inner"><svg id="policyPie" width="90" height="90" viewBox="-1 -1 2 2" style="flex-shrink:0"></svg><div class="pie-legend" id="policyPieLegend"></div></div>
    </div>
    <div>
      <div class="pie-box-title">Phone Numbers by Country</div>
      <div class="pie-box-inner"><svg id="phonePie" width="90" height="90" viewBox="-1 -1 2 2" style="flex-shrink:0"></svg><div class="pie-legend" id="phonePieLegend"></div></div>
    </div>
  </div>
</div>

<div class="summary-block">
  <div class="section-title">Policy Posture</div>
  <div id="policyBody"></div>
</div>

<div class="filters">
<h3>Filters</h3>
<div class="filter-row">
<div class="filter-group"><label>Search (Name / UPN / Phone)</label><input type="text" id="searchBox" placeholder="Name, UPN, or phone e.g. +47..."></div>
<div class="filter-group"><label>Risk Level</label><select id="filterRisk"><option value="">All</option><option>High</option><option>Medium</option><option>Low</option><option>N/A</option></select></div>
<div class="filter-group"><label>User Type</label><select id="filterType" data-field="userType"><option value="">All</option></select></div>
<div class="filter-group"><label>Account Status</label><select id="filterStatus" data-field="accountStatus"><option value="">All</option></select></div>
<div class="filter-group"><label>SMS/Voice Only</label><select id="filterPhoneOnly"><option value="">All</option><option>Yes</option><option>No</option></select></div>
<div class="filter-group"><label>SMS Policy</label><select id="filterSmsPolicy" data-field="smsPolicy"><option value="">All</option></select></div>
<div class="filter-group"><label>Passkey Policy</label><select id="filterPasskey" data-field="passkeyPolicy"><option value="">All</option></select></div>
<div class="filter-group"><label>Campaign Scope</label><select id="filterCampaign" data-field="campaign"><option value="">All</option></select></div>
<div class="filter-group"><label>Has signed in with SMS</label><select id="filterUsed"><option value="">All</option><option value="Yes">Yes</option><option value="No">No</option></select></div>
<div class="filter-group"><button class="btn-reset" onclick="resetFilters()">Reset All</button></div>
</div>
<div class="method-filters" id="methodFilters">
<label>Methods:</label>
<span id="methodChips"></span>
<div class="method-logic-toggle"><span id="modeOr" class="active" onclick="setMethodMode('or')">OR</span><span id="modeAnd" onclick="setMethodMode('and')">AND</span></div>
<label class="method-only-toggle"><input type="checkbox" id="filterOnlySelectedMethods">Only selected methods</label>
</div>
</div>

<div class="table-container">
<div class="table-info">Showing <span id="visibleCount">0</span> of <span id="totalCount">0</span> users with SMS/voice registered</div>
<div style="overflow-x:auto; max-height: 70vh; overflow-y: auto;">
<table id="smsTable">
<thead>
<tr>
<th data-col="displayName" onclick="sortTable('displayName')">Display Name<span class="sort-icon"></span></th>
<th data-col="upn" onclick="sortTable('upn')">UPN<span class="sort-icon"></span></th>
<th data-col="userType" onclick="sortTable('userType')">Type<span class="sort-icon"></span></th>
<th data-col="accountStatus" onclick="sortTable('accountStatus')">Account<span class="sort-icon"></span></th>
<th data-col="phoneNumbers" onclick="sortTable('phoneNumbers')">Phone<span class="sort-icon"></span></th>
<th data-col="smsSignInState" onclick="sortTable('smsSignInState')" title="smsSignInState from the phone method">SMS Sign-in<span class="sort-icon"></span></th>
<th data-col="otherMethods" onclick="sortTable('otherMethods')">Other Methods<span class="sort-icon"></span></th>
<th data-col="smsPolicy" onclick="sortTable('smsPolicy')">SMS Policy<span class="sort-icon"></span></th>
<th data-col="voicePolicy" onclick="sortTable('voicePolicy')">Voice Policy<span class="sort-icon"></span></th>
<th data-col="passkeyPolicy" onclick="sortTable('passkeyPolicy')">Passkey Policy<span class="sort-icon"></span></th>
<th data-col="campaign" onclick="sortTable('campaign')">Campaign<span class="sort-icon"></span></th>
<th data-col="smsUseCount" onclick="sortTable('smsUseCount')">SMS Uses<span class="sort-icon"></span></th>
<th data-col="riskLevel" onclick="sortTable('riskLevel')">Risk<span class="sort-icon"></span></th>
<th data-col="riskNotes" onclick="sortTable('riskNotes')">Risk Notes<span class="sort-icon"></span></th>
</tr>
</thead>
<tbody id="tableBody"></tbody>
</table>
</div>
</div>

<div class="footer">
Generated by I.D.E.A. 005 - SMS MFA Hunter | Per-Torben S&oslash;rensen
</div>

<script>
const DATA = $userJson;
const POLICY = $policyJson;
const SCAN_DAYS = $SignInScanDays;
let sortCol = 'riskLevel';
let sortDir = 'asc';
let activeMethodFilters = [];
let methodFilterMode = 'or';
let onlySelectedMethods = false;
const riskOrder = {High:0, Medium:1, Low:2, 'N/A':3};

function esc(s) { if (s === null || s === undefined) return ''; const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }
function key(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]/g, ''); }
function riskKey(r) { return r === 'N/A' ? 'na' : key(r); }
function yesBadge(v, warnOnYes) {
    if (v === 'Yes') return '<span class="badge ' + (warnOnYes ? 'badge-warnyes' : 'badge-yes') + '">Yes</span>';
    return '<span class="muted">' + esc(v) + '</span>';
}

function fillSelects() {
    document.querySelectorAll('select[data-field]').forEach(function(sel) {
        const f = sel.dataset.field;
        const vals = Array.from(new Set(DATA.map(function(r) { return r[f]; }).filter(function(v) { return v; }))).sort();
        vals.forEach(function(v) { const o = document.createElement('option'); o.value = v; o.textContent = v; sel.appendChild(o); });
    });
    const tags = Array.from(new Set([].concat.apply([], DATA.map(function(r) { return Array.isArray(r.methodTags) ? r.methodTags : []; })))).sort();
    document.getElementById('methodChips').innerHTML = tags.map(function(t) {
        return '<span class="method-chip" data-method="' + esc(t) + '" onclick="toggleMethod(this)">' + esc(t) + '</span> ';
    }).join('');
    if (SCAN_DAYS === 0) { document.getElementById('filterUsed').disabled = true; }
}

function renderTable() {
    const search = document.getElementById('searchBox').value.toLowerCase();
    const v = function(id) { return document.getElementById(id).value; };
    const fRisk = v('filterRisk'), fType = v('filterType'), fStatus = v('filterStatus');
    const fOnly = v('filterPhoneOnly'), fSms = v('filterSmsPolicy'), fCamp = v('filterCampaign'), fPk = v('filterPasskey');
    const fUsed = v('filterUsed');

    let filtered = DATA.filter(function(r) {
        if (search && !r.displayName.toLowerCase().includes(search) && !r.upn.toLowerCase().includes(search) && !r.phoneNumbers.toLowerCase().includes(search)) return false;
        if (fRisk && r.riskLevel !== fRisk) return false;
        if (fType && r.userType !== fType) return false;
        if (fStatus && r.accountStatus !== fStatus) return false;
        if (fOnly && r.phoneOnly !== fOnly) return false;
        if (fSms && r.smsPolicy !== fSms) return false;
        if (fCamp && r.campaign !== fCamp) return false;
        if (fPk && r.passkeyPolicy !== fPk) return false;
        if (fUsed === 'Yes' && !(r.smsUseCount > 0)) return false;
        if (fUsed === 'No' && r.smsUseCount > 0) return false;
        if (activeMethodFilters.length > 0) {
            const um = Array.isArray(r.methodTags) ? r.methodTags : [];
            if (onlySelectedMethods && !um.every(function(m) { return activeMethodFilters.includes(m); })) return false;
            if (methodFilterMode === 'and') { if (!activeMethodFilters.every(function(m) { return um.includes(m); })) return false; }
            else { if (!activeMethodFilters.some(function(m) { return um.includes(m); })) return false; }
        }
        return true;
    });

    filtered.sort(function(a, b) {
        let va = a[sortCol], vb = b[sortCol];
        if (sortCol === 'riskLevel') { va = riskOrder[va] ?? 9; vb = riskOrder[vb] ?? 9; }
        else if (sortCol === 'smsUseCount') { va = va || 0; vb = vb || 0; }
        else { va = String(va || '').toLowerCase(); vb = String(vb || '').toLowerCase(); }
        if (va < vb) return sortDir === 'asc' ? -1 : 1;
        if (va > vb) return sortDir === 'asc' ? 1 : -1;
        return 0;
    });

    document.getElementById('visibleCount').textContent = filtered.length;
    document.getElementById('totalCount').textContent = DATA.length;

    document.getElementById('tableBody').innerHTML = filtered.map(function(r) {
        const phone = r.phoneNumbers ? esc(r.phoneNumbers) + (r.phoneTypes ? ' <span class="muted">(' + esc(r.phoneTypes) + ')</span>' : '') : '<span class="muted">-</span>';
        const other = r.otherMethods ? esc(r.otherMethods) : '<span class="badge badge-high">None</span>';
        const uses = SCAN_DAYS === 0 ? '<span class="muted">not scanned</span>' : (r.smsUseCount > 0 ? '<span class="badge badge-high">' + r.smsUseCount + '</span> <span class="muted">' + esc(r.lastSmsUse) + '</span>' : '0');
        return '<tr class="risk-' + riskKey(r.riskLevel) + '">' +
            '<td>' + esc(r.displayName) + (r.dataSource !== 'Registration report' ? ' <span class="muted" title="Found via ' + esc(r.dataSource) + ', not the registration report">*</span>' : '') + '</td>' +
            '<td>' + esc(r.upn) + '</td>' +
            '<td><span class="badge badge-' + key(r.userType) + '">' + esc(r.userType) + '</span></td>' +
            '<td><span class="badge badge-' + key(r.accountStatus) + '">' + esc(r.accountStatus) + '</span></td>' +
            '<td>' + phone + '</td>' +
            '<td>' + esc(r.smsSignInState) + '</td>' +
            '<td>' + other + '</td>' +
            '<td>' + yesBadge(r.smsPolicy, true) + '</td>' +
            '<td>' + yesBadge(r.voicePolicy, true) + '</td>' +
            '<td>' + yesBadge(r.passkeyPolicy, false) + '</td>' +
            '<td>' + yesBadge(r.campaign, false) + '</td>' +
            '<td>' + uses + '</td>' +
            '<td><span class="badge badge-' + riskKey(r.riskLevel) + '">' + esc(r.riskLevel) + '</span></td>' +
            '<td>' + esc(r.riskNotes) + '</td></tr>';
    }).join('');

    document.querySelectorAll('#smsTable th').forEach(function(th) { th.classList.remove('sorted-asc', 'sorted-desc'); });
    const th = document.querySelector('#smsTable th[data-col="' + sortCol + '"]');
    if (th) th.classList.add(sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc');
}

function renderPolicy() {
    const host = document.getElementById('policyBody');
    if (POLICY.length === 0) { host.innerHTML = '<div class="muted">Policy posture was not collected.</div>'; return; }
    const areas = [];
    POLICY.forEach(function(p) { if (!areas.includes(p.Area)) areas.push(p.Area); });
    host.innerHTML = areas.map(function(a) {
        const rows = POLICY.filter(function(p) { return p.Area === a; });
        const counts = {};
        rows.forEach(function(r) { counts[r.Status] = (counts[r.Status] || 0) + 1; });
        const chips = ['Fail', 'Warn', 'Pass', 'Info'].filter(function(s) { return counts[s]; })
            .map(function(s) { return '<span class="badge status-' + key(s) + '">' + counts[s] + ' ' + s + '</span>'; }).join(' ');
        return '<div class="policy-area"><div class="policy-area-header" onclick="toggleSection(this)"><span>' + esc(a) + '</span><span>' + chips + '</span></div>' +
            '<div class="policy-area-body"><table class="policy-table"><thead><tr><th style="width:70px">Status</th><th>Check</th><th>Current</th><th>Recommended</th><th>Notes</th></tr></thead><tbody>' +
            rows.map(function(r) {
                return '<tr><td><span class="badge status-' + key(r.Status) + '">' + esc(r.Status) + '</span></td><td>' + esc(r.Check) + '</td><td>' + esc(r.Current) +
                    '</td><td>' + esc(r.Recommended) + '</td><td>' + esc(r.Notes) + '</td></tr>';
            }).join('') + '</tbody></table></div></div>';
    }).join('');
}

function toggleSection(header) { header.classList.toggle('collapsed'); }

function sortTable(col) {
    if (sortCol === col) { sortDir = sortDir === 'asc' ? 'desc' : 'asc'; }
    else { sortCol = col; sortDir = 'asc'; }
    renderTable();
}

function toggleMethod(el) {
    const m = el.dataset.method;
    el.classList.toggle('active');
    if (el.classList.contains('active')) { activeMethodFilters.push(m); }
    else { activeMethodFilters = activeMethodFilters.filter(function(x) { return x !== m; }); }
    updateMethodModeToggle();
    renderTable();
}

function setMethodMode(mode) {
    if (activeMethodFilters.length < 2) return;
    methodFilterMode = mode;
    document.getElementById('modeOr').classList.toggle('active', mode === 'or');
    document.getElementById('modeAnd').classList.toggle('active', mode === 'and');
    renderTable();
}

function updateMethodModeToggle() {
    const allow = activeMethodFilters.length >= 2;
    const o = document.getElementById('modeOr'), a = document.getElementById('modeAnd');
    o.classList.toggle('disabled', !allow);
    a.classList.toggle('disabled', !allow);
    if (!allow) { methodFilterMode = 'or'; o.classList.add('active'); a.classList.remove('active'); }
}

function drawPie(svgId, legendId, segs) {
    const svgEl = document.getElementById(svgId), lgdEl = document.getElementById(legendId);
    const tot = segs.reduce(function(s, d) { return s + d.v; }, 0);
    if (!svgEl || !lgdEl) return;
    if (tot === 0) { lgdEl.innerHTML = '<span class="muted">No data</span>'; return; }
    let ang = -Math.PI / 2, paths = '', lgd = '';
    segs.forEach(function(s) {
        const frac = s.v / tot, end = ang + frac * 2 * Math.PI;
        if (frac >= 0.9999) { paths += '<circle cx="0" cy="0" r="1" fill="' + s.c + '"/>'; }
        else {
            const la = frac > 0.5 ? 1 : 0;
            paths += '<path d="M0,0 L' + Math.cos(ang).toFixed(5) + ',' + Math.sin(ang).toFixed(5) + ' A1,1,0,' + la + ',1,' + Math.cos(end).toFixed(5) + ',' + Math.sin(end).toFixed(5) + ' Z" fill="' + s.c + '" stroke="white" stroke-width="0.03"/>';
        }
        lgd += '<div style="display:flex;align-items:center;gap:5px;font-size:0.78em;line-height:1.5"><span style="width:10px;height:10px;border-radius:2px;background:' + s.c + ';flex-shrink:0;display:inline-block"></span>' + esc(s.l) + ': <strong>' + s.v + '</strong></div>';
        ang = end;
    });
    svgEl.innerHTML = paths;
    lgdEl.innerHTML = lgd;
}

function renderSummary() {
    const enabled = DATA.filter(function(r) { return r.accountStatus === 'Enabled'; });
    const count = function(arr, fn) { return arr.filter(fn).length; };
    const rc = {};
    DATA.forEach(function(r) { rc[r.riskLevel] = (rc[r.riskLevel] || 0) + 1; });
    const pf = {};
    POLICY.forEach(function(p) { pf[p.Status] = (pf[p.Status] || 0) + 1; });

    const cards = [
        { v: DATA.length, l: 'Users with SMS/voice', c: 'info' },
        { v: rc.High || 0, l: 'High', c: 'high' },
        { v: rc.Medium || 0, l: 'Medium', c: 'medium' },
        { v: rc.Low || 0, l: 'Low', c: 'low' },
        { v: count(enabled, function(r) { return r.phoneOnly === 'Yes'; }), l: 'SMS/voice only', c: 'high' },
        { v: count(enabled, function(r) { return r.smsPolicy === 'Yes' || r.voicePolicy === 'Yes'; }), l: 'Allowed by policy', c: 'high' },
        { v: SCAN_DAYS > 0 ? count(enabled, function(r) { return r.smsUseCount > 0; }) : '-', l: SCAN_DAYS > 0 ? 'Used SMS (' + SCAN_DAYS + 'd)' : 'Used SMS (not scanned)', c: 'alert' },
        { v: pf.Fail || 0, l: 'Policy: Fail', c: 'alert' },
        { v: pf.Warn || 0, l: 'Policy: Warn', c: 'high' }
    ];
    document.getElementById('dashboard').innerHTML = cards.map(function(c) {
        return '<div class="card ' + c.c + '"><div class="value">' + c.v + '</div><div class="label">' + esc(c.l) + '</div></div>';
    }).join('');

    const total = enabled.length;
    const only = count(enabled, function(r) { return r.phoneOnly === 'Yes'; });
    const noPhish = count(enabled, function(r) { return r.phoneOnly !== 'Yes' && r.phishResistant !== 'Yes'; });
    const phish = count(enabled, function(r) { return r.phishResistant === 'Yes'; });
    const pct = function(n) { return total > 0 ? (n / total * 100).toFixed(1) : 0; };
    const segs = [
        { n: only, color: '#d32f2f', label: 'SMS/voice only' },
        { n: noPhish, color: '#fbc02d', label: 'SMS/voice + other MFA, no phishing-resistant' },
        { n: phish, color: '#388e3c', label: 'SMS/voice + phishing-resistant (cleanup)' }
    ];
    document.getElementById('barLabel').textContent = 'Fallback options for enabled SMS/voice users (' + total + ')';
    document.getElementById('mfaBar').innerHTML = segs.filter(function(s) { return s.n > 0; }).map(function(s) {
        return '<div class="mfa-bar-segment" style="width:' + pct(s.n) + '%;background:' + s.color + '" title="' + esc(s.label) + ': ' + s.n + '"></div>';
    }).join('');
    document.getElementById('mfaBarLegend').innerHTML = segs.filter(function(s) { return s.n > 0; }).map(function(s) {
        return '<span class="mfa-bar-legend-item"><span class="mfa-bar-legend-swatch" style="background:' + s.color + '"></span>' + esc(s.label) + ': <strong>' + s.n + '</strong> (' + pct(s.n) + '%)</span>';
    }).join('');

    const rColors = { High: '#f57c00', Medium: '#fbc02d', Low: '#0097a7', 'N/A': '#9e9e9e' };
    drawPie('riskPie', 'riskPieLegend', Object.keys(rColors).filter(function(k) { return rc[k]; }).map(function(k) { return { l: k, v: rc[k], c: rColors[k] }; }));

    const pColors = { Fail: '#d32f2f', Warn: '#f57c00', Pass: '#388e3c', Info: '#1565c0' };
    drawPie('policyPie', 'policyPieLegend', Object.keys(pColors).filter(function(k) { return pf[k]; }).map(function(k) { return { l: k, v: pf[k], c: pColors[k] }; }));

    const cc = {};
    DATA.forEach(function(r) { if (r.phoneCountry) { r.phoneCountry.split(/,\s*/).forEach(function(c) { cc[c] = (cc[c] || 0) + 1; }); } });
    const phoneColors = ['#1565c0', '#0097a7', '#6a1b9a', '#2e7d32', '#f57c00', '#c62828', '#455a64', '#ad1457'];
    drawPie('phonePie', 'phonePieLegend', Object.entries(cc).sort(function(a, b) { return b[1] - a[1]; })
        .map(function(e, i) { return { l: e[0], v: e[1], c: phoneColors[i % phoneColors.length] }; }));
}

function resetFilters() {
    document.getElementById('searchBox').value = '';
    document.querySelectorAll('.filters select').forEach(function(s) { s.value = ''; });
    document.getElementById('filterOnlySelectedMethods').checked = false;
    activeMethodFilters = [];
    onlySelectedMethods = false;
    document.querySelectorAll('.method-chip').forEach(function(c) { c.classList.remove('active'); });
    updateMethodModeToggle();
    renderTable();
}

fillSelects();
document.getElementById('searchBox').addEventListener('input', renderTable);
document.querySelectorAll('.filters select').forEach(function(s) { s.addEventListener('change', renderTable); });
document.getElementById('filterOnlySelectedMethods').addEventListener('change', function(e) { onlySelectedMethods = e.target.checked; renderTable(); });
updateMethodModeToggle();
renderPolicy();
renderSummary();
renderTable();
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Log "HTML report exported to: $OutputPath" -Level "SUCCESS"
}

function Open-HtmlReport {
    param([Parameter(Mandatory)][string]$Path)
    $full = (Resolve-Path $Path).Path
    $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    if (-not (Test-Path $edgePath)) { $edgePath = "C:\Program Files\Microsoft\Edge\Application\msedge.exe" }
    if (Test-Path $edgePath) {
        $fileUri = ([System.Uri]$full).AbsoluteUri
        Start-Process -FilePath $edgePath -ArgumentList "--new-window", $fileUri
        Write-Log "Report opened in Edge: $fileUri" -Level "INFO"
    }
    else {
        Write-Log "Edge not found. Open manually: $full" -Level "WARNING"
    }
}

#endregion

# ============================================================================
# Orchestration
# ============================================================================
function Invoke-PolicyCheck {
    param([switch]$Quiet)

    if (-not (Test-GraphReady)) { return $null }

    Write-Log "Starting policy posture check" -Level "INFO"
    $policy = Get-AuthMethodsPolicy
    if (-not $policy) { return $null }

    $findings = @()
    $findings += @(Get-AuthMethodsOverviewFindings -Policy $policy)
    $findings += @(Get-SmsVoicePolicyFindings -Policy $policy)
    $findings += @(Get-RegistrationCampaignFindings -Policy $policy)
    $findings += @(Get-PasskeyProfileFindings -Policy $policy)

    $script:PolicyFindings = $findings
    Write-Log "Policy posture check complete: $($findings.Count) findings" -Level "SUCCESS"
    if (-not $Quiet) {
        Show-PolicyConsole -Findings $findings
        if ($null -ne $script:UserFindings) {
            Show-PolicyConsole -Findings (Get-CrossCheckFindings -Users $script:UserFindings) -Title 'CROSS-CHECKS (cached user hunt)'
        }
    }
    return $findings
}

function Invoke-SmsHunt {
    param([switch]$Quiet)

    if (-not (Test-GraphReady)) { return $null }

    $days = Read-SignInScanDays
    Write-Log "Starting SMS/voice user hunt (sign-in scan: $days day(s))" -Level "INFO"
    $findings = Find-SmsUsers -SignInDays $days
    if ($null -eq $findings) {
        Write-Log "User hunt failed. See errors above." -Level "ERROR"
        return $null
    }

    $script:UserFindings = @($findings)
    if (-not $Quiet) {
        Show-UserConsole -Findings $script:UserFindings
        Show-PolicyConsole -Findings (Get-CrossCheckFindings -Users $script:UserFindings) -Title 'CROSS-CHECKS'
    }
    return $script:UserFindings
}

function Invoke-FullReport {
    if (-not (Test-GraphReady)) { return }

    if ($script:PolicyFindings -or $null -ne $script:UserFindings) {
        $reuse = Read-Host "  Reuse cached results from this session? (Y/N, default=Y)"
        if ($reuse -match '^[Nn]') { Clear-ResultCache }
    }

    $options = Show-OutputMenu
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

    $policy = if ($script:PolicyFindings) { $script:PolicyFindings } else { Invoke-PolicyCheck -Quiet }
    $users  = if ($null -ne $script:UserFindings) { $script:UserFindings } else { Invoke-SmsHunt -Quiet }

    if ($null -eq $policy -and $null -eq $users) {
        Write-Log "Nothing to report: both the policy check and the user hunt failed." -Level "ERROR"
        return
    }

    $cross = if ($null -ne $users) { @(Get-CrossCheckFindings -Users $users) } else { @() }
    $allPolicy = @($policy) + $cross | Where-Object { $_ }

    Show-PolicyConsole -Findings $allPolicy
    Show-UserConsole -Findings $users

    $exported = @()
    if ($options.Csv) {
        $exported += Export-SmsCsv -PolicyFindings $allPolicy -UserFindings $users -Timestamp $timestamp
    }
    if ($options.Html) {
        $tenantName = 'Unknown'
        try {
            $org = Invoke-GraphGet -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName'
            if ($org.value -and $org.value[0].displayName) { $tenantName = $org.value[0].displayName }
        }
        catch { $tenantName = (Get-MgContext).TenantId }

        $dir = ".\exports"
        if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $safeTenant = $tenantName -replace '[^\w\-]', '_'
        $htmlPath = Join-Path $dir "SmsMfaReport-$safeTenant-$timestamp.html"
        New-SmsHtmlReport -PolicyFindings $allPolicy -UserFindings $users -OutputPath $htmlPath -TenantName $tenantName -SignInScanDays $script:SignInScanDays
        if (Test-Path $htmlPath) {
            $exported += $htmlPath
            Open-HtmlReport -Path $htmlPath
        }
        else {
            Write-Log "HTML report was not written: $htmlPath" -Level "ERROR"
        }
    }

    if ($exported.Count -gt 0) {
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "EXPORTED FILES:" -ForegroundColor Cyan
        foreach ($p in $exported) { Write-Host "  $((Resolve-Path $p).Path)" -ForegroundColor White }
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "  DATA PRIVACY NOTICE: these files contain personal data (names, UPNs, phone" -ForegroundColor Yellow
        Write-Host "  numbers, sign-in activity). Store securely, share only with authorised" -ForegroundColor Yellow
        Write-Host "  recipients, and delete when no longer needed." -ForegroundColor Yellow
        Write-Host ("=" * 80) -ForegroundColor Cyan
    }
}

# ============================================================================
# Main loop
# ============================================================================
try {
    $running = $true
    while ($running) {
        Show-MainMenu
        $choice = "$(Read-Host '  Enter choice')".Trim().ToUpper()

        switch ($choice) {
            '1' { Connect-ReportGraph;              Read-Host "  Press Enter to return to the menu" | Out-Null }
            '2' { Invoke-PolicyCheck | Out-Null;    Read-Host "  Press Enter to return to the menu" | Out-Null }
            '3' { Invoke-SmsHunt | Out-Null;        Read-Host "  Press Enter to return to the menu" | Out-Null }
            '4' { Invoke-FullReport;                Read-Host "  Press Enter to return to the menu" | Out-Null }
            'C' { Clear-ResultCache; Write-Host "  Cache cleared." -ForegroundColor Gray; Start-Sleep -Seconds 1 }
            'Q' { $running = $false }
            default {
                Write-Host "  Invalid choice." -ForegroundColor Yellow
                Start-Sleep -Seconds 1
            }
        }
    }
}
finally {
    # Only tear down a connection this script opened.
    if ($script:GraphConnectedByScript) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    if ($DiagnosticMode) {
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    }
}
