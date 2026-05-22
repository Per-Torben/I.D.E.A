<#
.SYNOPSIS
    Automated creation and configuration of break-glass emergency access accounts in Microsoft Entra ID

.DESCRIPTION
    This PowerShell script automates the complete setup of break-glass emergency access accounts 
    in Microsoft Entra ID. Break-glass accounts are critical backup administrator 
    accounts used for emergency access when normal administrative access is compromised or unavailable.

    Key Features:
    - Interactive menu-driven configuration for flexible account management
    - Detects existing break-glass accounts or creates new ones (with manual selection option)
    - Selective configuration: FIDO2 keys, CA exclusions, GA role, RMAU protection
    - Configurable settings for account count, FIDO2 keys per account, and account prefix
    - Password complexity validation with configurable requirements (24+ chars)
    - Registers multiple FIDO2 security keys per account for passwordless authentication
    - Automatically excludes accounts from Conditional Access policies (All users/All/Specific)
    - Assigns Global Administrator role when needed
    - Adds accounts to Restricted Management Administrative Units (RMAU) for protection
    - Detects RMAU membership and warns when it may block FIDO2 detection
    - Comprehensive logging with automatic cleanup and retention policies
    - Implements verification and error handling with retry logic
    - Interactive prompts for physical FIDO2 key management
    - Returns to menu after each configuration for iterative setup
    - Auto-installs required Microsoft Graph Beta modules (no manual installation needed)

    Security Benefits:
    - Provides reliable emergency access bypassing Conditional Access restrictions
    - Uses multiple authentication factors (password + FIDO2 keys)
    - RMAU protection prevents unauthorized account modifications
    - Follows Microsoft's recommended break-glass account practices
    - Prevents potential lockout scenarios in tenant security configurations

.EXAMPLE
    .\Create-BreakGlassAccounts.ps1
    
    Runs the interactive break-glass account setup with menu-driven configuration.
    Configure account count, FIDO2 keys, and other settings through the menus.

.NOTES
    Prerequisites:
    - Microsoft Graph PowerShell SDK (Beta modules - auto-installed if missing):
      * Microsoft.Graph.Authentication
      * Microsoft.Graph.Beta.Users
      * Microsoft.Graph.Beta.Identity.DirectoryManagement
      * Microsoft.Graph.Beta.Identity.SignIns
    - DSInternals.Passkeys module (auto-installed)
    - Physical FIDO2 security keys for registration
    - Global Administrator permissions in the tenant
    - Required Graph API permissions (automatically requested)
    
    Note: All required modules are automatically installed to CurrentUser scope.
    No manual installation or administrative rights needed for module installation.

    Author: Per-Torben Sørensen with contributions from Github Copilot
    Version: 2.0
    Last Updated: January 6, 2026

.LINK
    https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access

#>

[CmdletBinding()]
param()

# Required Graph modules (Beta versions for FIDO2 and advanced features)
$requiredGraphModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Beta.Users',
    'Microsoft.Graph.Beta.Identity.DirectoryManagement',
    'Microsoft.Graph.Beta.Identity.SignIns'
)

# Auto-install missing Graph modules
foreach ($module in $requiredGraphModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing module: $module" -ForegroundColor Yellow
        Install-Module $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "✓ Installed $module" -ForegroundColor Green
    }
}

# Configuration settings (can be modified via settings menu)
$Config = @{
    AccountCount = 2
    KeysPerAccount = 2
    AccountPrefix = "breakglass-ga"
    RoleName = "Global Administrator"
    RMAUConfig = @{
        DisplayName = "Break-Glass Accounts Protection"
        Description = "Restricted Management Administrative Unit protecting break-glass emergency access accounts from unauthorized modification"
    }
    PasswordComplexity = @{
        MinLength = 24
        RequireUppercase = $true
        RequireLowercase = $true
        RequireNumbers = $true
        RequireSpecialChars = $true
    }
    LoggingConfig = @{
        LogDirectory = ".\Logs"
        LogFileName = "BreakGlass-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"
        MaxLogSizeMB = 10
        RetainDays = 30
    }
}

# Define required modules with their minimum versions
$RequiredModules = @(
    @{ Name = "DSInternals.Passkeys"; MinimumVersion = "1.0.0" }
)

#region Logging Functions
function Initialize-Logging {
    # Create logs directory if it doesn't exist
    if (-not (Test-Path $Config.LoggingConfig.LogDirectory)) {
        New-Item -Path $Config.LoggingConfig.LogDirectory -ItemType Directory -Force | Out-Null
    }
    
    # Clean up old log files
    $cutoffDate = (Get-Date).AddDays(-$Config.LoggingConfig.RetainDays)
    Get-ChildItem -Path $Config.LoggingConfig.LogDirectory -Filter "BreakGlass-*.log" | 
        Where-Object { $_.CreationTime -lt $cutoffDate } |
        Remove-Item -Force
    
    $script:LogFilePath = Join-Path $Config.LoggingConfig.LogDirectory $Config.LoggingConfig.LogFileName
    Write-Log "Logging initialized. Log file: $script:LogFilePath" -Level Info
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success')]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Console output with colors
    switch ($Level) {
        'Info' { Write-Host $logEntry -ForegroundColor Cyan }
        'Warning' { Write-Warning $logEntry }
        'Error' { Write-Error $logEntry }
        'Success' { Write-Host $logEntry -ForegroundColor Green }
    }
    
    # File logging (if log file path is set)
    if ($script:LogFilePath) {
        try {
            Add-Content -Path $script:LogFilePath -Value $logEntry -ErrorAction SilentlyContinue
        }
        catch {
            # Silently fail if logging fails to prevent script interruption
        }
    }
}

function Show-Progress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    Write-Log "Progress: $Activity - $Status ($PercentComplete%)" -Level Info
}
#endregion

#region Security and Validation Functions
function Test-PasswordComplexity {
    param(
        [SecureString]$Password,
        [hashtable]$Requirements
    )
    
    # Convert SecureString to plain text for validation
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try {
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        
        $checks = @{
            Length = $plainPassword.Length -ge $Requirements.MinLength
            Uppercase = (-not $Requirements.RequireUppercase) -or ($plainPassword -cmatch '[A-Z]')
            Lowercase = (-not $Requirements.RequireLowercase) -or ($plainPassword -cmatch '[a-z]')
            Numbers = (-not $Requirements.RequireNumbers) -or ($plainPassword -match '[0-9]')
            SpecialChars = (-not $Requirements.RequireSpecialChars) -or ($plainPassword -match '[^a-zA-Z0-9]')
        }
        
        return $checks
    }
    finally {
        # Clear sensitive data from memory
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}

function Test-TenantDomain {
    try {
        Write-Log "Validating tenant domain..." -Level Info
        $domain = (Get-MgBetaDomain | Where-Object {$_.Id -like "*.onmicrosoft.com" -and $_.Id -notlike "*.mail.onmicrosoft.com"}).Id
        if (-not $domain) {
            throw "Unable to determine tenant domain"
        }
        Write-Log "Tenant domain validated: $domain" -Level Success
        return $domain
    }
    catch {
        Write-Log "Failed to validate tenant domain: $_" -Level Error
        throw
    }
}

function Get-SecurePassword {
    do {
        Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  PASSWORD CONFIGURATION" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Password Requirements:" -ForegroundColor Yellow
        Write-Host "- Minimum $($Config.PasswordComplexity.MinLength) characters" -ForegroundColor White
        if ($Config.PasswordComplexity.RequireUppercase) { Write-Host "- At least one uppercase letter" -ForegroundColor White }
        if ($Config.PasswordComplexity.RequireLowercase) { Write-Host "- At least one lowercase letter" -ForegroundColor White }
        if ($Config.PasswordComplexity.RequireNumbers) { Write-Host "- At least one number" -ForegroundColor White }
        if ($Config.PasswordComplexity.RequireSpecialChars) { Write-Host "- At least one special character" -ForegroundColor White }
        Write-Host ""
        Write-Host "⚠ IMPORTANT: Type the password manually (pasting may not work in secure prompts)" -ForegroundColor Yellow
        Write-Host ""
        
        try {
            $pwd = Read-Host -AsSecureString "Enter strong passphrase for break-glass accounts"
            
            # Check if password is empty
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd)
            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            
            if ([string]::IsNullOrWhiteSpace($plainPassword)) {
                Write-Host "`n✗ Password cannot be empty. Please try again.`n" -ForegroundColor Red
                Write-Log "Password entry was empty" -Level Warning
                continue
            }
            
            $validation = Test-PasswordComplexity -Password $pwd -Requirements $Config.PasswordComplexity
            
            if ($validation.Values -contains $false) {
                Write-Host "`n✗ Password does not meet complexity requirements:" -ForegroundColor Red
                $validation.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object {
                    Write-Host "  - Failed: $($_.Key)" -ForegroundColor Red
                    Write-Log "  - Failed: $($_.Key)" -Level Warning
                }
                Write-Host "`nPlease try again with a stronger password.`n" -ForegroundColor Yellow
            }
            else {
                Write-Host "`n✓ Password meets all complexity requirements" -ForegroundColor Green
                Write-Log "Password meets all complexity requirements" -Level Success
            }
        }
        catch {
            Write-Host "`n✗ Error processing password: $_" -ForegroundColor Red
            Write-Log "Error processing password: $_" -Level Error
            Write-Host "Please try again.`n" -ForegroundColor Yellow
            continue
        }
    } while ($validation.Values -contains $false)
    
    return $pwd
}
#endregion

#region Helper Functions
# Function to ensure a module is installed and imported safely
function Ensure-Module {
    param (
        [string]$ModuleName
    )
    
    # Check if module is available
    $installedModule = Get-Module -Name $ModuleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    
    if (-not $installedModule) {
        Write-Log "Installing module: $ModuleName" -Level Info
        try {
            Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -ErrorAction Stop
            Write-Log "Successfully installed module: $ModuleName" -Level Success
        }
        catch {
            Write-Log "Failed to install module $ModuleName`: $_" -Level Error
            throw
        }
    }
    
    # Import the module
    try {
        Import-Module -Name $ModuleName -Force -ErrorAction Stop
        Write-Log "Successfully imported module: $ModuleName" -Level Success
    }
    catch {
        Write-Log "Failed to import module $ModuleName`: $_" -Level Error
        throw
    }
}

#region Break-Glass User Management Functions
function New-BreakGlassUsers {
    param (
        [SecureString]$Password,
        [int]$Count = 2
    )
    
    Write-Log "Creating $Count break-glass users..." -Level Info
    $upn = Test-TenantDomain
    $createdUsers = @()
    
    # Convert SecureString to plain text for user creation
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try {
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        
        1..$Count | ForEach-Object {
            try {
                $userParams = @{
                    AccountEnabled = $true
                    DisplayName = "BreakGlass GA$_"
                    UserPrincipalName = "$($Config.AccountPrefix)$_@$upn"
                    MailNickname = "$($Config.AccountPrefix.Replace('-',''))$_"
                    PasswordProfile = @{ password = $plainPassword }
                }
                
                $user = New-MgBetaUser @userParams
                $createdUsers += $user
                Write-Log "Created user: $($user.UserPrincipalName)" -Level Success
            }
            catch {
                Write-Log "Failed to create user $_`: $_" -Level Error
                throw
            }
        }
    }
    finally {
        # Clear sensitive data from memory
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
    
    return $createdUsers
}

function Add-ToRestrictedAdministrativeUnit {
    Write-Log "Adding break-glass accounts to Restricted Management Administrative Unit..." -Level Info
    
    try {
        # Check if RMAU already exists
        $existingRMAU = Get-MgBetaDirectoryAdministrativeUnit -Filter "displayName eq '$($Config.RMAUConfig.DisplayName)'" -ErrorAction SilentlyContinue
        
        if ($existingRMAU) {
            Write-Log "Found existing RMAU: $($existingRMAU.DisplayName)" -Level Info
            $rmau = $existingRMAU
        }
        else {
            # Create new RMAU
            Write-Log "Creating new Restricted Management Administrative Unit..." -Level Info
            $rmauParams = @{
                DisplayName = $Config.RMAUConfig.DisplayName
                Description = $Config.RMAUConfig.Description
                IsMemberManagementRestricted = $true
                Visibility = "HiddenMembership"
            }
            
            $rmau = New-MgBetaDirectoryAdministrativeUnit -BodyParameter $rmauParams
            Write-Log "Created RMAU: $($rmau.DisplayName) (ID: $($rmau.Id))" -Level Success
        }
        
        # Add each break-glass account to the RMAU
        $breakGlassUsers = Get-MgBetaUser -Filter "startswith(userPrincipalName,'$($Config.AccountPrefix)')" -ErrorAction Stop
        
        foreach ($user in $breakGlassUsers) {
            try {
                # Check if already a member
                $existingMembers = Get-MgBetaDirectoryAdministrativeUnitMember -AdministrativeUnitId $rmau.Id -ErrorAction SilentlyContinue
                if ($existingMembers.Id -contains $user.Id) {
                    Write-Log "$($user.UserPrincipalName) is already a member of the RMAU" -Level Info
                    continue
                }
                
                # Add user to RMAU
                $memberParams = @{
                    "@odata.id" = "https://graph.microsoft.com/beta/users/$($user.Id)"
                }
                New-MgBetaDirectoryAdministrativeUnitMemberByRef -AdministrativeUnitId $rmau.Id -BodyParameter $memberParams
                Write-Log "Added $($user.UserPrincipalName) to RMAU" -Level Success
            }
            catch {
                Write-Log "Failed to add $($user.UserPrincipalName) to RMAU: $_" -Level Error
                throw
            }
        }
        
        Write-Host ""
        Write-Host "⚠ WARNING: Accounts are now protected by RMAU" -ForegroundColor Yellow
        Write-Host "Only Global Administrators can modify these accounts" -ForegroundColor Yellow
        Write-Host "Future script operations may require GA permissions" -ForegroundColor Yellow
        Write-Host ""
        
    }
    catch {
        Write-Log "Failed to configure RMAU protection: $_" -Level Error
        throw
    }
}

function Add-GlobalAdminRole {
    Write-Log "Adding Global Administrator role to break-glass accounts..." -Level Info
    
    try {
        $gaRole = (Get-MgBetaDirectoryRole -Filter "displayName eq '$($Config.RoleName)'" -ErrorAction SilentlyContinue).Id
        if (-not $gaRole) {
            throw "Could not find Global Administrator role"
        }
        
        $breakGlassUsers = Get-MgBetaUser -Filter "startswith(userPrincipalName,'$($Config.AccountPrefix)')"
        
        foreach ($user in $breakGlassUsers) {
            try {
                New-MgBetaDirectoryRoleMemberByRef -DirectoryRoleId $gaRole -BodyParameter @{"@odata.id" = "https://graph.microsoft.com/beta/directoryObjects/$($user.Id)"}
                Write-Log "Assigned Global Administrator role to $($user.UserPrincipalName)" -Level Success
            }
            catch {
                Write-Log "Failed to assign role to $($user.UserPrincipalName): $_" -Level Error
                throw
            }
        }
    }
    catch {
        Write-Log "Failed to add Global Administrator role: $_" -Level Error
        throw
    }
}

function Get-CAPolicySelection {
    param (
        [array]$AllPolicies
    )
    
    # Categorize policies
    $allUsersPolicies = @($AllPolicies | Where-Object { 
        $_.Conditions.Users.IncludeUsers -contains "All" 
    })
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     Conditional Access Policy Selection                     ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Found $($AllPolicies.Count) total CA policies" -ForegroundColor White
    Write-Host "  → $($allUsersPolicies.Count) policies scoped to 'All users'" -ForegroundColor Yellow
    Write-Host ""
    
    if ($allUsersPolicies.Count -gt 0) {
        Write-Host "Policies scoped to 'All users':" -ForegroundColor Yellow
        for ($i = 0; $i -lt $allUsersPolicies.Count; $i++) {
            $p = $allUsersPolicies[$i]
            $state = if ($p.State -eq "enabled") { "✓" } elseif ($p.State -eq "enabledForReportingButNotEnforced") { "⚠" } else { "✗" }
            Write-Host "  $($i + 1). [$state] $($p.DisplayName)" -ForegroundColor White
        }
        Write-Host ""
    }
    
    Write-Host "Select which policies to update:" -ForegroundColor Cyan
    Write-Host "  [1] Only 'All users' policies ($($allUsersPolicies.Count) policies)" -ForegroundColor Green
    Write-Host "  [2] ALL policies ($($AllPolicies.Count) policies)" -ForegroundColor Yellow
    Write-Host "  [3] Select specific policies from list" -ForegroundColor White
    Write-Host "  [Q] Cancel" -ForegroundColor Red
    Write-Host ""
    
    do {
        $selection = Read-Host "Enter your choice (1-3 or Q)"
        $selection = $selection.ToUpper().Trim()
        
        switch ($selection) {
            '1' {
                Write-Log "User selected 'All users' scoped policies only ($($allUsersPolicies.Count) policies)" -Level Info
                return $allUsersPolicies
            }
            '2' {
                Write-Host "`n⚠ WARNING: This will update ALL $($AllPolicies.Count) CA policies" -ForegroundColor Yellow
                $confirm = Read-Host "Are you sure? (Y/N)"
                if ($confirm -match '^[Yy]') {
                    Write-Log "User selected ALL policies ($($AllPolicies.Count) policies)" -Level Info
                    return $AllPolicies
                }
                else {
                    Write-Host "Cancelled. Please select again.`n" -ForegroundColor Yellow
                    continue
                }
            }
            '3' {
                return Get-SpecificPolicies -AllPolicies $AllPolicies
            }
            'Q' {
                Write-Log "User cancelled CA policy selection" -Level Info
                return $null
            }
            default {
                Write-Host "Invalid selection. Please enter 1, 2, 3, or Q`n" -ForegroundColor Red
            }
        }
    } while ($true)
}

function Get-SpecificPolicies {
    param (
        [array]$AllPolicies
    )
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║          Select Specific CA Policies                        ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Display all policies with numbers
    for ($i = 0; $i -lt $AllPolicies.Count; $i++) {
        $p = $AllPolicies[$i]
        $state = if ($p.State -eq "enabled") { "✓" } elseif ($p.State -eq "enabledForReportingButNotEnforced") { "⚠" } else { "✗" }
        $scope = if ($p.Conditions.Users.IncludeUsers -contains "All") { "[All Users]" } else { "" }
        Write-Host ("{0,3}. [{1}] {2} {3}" -f ($i + 1), $state, $p.DisplayName, $scope) -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host "Enter policy numbers separated by commas (e.g., 1,3,5-8,12)" -ForegroundColor Yellow
    Write-Host "Or enter 'A' for all, 'Q' to cancel" -ForegroundColor Gray
    Write-Host ""
    
    do {
        $input = Read-Host "Policy selection"
        $input = $input.ToUpper().Trim()
        
        if ($input -eq 'Q') {
            Write-Log "User cancelled specific policy selection" -Level Info
            return $null
        }
        
        if ($input -eq 'A') {
            Write-Log "User selected all policies via specific selection menu" -Level Info
            return $AllPolicies
        }
        
        # Parse selection
        try {
            $selectedIndices = @()
            $parts = $input -split ','
            
            foreach ($part in $parts) {
                $part = $part.Trim()
                if ($part -match '^(\d+)-(\d+)$') {
                    # Range like 5-8
                    $start = [int]$matches[1]
                    $end = [int]$matches[2]
                    if ($start -ge 1 -and $end -le $AllPolicies.Count -and $start -le $end) {
                        $selectedIndices += ($start..$end)
                    }
                    else {
                        throw "Invalid range: $part"
                    }
                }
                elseif ($part -match '^\d+$') {
                    # Single number
                    $num = [int]$part
                    if ($num -ge 1 -and $num -le $AllPolicies.Count) {
                        $selectedIndices += $num
                    }
                    else {
                        throw "Invalid policy number: $num"
                    }
                }
                else {
                    throw "Invalid format: $part"
                }
            }
            
            $selectedIndices = $selectedIndices | Select-Object -Unique | Sort-Object
            $selectedPolicies = @($selectedIndices | ForEach-Object { $AllPolicies[$_ - 1] })
            
            Write-Host "`nYou selected $($selectedPolicies.Count) policies:" -ForegroundColor Green
            $selectedPolicies | ForEach-Object { Write-Host "  • $($_.DisplayName)" -ForegroundColor White }
            Write-Host ""
            $confirm = Read-Host "Proceed with these policies? (Y/N)"
            
            if ($confirm -match '^[Yy]') {
                Write-Log "User selected $($selectedPolicies.Count) specific policies" -Level Info
                return $selectedPolicies
            }
            else {
                Write-Host "`nPlease select again.`n" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "`n✗ Error: $_" -ForegroundColor Red
            Write-Host "Please try again.`n" -ForegroundColor Yellow
        }
    } while ($true)
}

function Remove-FromConditionalAccessPolicies {
    param (
        [object[]]$BreakGlassAccounts
    )
    Write-Log "Excluding break-glass accounts from Conditional Access policies..." -Level Info
    
    try {
        # Use the accounts that were passed in (supports both prefix-based and manually selected accounts)
        $bg = $BreakGlassAccounts
        if (-not $bg -or $bg.Count -eq 0) {
            Write-Log "No break-glass accounts provided to exclude from CA policies" -Level Error
            Write-Host "`n✗ No break-glass accounts available. Cannot update CA policies." -ForegroundColor Red
            return
        }
        Write-Log "Operating on $($bg.Count) break-glass account(s): $(($bg | ForEach-Object { $_.UserPrincipalName }) -join ', ')" -Level Info
        $allPolicies = Get-MgBetaIdentityConditionalAccessPolicy -All
        
        Write-Log "Found $($allPolicies.Count) Conditional Access policies" -Level Info
        
        # Let user select which policies to update
        $policiesToUpdate = Get-CAPolicySelection -AllPolicies $allPolicies
        
        if ($null -eq $policiesToUpdate -or $policiesToUpdate.Count -eq 0) {
            Write-Log "No policies selected or operation cancelled" -Level Warning
            Write-Host "`nNo policies will be updated." -ForegroundColor Yellow
            return
        }
        
        Write-Log "Analyzing $($policiesToUpdate.Count) selected policies for $($bg.Count) break-glass accounts..." -Level Info
        
        # Check which policies need updating and track missing accounts
        $policiesToActuallyUpdate = @()
        $alreadyExcluded = @()
        $partiallyExcluded = @()
        
        foreach ($policy in $policiesToUpdate) {
            $missingAccounts = @()
            
            foreach ($bgAccount in $bg) {
                if (-not $policy.Conditions.Users.ExcludeUsers -or $policy.Conditions.Users.ExcludeUsers -notcontains $bgAccount.Id) {
                    $missingAccounts += $bgAccount
                }
            }
            
            if ($missingAccounts.Count -eq 0) {
                # All accounts already excluded
                $alreadyExcluded += $policy
            }
            elseif ($missingAccounts.Count -eq $bg.Count) {
                # No accounts excluded (completely missing)
                $policiesToActuallyUpdate += [PSCustomObject]@{
                    Policy = $policy
                    MissingAccounts = $missingAccounts
                    Status = "Missing all accounts"
                }
            }
            else {
                # Some but not all accounts excluded (partial)
                $policiesToActuallyUpdate += [PSCustomObject]@{
                    Policy = $policy
                    MissingAccounts = $missingAccounts
                    Status = "Missing $($missingAccounts.Count) of $($bg.Count) accounts"
                }
                $partiallyExcluded += [PSCustomObject]@{
                    Policy = $policy
                    MissingAccounts = $missingAccounts
                }
            }
        }
        
        # Show status of policies
        if ($alreadyExcluded.Count -gt 0) {
            Write-Host "`n✓ Already excluded from $($alreadyExcluded.Count) policies (skipping):" -ForegroundColor Gray
            foreach ($p in $alreadyExcluded) {
                Write-Host "  • $($p.DisplayName)" -ForegroundColor Gray
            }
            Write-Log "Skipped $($alreadyExcluded.Count) policies where all break-glass accounts already excluded" -Level Info
        }
        
        if ($partiallyExcluded.Count -gt 0) {
            Write-Host "`n⚠ Partial exclusions detected ($($partiallyExcluded.Count) policies):" -ForegroundColor Yellow
            foreach ($item in $partiallyExcluded) {
                $missingNames = $item.MissingAccounts | ForEach-Object { ($_.UserPrincipalName -split '@')[0] }
                Write-Host "  • $($item.Policy.DisplayName)" -ForegroundColor Yellow
                Write-Host "    Missing: $($missingNames -join ', ')" -ForegroundColor Gray
            }
            Write-Log "Found $($partiallyExcluded.Count) policies with partial exclusions" -Level Warning
        }
        
        if ($policiesToActuallyUpdate.Count -eq 0) {
            Write-Host "`n✓ All selected policies already have all break-glass accounts excluded. No updates needed." -ForegroundColor Green
            Write-Log "No policies required updates" -Level Info
            return
        }
        
        Write-Host "`nUpdating $($policiesToActuallyUpdate.Count) policies..." -ForegroundColor Cyan
        Write-Log "Updating $($policiesToActuallyUpdate.Count) policies that need exclusions" -Level Info
        
        $successCount = 0
        $failCount = 0
        
        foreach ($item in $policiesToActuallyUpdate) {
            $policy = $item.Policy
            $statusMsg = $item.Status
            
            try {
                $exclude = @($policy.Conditions.Users.ExcludeUsers) + ($bg.Id)
                $uniqueExcludes = $exclude | Select-Object -Unique | Where-Object { $_ -ne $null }
                
                if ($WhatIf) {
                    Write-Host "  WHATIF: $($policy.DisplayName) [$statusMsg]" -ForegroundColor Cyan
                    Write-Log "WHATIF: Would exclude break-glass accounts from policy '$($policy.DisplayName)' [$statusMsg]" -Level Info
                    $successCount++
                }
                else {
                    # Get full policy object to preserve existing conditions
                    $fullPolicy = Get-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id
                    
                    # Build an explicit hashtable for the users conditions - SDK proxy objects do not
                    # serialize mutations reliably, so we construct the body from scratch.
                    $usersBody = @{
                        includeUsers  = @($fullPolicy.Conditions.Users.IncludeUsers  | Where-Object { $_ })
                        excludeUsers  = @($uniqueExcludes)
                        includeGroups = @($fullPolicy.Conditions.Users.IncludeGroups | Where-Object { $_ })
                        excludeGroups = @($fullPolicy.Conditions.Users.ExcludeGroups | Where-Object { $_ })
                        includeRoles  = @($fullPolicy.Conditions.Users.IncludeRoles  | Where-Object { $_ })
                        excludeRoles  = @($fullPolicy.Conditions.Users.ExcludeRoles  | Where-Object { $_ })
                    }
                    # Include GuestsOrExternalUsers if present
                    if ($fullPolicy.Conditions.Users.IncludeGuestsOrExternalUsers) {
                        $usersBody['includeGuestsOrExternalUsers'] = $fullPolicy.Conditions.Users.IncludeGuestsOrExternalUsers
                    }
                    if ($fullPolicy.Conditions.Users.ExcludeGuestsOrExternalUsers) {
                        $usersBody['excludeGuestsOrExternalUsers'] = $fullPolicy.Conditions.Users.ExcludeGuestsOrExternalUsers
                    }

                    Update-MgBetaIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -BodyParameter @{
                        conditions = @{ users = $usersBody }
                    } -ErrorAction Stop

                    $addedCount = $item.MissingAccounts.Count
                    Write-Host "  ✓ $($policy.DisplayName) [Added $addedCount account(s)]" -ForegroundColor Green
                    Write-Log "Updated policy: $($policy.DisplayName) - Added $addedCount break-glass account(s)" -Level Success
                    $successCount++
                }
            }
            catch {
                Write-Host "  ✗ $($policy.DisplayName): $_" -ForegroundColor Red
                Write-Log "Failed to update policy '$($policy.DisplayName)': $_" -Level Error
                $failCount++
            }
        }
        
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "UPDATE SUMMARY:" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  ✓ Updated: $successCount" -ForegroundColor Green
        Write-Host "  • Already excluded: $($alreadyExcluded.Count)" -ForegroundColor Gray
        if ($failCount -gt 0) {
            Write-Host "  ✗ Failed: $failCount" -ForegroundColor Red
        }
        Write-Host "  Total processed: $($policiesToUpdate.Count)" -ForegroundColor White
        Write-Log "CA policy update completed: $successCount updated, $($alreadyExcluded.Count) skipped, $failCount failed" -Level Info

        # --- Final state verification across all 'All users' policies ---
        # Graph replication can lag; retry up to 3 times with 2-second intervals.
        Write-Host ""
        Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
        Write-Host "VERIFICATION — Current exclusion state:" -ForegroundColor Cyan
        Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
        Write-Host "  Accounts checked: $(($bg | ForEach-Object { ($_.UserPrincipalName -split '@')[0] }) -join ', ')" -ForegroundColor Gray

        $maxRetries = 3; $retryDelaySec = 2
        $verifyAllPolicies = @()
        $pendingPolicyIds = @($policiesToActuallyUpdate | ForEach-Object { $_.Policy.Id })
        $confirmedResults = @{}  # policyId -> $true (ok) / $false (still missing)

        for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
            Start-Sleep -Seconds $retryDelaySec
            $fresh = @(Get-MgBetaIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
                Where-Object { $_.Conditions.Users.IncludeUsers -contains "All" })
            if ($attempt -eq 1) { $verifyAllPolicies = $fresh }  # keep for final display

            $stillPending = @()
            foreach ($id in $pendingPolicyIds) {
                $vp = $fresh | Where-Object { $_.Id -eq $id }
                if (-not $vp) { continue }
                $notExcluded = @($bg | Where-Object { $vp.Conditions.Users.ExcludeUsers -notcontains $_.Id })
                if ($notExcluded.Count -eq 0) {
                    $confirmedResults[$id] = $true
                } else {
                    $stillPending += $id
                }
            }
            $pendingPolicyIds = $stillPending
            if ($pendingPolicyIds.Count -eq 0) { break }
            if ($attempt -lt $maxRetries) {
                Write-Host "  ↻ $($pendingPolicyIds.Count) policy/policies not yet replicated, retrying (attempt $attempt/$maxRetries)..." -ForegroundColor DarkYellow
            }
        }
        # Mark any still-pending after all retries as failed
        foreach ($id in $pendingPolicyIds) { $confirmedResults[$id] = $false }

        # Re-fetch latest state for display
        $verifyAllPolicies = @(Get-MgBetaIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
            Where-Object { $_.Conditions.Users.IncludeUsers -contains "All" })

        $verifyOk = 0; $verifyFail = 0
        foreach ($vp in $verifyAllPolicies) {
            $notExcluded = @($bg | Where-Object { $vp.Conditions.Users.ExcludeUsers -notcontains $_.Id })
            if ($notExcluded.Count -eq 0) {
                Write-Host ("  ✓ {0}" -f $vp.DisplayName) -ForegroundColor Green
                $verifyOk++
            } else {
                $missing = ($notExcluded | ForEach-Object { ($_.UserPrincipalName -split '@')[0] }) -join ', '
                Write-Host ("  ✗ {0}  [not excluded: {1}]" -f $vp.DisplayName, $missing) -ForegroundColor Red
                $verifyFail++
            }
        }

        Write-Host ""
        if ($verifyFail -eq 0) {
            Write-Host "  ✓ All $($verifyAllPolicies.Count) 'All users' $(if($verifyAllPolicies.Count -eq 1){'policy'}else{'policies'}) confirmed — accounts are fully excluded." -ForegroundColor Green
            Write-Log "Final verification passed: all $($verifyAllPolicies.Count) 'All users' policies exclude the break-glass accounts" -Level Success
        } else {
            Write-Host "  ⚠ $verifyFail of $($verifyAllPolicies.Count) $(if($verifyAllPolicies.Count -eq 1){'policy'}else{'policies'}) still missing exclusions after $maxRetries retries — Graph replication may still be in progress." -ForegroundColor Yellow
            Write-Log "Final verification: $verifyFail policy/policies still missing break-glass account exclusions after $maxRetries retries" -Level Warning
        }
        Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    }
    catch {
        Write-Log "Failed to update Conditional Access policies: $_" -Level Error
        throw
    }
}
#endregion

#region FIDO2 Registration Workflow
function Invoke-LocalPasskeyRegistration {
    param (
        [string]$UPN,
        [string]$DisplayName
    )
    try {
        Write-Log "Generating FIDO2 options for $UPN with display name '$DisplayName'" -Level Info
        $FIDO2Options = Get-PasskeyRegistrationOptions -UserId $UPN -ErrorAction Stop
        $FIDO2 = New-Passkey -Options $FIDO2Options -ErrorAction Stop
        Write-Log "Successfully created passkey for $UPN" -Level Success
        return $FIDO2
    } catch {
        Write-Log "Failed to register the passkey for $UPN`: $_" -Level Error
        throw
    }
}

function Register-FIDO2KeyInEntraID {
    param (
        [string]$UPN,
        [string]$DisplayName,
        [DSInternals.Win32.WebAuthn.AttestationPublicKeyCredential]$FIDO2
    )
    try {
        Write-Log "Registering FIDO2 key '$DisplayName' in Entra ID for $UPN" -Level Info
        Register-EntraPasskey -UserId $UPN -Passkey $FIDO2 -DisplayName $DisplayName -ErrorAction Stop
        Write-Log "Successfully registered FIDO2 key '$DisplayName' in Entra ID for $UPN" -Level Success
    } catch {
        Write-Log "Failed to register the FIDO2 key '$DisplayName' in Entra ID for $UPN`: $_" -Level Error
        throw
    }
}

function Register-FIDO2KeysForUsers {
    param (
        [object[]]$Users,
        [int]$KeysPerUser = 2
    )
    
    Write-Log "Starting FIDO2 key registration for $($Users.Count) users with $KeysPerUser keys each" -Level Info
    Ensure-Module -ModuleName "DSInternals.Passkeys"
    
    foreach ($account in $Users) {
        Write-Log "Registering FIDO2 keys for $($account.DisplayName)" -Level Info
        
        1..$KeysPerUser | ForEach-Object {
            $upn = $account.UserPrincipalName
            $displayName = "FIDO2-$($account.DisplayName.Replace('BreakGlass ', 'BG'))-K$_"
            
            # Prompt user to prepare the correct FIDO2 key
            if ($_ -eq 1) {
                Write-Host "`nPreparing to register FIDO2 Key #1 for $($account.DisplayName)" -ForegroundColor Yellow
                Read-Host "Please ensure FIDO2 Key #1 is connected and press Enter to continue"
            } else {
                Write-Host "`nPreparing to register FIDO2 Key #2 for $($account.DisplayName)" -ForegroundColor Yellow
                Read-Host "Please unplug the previous key, insert FIDO2 Key #2, and press Enter to continue"
            }
            
            try {
                if ($WhatIf) {
                    Write-Log "WHATIF: Would register FIDO2 key '$displayName' for $upn" -Level Info
                }
                else {
                    # Register the FIDO2 key
                    $fido2Key = Invoke-LocalPasskeyRegistration -UPN $upn -DisplayName $displayName
                    Start-Sleep 2
                    
                    # Register the FIDO2 key in Entra ID
                    Register-FIDO2KeyInEntraID -UPN $upn -DisplayName $displayName -FIDO2 $fido2Key
                    Start-Sleep 2
                    
                    # Verify the registration
                    $verificationResult = Verify-Registration -UPN $upn -DisplayName $displayName
                    if (-not $verificationResult) {
                        Write-Log "FIDO2 key registration verification failed for $upn" -Level Error
                        throw "Verification failed for $displayName"
                    }
                }
            }
            catch {
                Write-Log "Failed to register FIDO2 key '$displayName' for $upn`: $_" -Level Error
                throw
            }
        }
    }
}

function Verify-Registration {
  param (
      [string]$UPN,
      [string]$DisplayName
  )
  
  $maxAttempts = 5
  $delaySeconds = 2
  
  Write-Log "Starting verification for FIDO2 key '$DisplayName' on user $UPN" -Level Info
  
  for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    try {
        Write-Log "Verification attempt $attempt of $maxAttempts for $DisplayName..." -Level Info
        $RegisteredKey = Get-MgBetaUserAuthenticationFido2Method -UserId $UPN | Where-Object { $_.DisplayName -eq $DisplayName }
        if ($RegisteredKey) {
            Write-Log "FIDO2 key '$DisplayName' verified successfully for user $UPN" -Level Success
            return $true
        } else {
            Write-Log "Verification attempt $attempt failed - key not found yet" -Level Warning
            if ($attempt -lt $maxAttempts) {
                Write-Log "Waiting $delaySeconds seconds before retry..." -Level Info
                Start-Sleep -Seconds $delaySeconds
            }
        }
    } catch {
        Write-Log "Verification attempt $attempt encountered error: $_" -Level Warning
        if ($attempt -lt $maxAttempts) {
            Write-Log "Waiting $delaySeconds seconds before retry..." -Level Info
            Start-Sleep -Seconds $delaySeconds
        }
    }
  }
  
  Write-Log "Failed to verify registration of FIDO2 key '$DisplayName' after $maxAttempts attempts" -Level Error
  return $false
}
#endregion

#region Menu Functions
function Show-SettingsMenu {
    Write-Host "`nBreak-Glass Account Settings" -ForegroundColor Cyan
    Write-Host "════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Current Settings:" -ForegroundColor Yellow
    Write-Host "  Account Count:        $($Config.AccountCount)" -ForegroundColor White
    Write-Host "  Keys Per Account:     $($Config.KeysPerAccount)" -ForegroundColor White
    Write-Host "  Account Prefix:       $($Config.AccountPrefix)" -ForegroundColor White
    Write-Host ""
    Write-Host "  [1] Change Account Count (currently: $($Config.AccountCount))" -ForegroundColor Green
    Write-Host "  [2] Change Keys Per Account (currently: $($Config.KeysPerAccount))" -ForegroundColor Green
    Write-Host "  [3] Change Account Prefix (currently: $($Config.AccountPrefix))" -ForegroundColor Green
    Write-Host "  [D] Done - Continue with current settings" -ForegroundColor Cyan
    Write-Host ""
    
    do {
        $choice = Read-Host "Enter your choice (1-3, or D to continue)"
        $choice = $choice.ToUpper().Trim()
        
        switch ($choice) {
            '1' {
                do {
                    $newCount = Read-Host "Enter number of accounts to create (1-10)"
                    if ($newCount -match '^\d+$' -and [int]$newCount -ge 1 -and [int]$newCount -le 10) {
                        $Config.AccountCount = [int]$newCount
                        Write-Host "✓ Account count updated to $($Config.AccountCount)" -ForegroundColor Green
                        Write-Log "Settings updated: AccountCount = $($Config.AccountCount)" -Level Info
                        break
                    }
                    else {
                        Write-Host "Invalid input. Please enter a number between 1 and 10." -ForegroundColor Red
                    }
                } while ($true)
                Show-SettingsMenu
                return
            }
            '2' {
                do {
                    $newKeys = Read-Host "Enter number of FIDO2 keys per account (1-5)"
                    if ($newKeys -match '^\d+$' -and [int]$newKeys -ge 1 -and [int]$newKeys -le 5) {
                        $Config.KeysPerAccount = [int]$newKeys
                        Write-Host "✓ Keys per account updated to $($Config.KeysPerAccount)" -ForegroundColor Green
                        Write-Log "Settings updated: KeysPerAccount = $($Config.KeysPerAccount)" -Level Info
                        break
                    }
                    else {
                        Write-Host "Invalid input. Please enter a number between 1 and 5." -ForegroundColor Red
                    }
                } while ($true)
                Show-SettingsMenu
                return
            }
            '3' {
                do {
                    $newPrefix = Read-Host "Enter account prefix (alphanumeric and hyphens only)"
                    if ($newPrefix -match '^[a-zA-Z0-9-]+$') {
                        $Config.AccountPrefix = $newPrefix
                        Write-Host "✓ Account prefix updated to '$($Config.AccountPrefix)'" -ForegroundColor Green
                        Write-Log "Settings updated: AccountPrefix = $($Config.AccountPrefix)" -Level Info
                        break
                    }
                    else {
                        Write-Host "Invalid prefix. Use only letters, numbers, and hyphens." -ForegroundColor Red
                    }
                } while ($true)
                Show-SettingsMenu
                return
            }
            'D' {
                Write-Log "User finished settings configuration" -Level Info
                return
            }
            default {
                Write-Host "Invalid choice. Please enter 1-3, or D to continue`n" -ForegroundColor Red
            }
        }
    } while ($true)
}

function Find-BreakGlassAccounts {
    Write-Host "`nBreak-Glass Account Detection" -ForegroundColor Cyan
    Write-Host "═════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Searching for break-glass accounts..." -ForegroundColor Yellow
    Write-Host "Search pattern: $($Config.AccountPrefix)*" -ForegroundColor Gray
    Write-Host ""
    
    try {
        $existingAccounts = Get-MgBetaUser -Filter "startswith(userPrincipalName,'$($Config.AccountPrefix)')" -ErrorAction Stop
        
        if ($existingAccounts.Count -gt 0) {
            Write-Host "✓ Found $($existingAccounts.Count) break-glass account(s):" -ForegroundColor Green
            Write-Host ""
            foreach ($account in $existingAccounts) {
                Write-Host "  • " -NoNewline -ForegroundColor Cyan
                Write-Host "$($account.UserPrincipalName)" -ForegroundColor White
                Write-Host "    Display Name: $($account.DisplayName)" -ForegroundColor Gray
                Write-Host "    Object ID: $($account.Id)" -ForegroundColor Gray
                Write-Host "    Created: $($account.CreatedDateTime)" -ForegroundColor Gray
                Write-Host ""
            }
            Write-Log "Found $($existingAccounts.Count) existing break-glass accounts" -Level Success
            return $existingAccounts
        }
        else {
            Write-Host "⚠ No break-glass accounts found matching pattern: $($Config.AccountPrefix)*" -ForegroundColor Yellow
            Write-Log "No break-glass accounts found with prefix '$($Config.AccountPrefix)'" -Level Warning
            return $null
        }
    }
    catch {
        Write-Log "Error searching for break-glass accounts: $_" -Level Error
        Write-Host "✗ Error searching for accounts: $_" -ForegroundColor Red
        throw
    }
}

function Select-BreakGlassAccountsManually {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║        Manual Account Selection                              ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Loading all user accounts for selection..." -ForegroundColor Yellow
    
    try {
        # Get all users
        $allUsers = Get-MgBetaUser -All -Property Id,DisplayName,UserPrincipalName,CreatedDateTime | 
            Select-Object Id, DisplayName, UserPrincipalName, CreatedDateTime |
            Sort-Object DisplayName
        
        Write-Host "Found $($allUsers.Count) total users in the tenant" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Select the break-glass accounts from the grid (use Ctrl+Click for multiple)..." -ForegroundColor Yellow
        Write-Host ""
        
        # Show Out-GridView for selection
        $selectedAccounts = $allUsers | Out-GridView -Title "Select Break-Glass Accounts (Ctrl+Click for multiple)" -OutputMode Multiple
        
        if ($selectedAccounts -and $selectedAccounts.Count -gt 0) {
            Write-Host "✓ Selected $($selectedAccounts.Count) account(s):" -ForegroundColor Green
            foreach ($account in $selectedAccounts) {
                Write-Host "  • $($account.UserPrincipalName)" -ForegroundColor Cyan
            }
            Write-Log "User manually selected $($selectedAccounts.Count) accounts as break-glass accounts" -Level Info
            return $selectedAccounts
        }
        else {
            Write-Host "✗ No accounts selected" -ForegroundColor Red
            Write-Log "User cancelled manual account selection" -Level Warning
            return $null
        }
    }
    catch {
        Write-Log "Error during manual account selection: $_" -Level Error
        Write-Host "✗ Error during account selection: $_" -ForegroundColor Red
        return $null
    }
}

function Get-OrCreateBreakGlassAccounts {
    # First, search for existing accounts
    $accounts = Find-BreakGlassAccounts
    
    if ($accounts) {
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
        $confirmation = Read-Host "Use these accounts? (Y/N)"
        
        if ($confirmation -match '^[Yy]') {
            Write-Log "User confirmed using found break-glass accounts" -Level Info
            return $accounts
        }
        else {
            Write-Host "`nYou chose not to use the found accounts." -ForegroundColor Yellow
        }
    }
    
    # No accounts found or user declined to use them
    Write-Host "`nBreak-Glass Account Setup Required" -ForegroundColor Yellow
    Write-Host "══════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Choose an option:" -ForegroundColor Cyan
    Write-Host "  [1] Create new break-glass accounts" -ForegroundColor Green
    Write-Host "  [2] Select existing accounts manually (Out-GridView)" -ForegroundColor White
    Write-Host "  [Q] Quit" -ForegroundColor Red
    Write-Host ""
    
    do {
        $choice = Read-Host "Enter your choice (1, 2, or Q)"
        $choice = $choice.ToUpper().Trim()
        
        switch ($choice) {
            '1' {
                Write-Log "User chose to create new break-glass accounts" -Level Info
                $pwd = Get-SecurePassword
                $newAccounts = New-BreakGlassUsers -Password $pwd -Count $Config.AccountCount
                Write-Host "`n✓ Successfully created $($newAccounts.Count) break-glass account(s)" -ForegroundColor Green
                Write-Host ""
                foreach ($account in $newAccounts) {
                    Write-Host "  • $($account.UserPrincipalName)" -ForegroundColor White
                    Write-Host "    Display Name: $($account.DisplayName)" -ForegroundColor Gray
                }
                Write-Host ""
                Write-Log "Created $($newAccounts.Count) new break-glass accounts" -Level Success
                return $newAccounts
            }
            '2' {
                Write-Log "User chose to manually select break-glass accounts" -Level Info
                $selectedAccounts = Select-BreakGlassAccountsManually
                if ($selectedAccounts) {
                    return $selectedAccounts
                }
                else {
                    Write-Host "`nNo accounts selected. Please try again.`n" -ForegroundColor Yellow
                }
            }
            'Q' {
                Write-Log "User quit during account selection/creation" -Level Info
                return $null
            }
            default {
                Write-Host "Invalid choice. Please enter 1, 2, or Q`n" -ForegroundColor Red
            }
        }
    } while ($true)
}

function Test-FIDO2Configuration {
    param (
        [object[]]$Accounts
    )
    
    try {
        $allConfigured = $true
        foreach ($account in $Accounts) {
            $fido2Keys = Get-MgBetaUserAuthenticationFido2Method -UserId $account.Id -ErrorAction SilentlyContinue
            if (-not $fido2Keys -or $fido2Keys.Count -eq 0) {
                $allConfigured = $false
                break
            }
        }
        return $allConfigured
    }
    catch {
        return $false
    }
}

function Test-GlobalAdminRole {
    param (
        [object[]]$Accounts
    )
    
    try {
        $gaRoleId = (Get-MgBetaDirectoryRole -Filter "displayName eq 'Global Administrator'" -ErrorAction SilentlyContinue).Id
        $allHaveRole = $true
        
        foreach ($account in $Accounts) {
            $members = Get-MgBetaDirectoryRoleMember -DirectoryRoleId $gaRoleId -ErrorAction SilentlyContinue
            $isMember = $members | Where-Object { $_.Id -eq $account.Id }
            if (-not $isMember) {
                $allHaveRole = $false
                break
            }
        }
        return $allHaveRole
    }
    catch {
        return $false
    }
}

function Test-CAExclusions {
    param (
        [object[]]$Accounts
    )
    
    try {
        $policies = Get-MgBetaIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue
        $allUsersPolicies = @($policies | Where-Object { $_.Conditions.Users.IncludeUsers -contains "All" })
        $policyCount = $allUsersPolicies.Count
        
        if ($policyCount -eq 0) {
            return @{ Excluded = $true; AllUsersPolicyCount = 0 }  # No policies to exclude from
        }
        
        $accountIds = $Accounts.Id
        foreach ($policy in $allUsersPolicies) {
            $excludedUsers = $policy.Conditions.Users.ExcludeUsers
            foreach ($accountId in $accountIds) {
                if ($excludedUsers -notcontains $accountId) {
                    return @{ Excluded = $false; AllUsersPolicyCount = $policyCount }
                }
            }
        }
        return @{ Excluded = $true; AllUsersPolicyCount = $policyCount }
    }
    catch {
        return @{ Excluded = $false; AllUsersPolicyCount = 0 }
    }
}

function Test-RMAUProtection {
    param (
        [object[]]$Accounts
    )
    
    try {
        # Find restricted AUs containing break-glass accounts
        $restrictedAUs = Get-MgBetaDirectoryAdministrativeUnit -Filter "isMemberManagementRestricted eq true" -ErrorAction SilentlyContinue
        
        if (-not $restrictedAUs -or $restrictedAUs.Count -eq 0) {
            return $false  # No RMAUs exist
        }
        
        # Check if all accounts are in at least one RMAU
        $allProtected = $true
        foreach ($account in $Accounts) {
            $inRMAU = $false
            foreach ($au in $restrictedAUs) {
                $members = Get-MgBetaDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -ErrorAction SilentlyContinue
                if ($members.Id -contains $account.Id) {
                    $inRMAU = $true
                    break
                }
            }
            if (-not $inRMAU) {
                $allProtected = $false
                break
            }
        }
        return $allProtected
    }
    catch {
        return $false
    }
}

function Show-ConfigurationMenu {
    param (
        [object[]]$Accounts,
        [hashtable]$ConfigStatus
    )
    
    Write-Host "`nBreak-Glass Account Configuration Menu" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Break-glass accounts ready: $($Accounts.Count) account(s)" -ForegroundColor Green
    Write-Host ""
    foreach ($account in $Accounts) {
        Write-Host "  • $($account.UserPrincipalName)" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "Select configuration steps to perform:" -ForegroundColor Yellow
    Write-Host ""
    
    # Step 1: FIDO2
    if ($ConfigStatus.FIDO2Configured) {
        Write-Host "  [1] Register FIDO2 security keys" -NoNewline -ForegroundColor White
        if ($ConfigStatus.InRMAU) {
            Write-Host " [✓ Already configured]" -NoNewline -ForegroundColor Green
            Write-Host " (⚠ RMAU protection may block FIDO2 detection)" -ForegroundColor Yellow
        } else {
            Write-Host " [✓ Already configured]" -ForegroundColor Green
        }
    } else {
        Write-Host "  [1] Register FIDO2 security keys" -NoNewline -ForegroundColor White
        if ($ConfigStatus.InRMAU) {
            Write-Host " [⚠ Needed]" -NoNewline -ForegroundColor Yellow
            Write-Host " (⚠ RMAU protection may block FIDO2 detection)" -ForegroundColor Yellow
        } else {
            Write-Host " [⚠ Needed]" -ForegroundColor Yellow
        }
    }
    
    # Step 2: CA Exclusions
    if ($ConfigStatus.CAExcluded.Excluded) {
        $caCount = $ConfigStatus.CAExcluded.AllUsersPolicyCount
        $caLabel = if ($caCount -gt 0) { " [✓ Excluded from $caCount 'All users' $(if($caCount -eq 1){'policy'}else{'policies'})]" } else { " [✓ No 'All users' policies found]" }
        Write-Host "  [2] Exclude from Conditional Access policies" -NoNewline -ForegroundColor White
        Write-Host $caLabel -ForegroundColor Green
    } else {
        $caCount = $ConfigStatus.CAExcluded.AllUsersPolicyCount
        Write-Host "  [2] Exclude from Conditional Access policies" -NoNewline -ForegroundColor White
        Write-Host " [⚠ Needed — $caCount 'All users' $(if($caCount -eq 1){'policy'}else{'policies'}) not fully covered]" -ForegroundColor Yellow
    }
    
    # Step 3: GA Role
    if ($ConfigStatus.HasGARole) {
        Write-Host "  [3] Assign Global Administrator role" -NoNewline -ForegroundColor Yellow
        Write-Host " [✓ Already assigned]" -ForegroundColor Green
    } else {
        Write-Host "  [3] Assign Global Administrator role" -NoNewline -ForegroundColor Yellow
        Write-Host " [⚠ Needed]" -ForegroundColor Yellow
    }
    
    # Step 4: RMAU Protection
    if ($ConfigStatus.InRMAU) {
        Write-Host "  [4] Add to Restricted Management Administrative Unit (RMAU)" -NoNewline -ForegroundColor Yellow
        Write-Host " [✓ Already protected]" -ForegroundColor Green
    } else {
        Write-Host "  [4] Add to Restricted Management Administrative Unit (RMAU)" -NoNewline -ForegroundColor Yellow
        Write-Host " [⚠ Recommended]" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "  ⚠ IMPORTANT: Setup FIDO2 keys BEFORE assigning GA role!" -ForegroundColor Yellow
    Write-Host "  ⚠ IMPORTANT: Add to RMAU LAST - it restricts future modifications!" -ForegroundColor Yellow
    Write-Host "    Recommended order: [1] → [2] → [3] → [4]" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [A] Run ALL configuration steps (recommended order)" -ForegroundColor Green
    Write-Host "  [Q] Quit without configuring" -ForegroundColor Red
    Write-Host ""
}

function Get-ConfigurationSelection {
    param (
        [object[]]$Accounts
    )
    
    $validSelections = @('1','2','3','4','A','Q')
    
    do {
        # Check current configuration status
        Write-Host "Checking current configuration status..." -ForegroundColor Gray
        $configStatus = @{
            FIDO2Configured = Test-FIDO2Configuration -Accounts $Accounts
            HasGARole = Test-GlobalAdminRole -Accounts $Accounts
            CAExcluded = Test-CAExclusions -Accounts $Accounts
            InRMAU = Test-RMAUProtection -Accounts $Accounts
        }
        
        Show-ConfigurationMenu -Accounts $Accounts -ConfigStatus $configStatus
        $selection = Read-Host "Enter your selection(s) (e.g., '1,2' for multiple or 'A' for all)"
        $selection = $selection.ToUpper().Trim()
        
        if ($selection -eq 'Q') {
            Write-Log "User chose to quit without configuring accounts" -Level Info
            return $null
        }
        
        if ($selection -eq 'A') {
            Write-Log "User selected ALL configuration steps" -Level Info
            return @('1','2','3','4')
        }
        
        # Parse comma-separated selections
        $selections = $selection -split ',' | ForEach-Object { $_.Trim() }
        $invalidSelections = $selections | Where-Object { $_ -notin $validSelections }
        
        if ($invalidSelections.Count -gt 0) {
            Write-Host "`nInvalid selection(s): $($invalidSelections -join ', ')" -ForegroundColor Red
            Write-Host "Please enter valid options (1-4, A, or Q)" -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
        else {
            Write-Log "User selected configuration steps: $($selections -join ', ')" -Level Info
            return $selections
        }
    } while ($true)
}
#endregion

#region Main Execution
function Start-BreakGlassConfiguration {
    param (
        [object[]]$BreakGlassAccounts,
        [string[]]$ConfigSteps
    )
    
    try {
        Write-Log "=== Starting Break-Glass Account Configuration ===" -Level Info
        Write-Log "Configuring $($BreakGlassAccounts.Count) accounts" -Level Info
        Write-Log "Selected configuration steps: $($ConfigSteps -join ', ')" -Level Info
        
        $totalSteps = $ConfigSteps.Count
        $currentStep = 0
        
        # Step 1: Register FIDO2 keys
        if ($ConfigSteps -contains '1') {
            $currentStep++
            $percentComplete = [int](($currentStep / $totalSteps) * 100)
            
            Show-Progress -Activity "Break-Glass Configuration" -Status "Registering FIDO2 keys" -PercentComplete $percentComplete
            Register-FIDO2KeysForUsers -Users $BreakGlassAccounts -KeysPerUser $Config.KeysPerAccount
            Write-Log "✓ Configuration step 1 completed: Registered FIDO2 keys" -Level Success
        }
        else {
            Write-Log "Configuration step 1 skipped: Register FIDO2 keys" -Level Info
        }
        
        # Step 2: Exclude from all Conditional Access policies
        if ($ConfigSteps -contains '2') {
            $currentStep++
            $percentComplete = [int](($currentStep / $totalSteps) * 100)
            
            Show-Progress -Activity "Break-Glass Configuration" -Status "Updating Conditional Access policies" -PercentComplete $percentComplete
            Remove-FromConditionalAccessPolicies -BreakGlassAccounts $BreakGlassAccounts
            Write-Log "✓ Configuration step 2 completed: Excluded from Conditional Access policies" -Level Success
        }
        else {
            Write-Log "Configuration step 2 skipped: Exclude from Conditional Access policies" -Level Info
        }
        
        # Step 3: Add Global Administrator role
        if ($ConfigSteps -contains '3') {
            $currentStep++
            $percentComplete = [int](($currentStep / $totalSteps) * 100)
            
            Show-Progress -Activity "Break-Glass Configuration" -Status "Adding Global Administrator roles" -PercentComplete $percentComplete
            Add-GlobalAdminRole
            Write-Log "✓ Configuration step 3 completed: Assigned Global Administrator role" -Level Success
        }
        else {
            Write-Log "Configuration step 3 skipped: Assign Global Administrator role" -Level Info
        }
        
        # Step 4: Add to Restricted Management Administrative Unit
        if ($ConfigSteps -contains '4') {
            $currentStep++
            $percentComplete = [int](($currentStep / $totalSteps) * 100)
            
            Show-Progress -Activity "Break-Glass Configuration" -Status "Configuring RMAU protection" -PercentComplete $percentComplete
            Add-ToRestrictedAdministrativeUnit
            Write-Log "✓ Configuration step 4 completed: Added to Restricted Administrative Unit" -Level Success
        }
        else {
            Write-Log "Configuration step 4 skipped: Add to Restricted Administrative Unit" -Level Info
        }
        
        Show-Progress -Activity "Break-Glass Configuration" -Status "Completed successfully" -PercentComplete 100
        Write-Log "=== Break-glass account configuration completed successfully! ===" -Level Success
        
        # Summary
        Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║                CONFIGURATION SUMMARY                         ║" -ForegroundColor Green
        Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Host "Configured $($BreakGlassAccounts.Count) break-glass account(s):" -ForegroundColor Yellow
        $BreakGlassAccounts | ForEach-Object { Write-Host "  • $($_.UserPrincipalName)" -ForegroundColor Cyan }
        Write-Host ""
        Write-Host "Completed configuration steps:" -ForegroundColor Yellow
        if ($ConfigSteps -contains '1') { Write-Host "  ✓ Registered FIDO2 security keys ($($Config.KeysPerAccount * $BreakGlassAccounts.Count) total)" -ForegroundColor Green }
        if ($ConfigSteps -contains '2') { Write-Host "  ✓ Excluded from Conditional Access policies" -ForegroundColor Green }
        if ($ConfigSteps -contains '3') { Write-Host "  ✓ Assigned Global Administrator role" -ForegroundColor Green }
        if ($ConfigSteps -contains '4') { Write-Host "  ✓ Added to Restricted Management Administrative Unit" -ForegroundColor Green }
        Write-Host ""
        Write-Host "Log file: $script:LogFilePath" -ForegroundColor White
        Write-Host ""
        
    } catch {
        Write-Log "Configuration failed: $_" -Level Error
        Show-Progress -Activity "Break-Glass Configuration" -Status "Failed" -PercentComplete 100
        throw
    }
}

# Initialize logging first
Initialize-Logging

# Check required modules before proceeding (only DSInternals.Passkeys needs to be checked since Graph modules are handled by #Requires)
Write-Log "Checking DSInternals.Passkeys module..." -Level Info
try {
    $passkeyModule = Get-Module -Name "DSInternals.Passkeys" -ListAvailable
    if (-not $passkeyModule) {
        Write-Log "Installing DSInternals.Passkeys module..." -Level Info
        Install-Module -Name "DSInternals.Passkeys" -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck
        Write-Log "Successfully installed DSInternals.Passkeys module" -Level Success
    } else {
        Write-Log "DSInternals.Passkeys module is already installed" -Level Success
    }
}
catch {
    Write-Log "Failed to check/install DSInternals.Passkeys module: $_" -Level Error
    exit 1
}

# Connect to Microsoft Graph with proper cleanup
Write-Log "Preparing Microsoft Graph connection..." -Level Info
try {
    # Disconnect any existing Graph sessions to prevent conflicts
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Log "Disconnected any existing Graph sessions" -Level Info
    }
    catch {
        # Ignore errors from disconnect if no session exists
    }
    
    # Connect with required scopes
    Write-Log "Connecting to Microsoft Graph..." -Level Info
    Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All, Directory.AccessAsUser.All, Policy.ReadWrite.ConditionalAccess, RoleManagement.ReadWrite.Directory, User.ReadWrite.All"
    Write-Log "Successfully connected to Microsoft Graph" -Level Success
}
catch {
    Write-Log "Failed to connect to Microsoft Graph: $_" -Level Error
    exit 1
}

# Display and configure settings
Show-SettingsMenu

# Step 1: Get or create break-glass accounts
$breakGlassAccounts = Get-OrCreateBreakGlassAccounts

if (-not $breakGlassAccounts -or $breakGlassAccounts.Count -eq 0) {
    Write-Host "`nNo break-glass accounts available. Exiting..." -ForegroundColor Yellow
    Write-Log "Script terminated - no break-glass accounts available" -Level Warning
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    exit 0
}

# Step 2 & 3: Loop to allow multiple configuration operations
do {
    # Get configuration steps to perform
    $configSteps = Get-ConfigurationSelection -Accounts $breakGlassAccounts
    
    if (-not $configSteps) {
        Write-Host "`nExiting configuration menu..." -ForegroundColor Yellow
        Write-Log "User exited configuration menu" -Level Info
        break
    }
    
    # Execute the configuration
    Start-BreakGlassConfiguration -BreakGlassAccounts $breakGlassAccounts -ConfigSteps $configSteps
    
    Write-Host "`nPress Enter to return to configuration menu..." -ForegroundColor Cyan
    Read-Host
    
} while ($true)

Write-Log "Script completed" -Level Info
Disconnect-MgGraph -ErrorAction SilentlyContinue
#endregion