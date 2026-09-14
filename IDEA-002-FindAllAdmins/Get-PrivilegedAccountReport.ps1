<#
.SYNOPSIS
    I.D.E.A. 002 - Comprehensive security audit of all privileged accounts in Entra ID with automated risk assessment.

.DESCRIPTION
    Part of Identity Engineering Artifacts (I.D.E.A.) 002 - Privileged Account Security Audit
    
    This script performs comprehensive discovery and analysis of administrative privilege assignments 
    in your Entra ID tenant, providing actionable security insights to identify and remediate risky 
    configurations.
    
    SETUP: First run Create-PrivilegedAccountReportApp.ps1 to create the required app registration 
    with certificate-based authentication and proper Graph API permissions. Then establish a Graph 
    connection before running this report script.
    
    WHAT THIS SCRIPT DISCOVERS:
    ✓ Direct role assignments (active/permanent privileges)
    ✓ PIM eligible role assignments (can activate privileges)
    ✓ Group-based role assignments (privileges inherited from groups)
    ✓ Complex PIM chains (groups eligible to activate membership in other groups that grant roles)
    ✓ Complete nested group resolution (tracks privilege paths through multiple group layers)
    ✓ Service principals with administrative roles
    ✓ MFA authentication methods for each privileged user
    ✓ Restricted Administrative Unit (RMAU) protection status
    
    ASSIGNMENT TYPE BADGES EXPLAINED:
    [Active]     = Direct role assignment - user has permanent/standing administrative role
    [PIM]        = PIM Eligible - user can activate the administrative role on-demand
    [Group]      = Group-Based - user is an active member of a group that has the administrative role
    [PIM-Group]  = PIM Group Eligible - user can activate membership in a group that has the administrative role
    
    Key Differences:
    • [Group] users CURRENTLY HAVE the privilege through active group membership
    • [PIM-Group] users CAN OBTAIN the privilege by activating group membership (requires PIM activation)
    • [Group] includes nested groups - user may be in Group A, which is in Group B that has the role
    • [PIM-Group] includes complex chains - user eligible for Group A, which is eligible for Group B with role
    
    SECURITY RISK ASSESSMENT:
    Each privileged user receives a risk level based on two critical security factors:
    
    🚨 CRITICAL: No MFA enabled (immediate security risk)
    🚨 HIGH: Phone/SMS MFA + No RMAU protection (vulnerable to SIM swapping + lateral movement)
    ⚠️ MEDIUM: Either phone MFA with RMAU OR strong MFA without RMAU (single weakness)
    ✅ LOW: Strong MFA (FIDO2/Authenticator) + RMAU protection (fully secured)
    
    WHY THESE CHECKS MATTER:
    • Phone/SMS MFA is vulnerable to SIM swapping attacks
    • Restricted Administrative Units prevent privilege escalation and lateral movement
    • Privileged accounts are the highest-value targets for attackers
    • Combined weaknesses (phone MFA + no RMAU) create critical security gaps
    
    OUTPUT FORMATS:
    • On-screen summary with risk statistics and detailed findings
    • CSV export: RoleDistribution (roles/groups with assignment counts)
    • CSV export: UserStatus (per-user details with roles, MFA methods, risk levels)
    • Interactive HTML report: filterable/sortable dashboard of every privileged principal
    
    The script resolves complex privilege paths including scenarios where users are eligible 
    to activate membership in groups that are themselves eligible to activate membership in 
    other groups that grant administrative roles (multi-level PIM chains).

.PARAMETER LogDirectory
    Directory path for log files. Defaults to .\Logs

.PARAMETER IncludeGroups
    Include group-based role assignments and PIM group eligibility. Defaults to $true.
    Set to $false to exclude group-related privileged access from the report.

.PARAMETER ReturnData
    When specified, returns data objects instead of displaying report. Useful for storing results in variables.

.PARAMETER UseInteractiveAuth
    Use interactive authentication instead of app-based authentication.
    When not specified, assumes app-based (certificate or client secret) authentication is already established.

.EXAMPLE
    # Setup (one-time): Create app registration with required permissions
    .\Create-PrivilegedAccountReportApp.ps1
    
    # Then establish Graph connection and run the report:
    .\Get-PrivilegedAccountReport.ps1
    Runs the report, displays on-screen summary, and prompts for CSV export.

.EXAMPLE
    .\Get-PrivilegedAccountReport.ps1 -UseInteractiveAuth
    Uses interactive authentication (prompts for credentials) instead of app-based auth.

.EXAMPLE
    .\Get-PrivilegedAccountReport.ps1 -IncludeGroups $false
    Excludes group-based and PIM group assignments from the report (groups included by default).

.EXAMPLE
    $results = .\Get-PrivilegedAccountReport.ps1 -ReturnData
    Stores results in variable for analysis. Access with $results.Users and $results.Summary

.NOTES
    Authentication:
    - Default: Uses app-based authentication (certificate or client secret)
    - Alternative: Use -UseInteractiveAuth for interactive login
    
    IMPORTANT - Interactive Authentication Limitation:
    When using interactive authentication (-UseInteractiveAuth), MFA status reporting may be incomplete
    if privileged users are members of Restricted Administrative Units (RAUs) and the interactive user
    does not have access to those RAUs. App-only authentication is recommended for complete reporting.
    
    Portability:
    This script is designed to work across any Microsoft Entra ID tenant without modification.
    - No hardcoded tenant IDs, domain names, or resource identifiers
    - All role and group discovery is dynamic via Microsoft Graph API
    - Log and export paths use relative directories (.\Logs by default)
    - Works with both certificate-based and interactive authentication
    
    Required Microsoft Graph API permissions (Application):
    - User.Read.All
    - Directory.Read.All
    - RoleManagement.Read.Directory
    - RoleEligibilitySchedule.Read.Directory
    - UserAuthenticationMethod.Read.All
    - PrivilegedAccess.Read.AzureADGroup (for PIM group eligibility detection)
    
    Author: Per-Torben Sørensen
    Version: 1.3
    Created: October 2025
    Updated: February 2026 - Added PIM group eligibility, service principal detection, account-focused output
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$LogDirectory = ".\Logs",
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeGroups = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$ReturnData,
    
    [Parameter(Mandatory = $false)]
    [switch]$UseInteractiveAuth
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.Governance, Microsoft.Graph.Identity.SignIns

# Create log directory if it doesn't exist
if (!(Test-Path $LogDirectory)) { 
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null 
}

$LogFile = Join-Path $LogDirectory "Get-PrivilegedAccountReport-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $LogEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $LogFile -Value $LogEntry
    
    switch ($Level) {
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function Get-PIMEligibleAssignments {
    <#
    .SYNOPSIS
        Retrieves PIM eligible role assignments for users.
    #>
    param()
    
    try {
        Write-Log "Retrieving PIM eligible role assignments..." -Level "INFO"
        
        # Try multiple PIM endpoints to ensure we catch all eligible assignments
        $eligibleAssignments = @()
        $endpoints = @(
            "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances",
            "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules",
            "https://graph.microsoft.com/beta/privilegedAccess/azureAD/roleAssignments?`$filter=assignmentState eq 'Eligible'",
            "https://graph.microsoft.com/beta/privilegedAccess/aadRoles/roleAssignments?`$filter=assignmentState eq 'Eligible'"
        )
        
        foreach ($endpoint in $endpoints) {
            try {
                $uri = $endpoint
                
                do {
                    $response = Invoke-MgGraphRequest -Uri $uri -Method GET
                    $eligibleAssignments += $response.value
                    $uri = $response.'@odata.nextLink'
                } while ($uri)
                
                # If we got results from this endpoint, no need to try others
                if ($eligibleAssignments.Count -gt 0) {
                    Write-Log "Found $($eligibleAssignments.Count) PIM eligible assignments" -Level "INFO"
                    break
                }
            }
            catch {
                # Silent continue for PIM endpoint failures
                continue
            }
        }
        
        Write-Log "Found $($eligibleAssignments.Count) total PIM eligible assignments" -Level "SUCCESS"
        return $eligibleAssignments
    }
    catch {
        $errorMessage = $_.Exception.Message
        
        # Check if this is a PIM licensing issue (P2 required)
        if ($errorMessage -match "BadRequest|Bad Request|Forbidden|403") {
            Write-Log "PIM is not available - This feature requires Entra ID P2 (Premium P2) licensing" -Level "WARNING"
            Write-Host ""
            Write-Host "  NOTE: Privileged Identity Management (PIM) requires Entra ID P2 license." -ForegroundColor Yellow
            Write-Host "        Your tenant appears to have P1 licensing." -ForegroundColor Yellow
            Write-Host "        Only active (permanent) role assignments will be shown." -ForegroundColor Yellow
            Write-Host ""
        }
        else {
            Write-Log "Error retrieving PIM eligible assignments: $errorMessage" -Level "ERROR"
        }
        return @()
    }
}

function Get-ActiveRoleAssignments {
    <#
    .SYNOPSIS
        Retrieves active (permanent) role assignments for users.
    #>
    param()
    
    try {
        Write-Log "Retrieving active role assignments..." -Level "INFO"
        
        # Get active assignments without expand (will fetch details separately)
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
        $activeAssignments = @()
        
        do {
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET
            $activeAssignments += $response.value
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        Write-Log "Found $($activeAssignments.Count) active role assignments" -Level "SUCCESS"
        return $activeAssignments
    }
    catch {
        Write-Log "Error retrieving active role assignments: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Get-GroupBasedRoleAssignments {
    <#
    .SYNOPSIS
        Retrieves role assignments made to groups (role-assignable groups).
    #>
    param()
    
    try {
        Write-Log "Retrieving group-based role assignments..." -Level "INFO"
        
        # Get all role assignments without expand
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
        $allAssignments = @()
        
        do {
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET
            $allAssignments += $response.value
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        
        # Filter for group principals - will need to fetch principal details separately
        # Group assignments will have principalId that we need to verify is a group
        Write-Log "Found $($allAssignments.Count) total role assignments, filtering for groups..." -Level "INFO"
        
        return $allAssignments
    }
    catch {
        Write-Log "Error retrieving group-based role assignments: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Get-PIMGroupEligibilityAssignments {
    <#
    .SYNOPSIS
        Retrieves PIM group eligibility assignments (users eligible to activate group membership).
    #>
    param(
        [Parameter(Mandatory = $false)]
        [array]$RoleAssignableGroups = @(),
        [Parameter(Mandatory = $false)]
        [array]$EligibleAssignments = @()
    )
    
    try {
        Write-Log "Retrieving PIM group eligibility assignments..." -Level "INFO"
        
        $eligibleGroupAssignments = @()
        
        # If we have specific role-assignable groups, check each one individually
        if ($RoleAssignableGroups.Count -gt 0) {
            Write-Log "Checking PIM eligibility for $($RoleAssignableGroups.Count) role-assignable groups individually..." -Level "INFO"
            
            foreach ($group in $RoleAssignableGroups) {
                $groupId = $group.Id
                $groupName = $group.DisplayName
                
                Write-Log "Checking PIM eligibility for group: $groupName (ID: $groupId)" -Level "INFO"
                
                # Try different PIM group endpoints for this specific group
                $groupEndpoints = @(
                    "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$groupId'",
                    "https://graph.microsoft.com/beta/privilegedAccess/aadGroups/$groupId/eligibilitySchedules",
                    "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$groupId'",
                    "https://graph.microsoft.com/beta/privilegedAccess/group/$groupId/eligibilitySchedules"
                )
                
                $groupAssignments = @()
                
                foreach ($endpoint in $groupEndpoints) {
                    try {
                        $uri = $endpoint
                        do {
                            $response = Invoke-MgGraphRequest -Uri $uri -Method GET
                            
                            if ($response.value) {
                                $groupAssignments += $response.value
                            }
                            
                            $uri = $response.'@odata.nextLink'
                        } while ($uri)
                        
                        if ($groupAssignments.Count -gt 0) {
                            Write-Log "Found $($groupAssignments.Count) PIM eligibility assignments for group $groupName" -Level "SUCCESS"
                            break  # If successful, don't try other endpoints for this group
                        }
                    }
                    catch {
                        # Silent continue for PIM endpoint failures
                    }
                }
                
                # Log final result for group
                if ($groupAssignments.Count -eq 0) {
                    Write-Log "No PIM eligibility found for group $groupName" -Level "INFO"
                }
                
                $eligibleGroupAssignments += $groupAssignments
            }
        }
        else {
            # Fallback to bulk endpoints if no specific groups provided
            Write-Log "No role-assignable groups provided, trying bulk PIM endpoints..." -Level "INFO"
            
            $endpoints = @(
                "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances",
                "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules"
            )
            
            foreach ($endpoint in $endpoints) {
                try {
                    Write-Log "Trying PIM group endpoint: $endpoint" -Level "INFO"
                    $uri = $endpoint
                    
                    do {
                        $response = Invoke-MgGraphRequest -Uri $uri -Method GET
                        $eligibleGroupAssignments += $response.value
                        $uri = $response.'@odata.nextLink'
                    } while ($uri)
                    
                    Write-Log "Found $($response.value.Count) group eligibility assignments from endpoint" -Level "INFO"
                    
                    # If we got results from this endpoint, no need to try others
                    if ($eligibleGroupAssignments.Count -gt 0) {
                        break
                    }
                }
                catch {
                    Write-Log "Endpoint $endpoint failed: $($_.Exception.Message)" -Level "WARNING"
                    continue
                }
            }
        }
        
        Write-Log "Found $($eligibleGroupAssignments.Count) total PIM group eligibility assignments" -Level "SUCCESS"
        return $eligibleGroupAssignments
    }
    catch {
        $errorMessage = $_.Exception.Message
        
        # Check if this is a PIM licensing issue (P2 required) or endpoint issue
        if ($errorMessage -match "BadRequest|Bad Request|Forbidden|403") {
            Write-Log "PIM Group Eligibility may not be available - checking if endpoint exists" -Level "WARNING"
        }
        elseif ($errorMessage -match "NotFound|404") {
            Write-Log "PIM Group Eligibility endpoint not found - feature may not be enabled" -Level "WARNING"
        }
        else {
            Write-Log "Error retrieving PIM group eligibility assignments: $errorMessage" -Level "WARNING"
        }
        return @()
    }
}

function Get-NestedGroupMembers {
    <#
    .SYNOPSIS
        Recursively gets all user members from a group, including nested groups.
    #>
    param(
        [string]$GroupId,
        [hashtable]$ProcessedGroups = @{},
        [int]$MaxDepth = 10,
        [int]$CurrentDepth = 0
    )
    
    # Prevent infinite recursion
    if ($CurrentDepth -ge $MaxDepth) {
        Write-Log "Maximum nesting depth ($MaxDepth) reached for group $GroupId" -Level "WARNING"
        return @()
    }
    
    # Check if we've already processed this group to prevent circular references
    if ($ProcessedGroups.ContainsKey($GroupId)) {
        return @()
    }
    
    $ProcessedGroups[$GroupId] = $true
    $allUsers = @()
    
    try {
        # Get direct members of the group
        $members = Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop
        
        foreach ($member in $members) {
            $memberType = $member.AdditionalProperties.'@odata.type'
            
            if ($memberType -eq '#microsoft.graph.user') {
                # It's a user, add to collection
                $allUsers += @{
                    Id = $member.Id
                    GroupPath = @($GroupId)
                    NestingLevel = $CurrentDepth
                }
            }
            elseif ($memberType -eq '#microsoft.graph.group') {
                # It's a nested group, recurse into it
                $nestedUsers = Get-NestedGroupMembers -GroupId $member.Id -ProcessedGroups $ProcessedGroups -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
                
                # Add current group to the path for all nested users
                foreach ($nestedUser in $nestedUsers) {
                    $nestedUser.GroupPath = @($GroupId) + $nestedUser.GroupPath
                    $nestedUser.NestingLevel = $CurrentDepth
                    $allUsers += $nestedUser
                }
            }
        }
    }
    catch {
        Write-Log "Error retrieving members for group $GroupId : $($_.Exception.Message)" -Level "WARNING"
    }
    
    return $allUsers
}

function Get-GroupRoleChain {
    <#
    .SYNOPSIS
        Resolves all roles that a group provides, including through nested group membership and PIM assignments.
    #>
    param(
        [string]$GroupId,
        [array]$AllActiveAssignments,
        [array]$AllEligibleAssignments,
        [array]$AllPIMGroupEligibility,
        [hashtable]$ProcessedGroups = @{},
        [int]$MaxDepth = 10,
        [int]$CurrentDepth = 0
    )
    
    # Prevent infinite recursion
    if ($CurrentDepth -ge $MaxDepth) {
        Write-Log "Maximum nesting depth ($MaxDepth) reached for group role chain $GroupId" -Level "WARNING"
        return @()
    }
    
    # Check if we've already processed this group to prevent circular references
    if ($ProcessedGroups.ContainsKey($GroupId)) {
        return @()
    }
    
    $ProcessedGroups[$GroupId] = $true
    $roleChain = @()
    
    try {
        $group = Get-MgGroup -GroupId $GroupId -Property DisplayName,IsAssignableToRole -ErrorAction Stop
        
        # Check for direct active role assignments
        $directActiveRoles = $AllActiveAssignments | Where-Object { $_.principalId -eq $GroupId }
        foreach ($assignment in $directActiveRoles) {
            $roleDefinition = Get-RoleDefinitionDetails -RoleDefinitionId $assignment.roleDefinitionId
            if ($roleDefinition) {
                $roleChain += @{
                    RoleName = $roleDefinition.displayName
                    RoleId = $assignment.roleDefinitionId
                    AssignmentType = "Active (via Group)"
                    GroupName = $group.DisplayName
                    GroupId = $GroupId
                    GroupPath = @($GroupId)
                    GroupPathNames = @($group.DisplayName)
                    NestingLevel = $CurrentDepth
                }
            }
        }
        
        # Check for direct PIM eligible role assignments
        $directEligibleRoles = $AllEligibleAssignments | Where-Object { $_.principalId -eq $GroupId }
        foreach ($assignment in $directEligibleRoles) {
            $roleDefinition = Get-RoleDefinitionDetails -RoleDefinitionId $assignment.roleDefinitionId
            if ($roleDefinition) {
                $roleChain += @{
                    RoleName = $roleDefinition.displayName
                    RoleId = $assignment.roleDefinitionId
                    AssignmentType = "PIM Eligible (via Group)"
                    GroupName = $group.DisplayName
                    GroupId = $GroupId
                    GroupPath = @($GroupId)
                    GroupPathNames = @($group.DisplayName)
                    NestingLevel = $CurrentDepth
                }
            }
        }
        
        # Check if this group is a member of other groups (regular nesting)
        try {
            $memberOfGroups = Get-MgGroupMemberOf -GroupId $GroupId -All -ErrorAction Stop
            foreach ($parentGroup in $memberOfGroups) {
                $parentGroupType = $parentGroup.AdditionalProperties.'@odata.type'
                if ($parentGroupType -eq '#microsoft.graph.group') {
                    # Recursively check the parent group's role assignments
                    $parentRoles = Get-GroupRoleChain -GroupId $parentGroup.Id `
                        -AllActiveAssignments $AllActiveAssignments `
                        -AllEligibleAssignments $AllEligibleAssignments `
                        -AllPIMGroupEligibility $AllPIMGroupEligibility `
                        -ProcessedGroups $ProcessedGroups `
                        -MaxDepth $MaxDepth `
                        -CurrentDepth ($CurrentDepth + 1)
                    
                    # Add current group to the path for all parent roles
                    foreach ($role in $parentRoles) {
                        $role.GroupPath = @($GroupId) + $role.GroupPath
                        $role.GroupPathNames = @($group.DisplayName) + $role.GroupPathNames
                        $role.NestingLevel = $CurrentDepth
                        $roleChain += $role
                    }
                }
            }
        }
        catch {
            Write-Log "Error checking group membership for $GroupId : $($_.Exception.Message)" -Level "WARNING"
        }
        
        # NEW: Check if this group is PIM ELIGIBLE for membership in other groups
        $pimEligibleForGroups = $AllPIMGroupEligibility | Where-Object { $_.principalId -eq $GroupId }
        foreach ($pimEligibility in $pimEligibleForGroups) {
            $targetGroupId = $pimEligibility.groupId
            Write-Log "Group $($group.DisplayName) is PIM eligible for group $targetGroupId" -Level "INFO"
            
            try {
                # Recursively check what roles the target group provides
                $targetGroupRoles = Get-GroupRoleChain -GroupId $targetGroupId `
                    -AllActiveAssignments $AllActiveAssignments `
                    -AllEligibleAssignments $AllEligibleAssignments `
                    -AllPIMGroupEligibility $AllPIMGroupEligibility `
                    -ProcessedGroups $ProcessedGroups `
                    -MaxDepth $MaxDepth `
                    -CurrentDepth ($CurrentDepth + 1)
                
                # Add current group to the path with PIM indicator
                foreach ($role in $targetGroupRoles) {
                    $role.GroupPath = @($GroupId) + $role.GroupPath
                    $role.GroupPathNames = @("$($group.DisplayName) [PIM]") + $role.GroupPathNames
                    $role.NestingLevel = $CurrentDepth
                    $roleChain += $role
                }
            }
            catch {
                Write-Log "Error checking PIM eligible group $targetGroupId : $($_.Exception.Message)" -Level "WARNING"
            }
        }
    }
    catch {
        Write-Log "Error resolving role chain for group $GroupId : $($_.Exception.Message)" -Level "WARNING"
    }
    
    return $roleChain
}

function Get-AllGroupMembers {
    <#
    .SYNOPSIS
        Gets all members of a group including users in nested regular groups and users PIM eligible for nested groups.
        This handles: User → Regular Group → PIM Group → Role scenarios.
    #>
    param(
        [string]$GroupId,
        [array]$AllPIMGroupEligibility,
        [hashtable]$ProcessedGroups = @{},
        [int]$MaxDepth = 10,
        [int]$CurrentDepth = 0
    )
    
    # Prevent infinite recursion
    if ($CurrentDepth -ge $MaxDepth) {
        Write-Log "Maximum depth ($MaxDepth) reached for group members $GroupId" -Level "WARNING"
        return @()
    }
    
    # Check if we've already processed this group
    if ($ProcessedGroups.ContainsKey($GroupId)) {
        return @()
    }
    
    $ProcessedGroups[$GroupId] = $true
    $allMembers = @()
    
    try {
        $group = Get-MgGroup -GroupId $GroupId -Property DisplayName -ErrorAction Stop
        
        # Get direct members of the group
        $members = Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop
        
        foreach ($member in $members) {
            $memberType = $member.AdditionalProperties.'@odata.type'
            
            if ($memberType -eq '#microsoft.graph.user') {
                # Direct user member
                $allMembers += @{
                    UserId = $member.Id
                    MembershipType = "Direct Member"
                    GroupPath = @($group.DisplayName)
                    GroupIdPath = @($GroupId)
                    NestingLevel = $CurrentDepth
                }
            }
            elseif ($memberType -eq '#microsoft.graph.group') {
                # Nested group - get its members recursively
                $nestedMembers = Get-AllGroupMembers -GroupId $member.Id `
                    -AllPIMGroupEligibility $AllPIMGroupEligibility `
                    -ProcessedGroups $ProcessedGroups `
                    -MaxDepth $MaxDepth `
                    -CurrentDepth ($CurrentDepth + 1)
                
                foreach ($nestedMember in $nestedMembers) {
                    $nestedMember.GroupPath = @($group.DisplayName) + $nestedMember.GroupPath
                    $nestedMember.GroupIdPath = @($GroupId) + $nestedMember.GroupIdPath
                    $allMembers += $nestedMember
                }
            }
        }
        
        # Also check for users who are PIM eligible for this group
        $pimEligibleForThisGroup = $AllPIMGroupEligibility | Where-Object { $_.groupId -eq $GroupId }
        foreach ($pimAssignment in $pimEligibleForThisGroup) {
            # Check if it's a user
            try {
                $user = Get-MgUser -UserId $pimAssignment.principalId -Property Id -ErrorAction Stop
                $allMembers += @{
                    UserId = $user.Id
                    MembershipType = "PIM Eligible"
                    GroupPath = @("$($group.DisplayName) [PIM]")
                    GroupIdPath = @($GroupId)
                    NestingLevel = $CurrentDepth
                }
            }
            catch {
                # Not a user, check if it's a group that is PIM eligible for this group
                try {
                    $pimEligibleGroup = Get-MgGroup -GroupId $pimAssignment.principalId -Property DisplayName -ErrorAction Stop
                    
                    # Recursively get members of the PIM eligible group
                    $pimGroupMembers = Get-AllGroupMembers -GroupId $pimAssignment.principalId `
                        -AllPIMGroupEligibility $AllPIMGroupEligibility `
                        -ProcessedGroups $ProcessedGroups `
                        -MaxDepth $MaxDepth `
                        -CurrentDepth ($CurrentDepth + 1)
                    
                    foreach ($pimGroupMember in $pimGroupMembers) {
                        $pimGroupMember.GroupPath = $pimGroupMember.GroupPath + @("$($group.DisplayName) [PIM]")
                        $pimGroupMember.GroupIdPath = $pimGroupMember.GroupIdPath + @($GroupId)
                        $allMembers += $pimGroupMember
                    }
                }
                catch {
                    # Not a user or group, skip
                }
            }
        }
    }
    catch {
        Write-Log "Error getting members for group $GroupId : $($_.Exception.Message)" -Level "WARNING"
    }
    
    return $allMembers
}

#region Cross-tenant access (inbound MFA trust)

# A B2B guest with a privileged role performs MFA in their home tenant, so their authentication
# methods are not visible here and they appear as "No MFA". If inbound MFA trust is enabled for
# that home tenant, Conditional Access in this tenant accepts the home tenant's MFA claim.

$script:CrossTenantAccessPolicy = $null
$script:TenantIdCache = @{}

function Get-CrossTenantAccessPolicy {
    [CmdletBinding()]
    param([switch]$Force)

    if ($script:CrossTenantAccessPolicy -and -not $Force) { return $script:CrossTenantAccessPolicy }

    $policy = [PSCustomObject]@{
        Available          = $false
        DefaultMfaAccepted = $false
        Partners           = @{}
        Error              = $null
    }

    try {
        $default = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default' -ErrorAction Stop
        $policy.DefaultMfaAccepted = [bool]$default.inboundTrust.isMfaAccepted

        $uri = 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners'
        while ($uri) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            foreach ($partner in $page.value) {
                if (-not $partner.tenantId) { continue }
                # A null inboundTrust (or null isMfaAccepted) means the partner inherits the default.
                $inherits = ($null -eq $partner.inboundTrust) -or ($null -eq $partner.inboundTrust.isMfaAccepted)
                $policy.Partners[$partner.tenantId.ToString().ToLower()] = [PSCustomObject]@{
                    TenantId          = $partner.tenantId.ToString()
                    MfaAccepted       = if ($inherits) { $policy.DefaultMfaAccepted } else { [bool]$partner.inboundTrust.isMfaAccepted }
                    InheritsDefault   = $inherits
                    IsServiceProvider = [bool]$partner.isServiceProvider
                }
            }
            $uri = $page.'@odata.nextLink'
        }

        $policy.Available = $true
    }
    catch {
        $policy.Error = $_.Exception.Message
    }

    $script:CrossTenantAccessPolicy = $policy
    return $policy
}

function Get-ExternalUserDomain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$UserPrincipalName,
        [AllowEmptyString()][AllowNull()][string]$Mail
    )

    # B2B guest UPNs encode the invited address as alice.smith_contoso.com#EXT#@host.onmicrosoft.com
    if ($UserPrincipalName -match '^(?<local>.+)#EXT#@') {
        if ($Matches['local'] -match '_(?<domain>[^_@]+\.[^_@]+)$') {
            return $Matches['domain'].ToLower()
        }
    }

    if ($Mail -and $Mail -match '@') { return ($Mail -split '@')[-1].Trim().ToLower() }
    if ($UserPrincipalName -and $UserPrincipalName -match '@') { return ($UserPrincipalName -split '@')[-1].Trim().ToLower() }

    return $null
}

function Resolve-TenantIdFromDomain {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Domain)

    # Reject anything that is not a plain hostname so it cannot alter the request URL.
    if ([string]::IsNullOrWhiteSpace($Domain) -or $Domain -notmatch '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$') {
        return $null
    }

    $key = $Domain.ToLower()
    if ($script:TenantIdCache.ContainsKey($key)) { return $script:TenantIdCache[$key] }

    $info = $null
    try {
        $response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByDomainName(domainName='$key')" -ErrorAction Stop
        if ($response.tenantId) {
            $info = [PSCustomObject]@{
                TenantId    = $response.tenantId.ToString()
                DisplayName = $response.displayName
                Domain      = $key
            }
        }
    }
    catch {
        # Guests from Google, Microsoft accounts or one-time passcode have no resolvable Entra tenant.
        Write-Verbose "Tenant lookup failed for '$key': $($_.Exception.Message)"
    }

    $script:TenantIdCache[$key] = $info
    return $info
}

function Get-CrossTenantMfaTrust {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$UserPrincipalName,
        [AllowEmptyString()][AllowNull()][string]$Mail,
        [AllowEmptyString()][AllowNull()][string]$UserType,
        [PSCustomObject]$Policy
    )

    $result = [PSCustomObject]@{
        Status       = 'N/A'
        HomeDomain   = $null
        HomeTenantId = $null
        HomeTenant   = $null
        Source       = $null
    }

    if ($UserType -ne 'Guest') { return $result }

    if (-not $Policy) { $Policy = Get-CrossTenantAccessPolicy }
    if (-not $Policy.Available) { $result.Status = 'Unknown'; return $result }

    $domain = Get-ExternalUserDomain -UserPrincipalName $UserPrincipalName -Mail $Mail
    if (-not $domain) { $result.Status = 'Unknown'; return $result }
    $result.HomeDomain = $domain

    $tenant = Resolve-TenantIdFromDomain -Domain $domain
    if (-not $tenant) {
        $result.Status = 'Unknown'
        $result.HomeTenant = $domain
        return $result
    }

    $result.HomeTenantId = $tenant.TenantId
    $result.HomeTenant = if ($tenant.DisplayName) { $tenant.DisplayName } else { $domain }

    $partner = $Policy.Partners[$tenant.TenantId.ToLower()]
    if ($partner) {
        $result.Source = if ($partner.InheritsDefault) { 'Default' } else { 'Partner' }
        $result.Status = if ($partner.MfaAccepted) { 'Trusted' } else { 'Not trusted' }
    }
    else {
        $result.Source = 'Default'
        $result.Status = if ($Policy.DefaultMfaAccepted) { 'Trusted' } else { 'Not trusted' }
    }

    return $result
}

#endregion

#region HTML Report

function Get-PrivilegedAccountRiskAssessment {
    param(
        [Parameter(Mandatory)][AllowNull()]$MFAStatus,
        [Parameter(Mandatory)][AllowNull()]$AUProtection,
        [AllowNull()]$MFATrust
    )

    if ($null -eq $MFAStatus -or $null -eq $MFAStatus.MFACapable) {
        return @{ Level = 'Unknown'; Notes = 'MFA status unavailable (missing permission or restricted AU access)' }
    }

    $hasPhone = ($MFAStatus.HasPhone -eq $true)
    $auProtected = ($AUProtection -and $AUProtection.IsProtected -eq $true)

    if ($MFAStatus.MFACapable -eq $false) {
        if ($MFATrust -and $MFATrust.Status -eq 'Trusted') {
            return @{ Level = 'Medium'; Notes = "No MFA in this tenant, but inbound MFA trust accepts home tenant MFA ($($MFATrust.HomeTenant))" }
        }
        return @{ Level = 'Critical'; Notes = 'No MFA method registered on a privileged account' }
    }
    if ($hasPhone -and -not $auProtected) {
        return @{ Level = 'High'; Notes = 'Phone/SMS MFA (SIM-swap risk) and no restricted AU protection' }
    }
    if ($hasPhone) {
        return @{ Level = 'Medium'; Notes = 'Phone/SMS MFA is vulnerable to SIM swapping' }
    }
    if (-not $auProtected) {
        return @{ Level = 'Medium'; Notes = 'Not protected by a restricted administrative unit' }
    }
    return @{ Level = 'Low'; Notes = 'Strong MFA and restricted AU protection' }
}

function Get-FilteredGroupBasedRoles {
    param([Parameter(Mandatory)][AllowNull()]$Account)

    $groupRoles = @($Account.GroupBasedRoles)
    $pimGroupRoles = @($Account.PIMGroupEligibleRoles)
    $filtered = @()

    foreach ($role in $groupRoles) {
        # "PIM Group Active Member" is only meaningful when the group grants no real role on its own
        if ($role.RoleName -eq 'PIM Group Active Member') {
            $grantsActualRoles = $false
            foreach ($otherRole in ($groupRoles + $pimGroupRoles)) {
                if ($otherRole.RoleName -eq 'PIM Group Active Member') { continue }
                if ($otherRole.GroupName -eq $role.GroupName -or
                    $otherRole.GroupName -like "$($role.GroupName) *" -or
                    $otherRole.GroupName -like "$($role.GroupName) → *") {
                    $grantsActualRoles = $true
                    break
                }
            }
            if ($grantsActualRoles) { continue }
        }
        $filtered += $role
    }

    return $filtered
}

function New-PrivilegedAccountHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$PrivilegedUsers,
        [Parameter(Mandatory)][hashtable]$ServicePrincipals,
        [Parameter(Mandatory)][hashtable]$PrivilegedGroups,
        [Parameter(Mandatory)][hashtable]$RoleStats,
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$TenantName = 'Unknown',
        [bool]$IncludeGroupAssignments = $true
    )

    $methodTagMap = @{
        'Microsoft Authenticator' = 'Authenticator'
        'Phone'                   = 'Phone'
        'Email'                   = 'Email'
        'FIDO2 Security Key'      = 'FIDO2'
        'Windows Hello'           = 'Windows Hello'
        'Software OATH'           = 'Software OATH'
        'Temporary Access Pass'   = 'TAP'
    }

    $rows = @()

    foreach ($user in $PrivilegedUsers.Values) {
        $mfa = $user.MFAStatus
        $risk = Get-PrivilegedAccountRiskAssessment -MFAStatus $mfa -AUProtection $user.AUProtection -MFATrust $user.MFATrust

        $roles = @()
        foreach ($role in $user.ActiveRoles) { $roles += @{ n = $role.RoleName; t = 'Active'; g = '' } }
        foreach ($role in $user.EligibleRoles) { $roles += @{ n = $role.RoleName; t = 'PIM Eligible'; g = '' } }
        if ($IncludeGroupAssignments) {
            foreach ($role in (Get-FilteredGroupBasedRoles -Account $user)) {
                $roles += @{ n = $role.RoleName; t = 'Group-Based'; g = $role.GroupName }
            }
        }
        foreach ($role in $user.PIMGroupEligibleRoles) {
            $roles += @{ n = $role.RoleName; t = 'PIM Group Eligible'; g = $role.GroupName }
        }

        $methodsList = if ($mfa -and $mfa.MethodsList) { @($mfa.MethodsList) } else { @() }
        $methodTags = @($methodsList | ForEach-Object { if ($methodTagMap.ContainsKey($_)) { $methodTagMap[$_] } else { $_ } })

        $mfaStatusText = if ($null -eq $mfa -or $null -eq $mfa.MFACapable) { 'Unknown' }
        elseif ($mfa.MFACapable) { 'Enabled' } else { 'Disabled' }

        $rows += [PSCustomObject]@{
            displayName     = $user.DisplayName
            identifier      = $user.UserPrincipalName
            principalType   = 'User'
            accountStatus   = if ($user.AccountEnabled) { 'Enabled' } else { 'Disabled' }
            mfaStatus       = $mfaStatusText
            mfaMethods      = if ($methodTags.Count -gt 0) { $methodTags -join ', ' } else { '-' }
            methodTags      = $methodTags
            phoneNumbers    = if ($mfa -and $mfa.PhoneNumbers) { @($mfa.PhoneNumbers) -join ', ' } else { '' }
            auProtected     = if ($user.AUProtection -and $user.AUProtection.IsProtected) { 'Yes' } else { 'No' }
            auName          = if ($user.AUProtection) { [string]$user.AUProtection.AUName } else { '' }
            mfaTrust        = if ($user.MFATrust) { $user.MFATrust.Status } else { 'N/A' }
            homeTenant      = if ($user.MFATrust) { [string]$user.MFATrust.HomeTenant } else { '' }
            assignmentTags  = @($roles | ForEach-Object { $_.t } | Select-Object -Unique)
            roles           = $roles
            rolesText       = (@($roles | ForEach-Object { $_.n }) -join ', ')
            roleCount       = $roles.Count
            riskLevel       = $risk.Level
            riskNotes       = $risk.Notes
        }
    }

    foreach ($sp in $ServicePrincipals.Values) {
        $roles = @()
        foreach ($role in $sp.ActiveRoles) { $roles += @{ n = $role.RoleName; t = 'Active'; g = '' } }
        foreach ($role in $sp.EligibleRoles) { $roles += @{ n = $role.RoleName; t = 'PIM Eligible'; g = '' } }

        $rows += [PSCustomObject]@{
            displayName     = $sp.DisplayName
            identifier      = "App ID: $($sp.AppId)"
            principalType   = 'Service Principal'
            accountStatus   = 'N/A'
            mfaStatus       = 'N/A'
            mfaMethods      = '-'
            methodTags      = @()
            phoneNumbers    = ''
            auProtected     = 'N/A'
            auName          = ''
            mfaTrust        = 'N/A'
            homeTenant      = ''
            assignmentTags  = @($roles | ForEach-Object { $_.t } | Select-Object -Unique)
            roles           = $roles
            rolesText       = (@($roles | ForEach-Object { $_.n }) -join ', ')
            roleCount       = $roles.Count
            riskLevel       = 'N/A'
            riskNotes       = 'Service principal - secure with certificate credentials and workload identity CA'
        }
    }

    foreach ($group in $PrivilegedGroups.Values) {
        $roles = @()
        foreach ($role in $group.ActiveRoles) { $roles += @{ n = $role.RoleName; t = 'Active'; g = '' } }
        foreach ($role in $group.EligibleRoles) { $roles += @{ n = $role.RoleName; t = 'PIM Eligible'; g = '' } }

        $rows += [PSCustomObject]@{
            displayName     = $group.DisplayName
            identifier      = "$($group.MemberCount) members"
            principalType   = 'Role-Assignable Group'
            accountStatus   = 'N/A'
            mfaStatus       = 'N/A'
            mfaMethods      = '-'
            methodTags      = @()
            phoneNumbers    = ''
            auProtected     = 'N/A'
            auName          = ''
            mfaTrust        = 'N/A'
            homeTenant      = ''
            assignmentTags  = @($roles | ForEach-Object { $_.t } | Select-Object -Unique)
            roles           = $roles
            rolesText       = (@($roles | ForEach-Object { $_.n }) -join ', ')
            roleCount       = $roles.Count
            riskLevel       = 'N/A'
            riskNotes       = 'Role-assignable group - every member inherits the roles below'
        }
    }

    $roleRows = foreach ($role in $RoleStats.Values) {
        [PSCustomObject]@{
            roleName    = $role.RoleName
            type        = $role.Type
            active      = $role.ActiveCount
            eligible    = $role.EligibleCount
            groupBased  = $role.GroupBasedCount
            pimGroup    = $role.PIMGroupEligibleCount
            totalUsers  = $role.TotalUniqueUsers
        }
    }

    # JSON is valid JS, so it is emitted as-is; only "</" is broken up so data cannot end the <script> block
    $jsonData = $rows | ConvertTo-Json -Depth 5 -Compress
    if (-not $jsonData) { $jsonData = '[]' }
    if ($jsonData -notmatch '^\s*\[') { $jsonData = "[$jsonData]" }
    $jsonData = $jsonData -replace '</', '<\/'

    $jsonRoles = $roleRows | ConvertTo-Json -Depth 3 -Compress
    if (-not $jsonRoles) { $jsonRoles = '[]' }
    if ($jsonRoles -notmatch '^\s*\[') { $jsonRoles = "[$jsonRoles]" }
    $jsonRoles = $jsonRoles -replace '</', '<\/'

    $generatedDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $totalPrincipals = $rows.Count

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Entra ID Privileged Account Report - $TenantName - $generatedDate</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; padding: 20px; }
.header { background: linear-gradient(135deg, #1a237e, #0d47a1); color: white; padding: 30px; border-radius: 12px; margin-bottom: 20px; }
.header h1 { font-size: 1.8em; margin-bottom: 5px; }
.header .meta { opacity: 0.8; font-size: 0.9em; }
.filters { background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
.filters h3 { margin-bottom: 12px; color: #1a237e; }
.filter-row { display: flex; flex-wrap: wrap; gap: 12px; align-items: end; }
.filter-group { display: flex; flex-direction: column; }
.filter-group label { font-size: 0.8em; font-weight: 600; color: #555; margin-bottom: 4px; }
.filter-group select, .filter-group input { padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 0.9em; min-width: 140px; }
.filter-group input[type="text"] { min-width: 240px; }
.method-filters { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 10px; padding-top: 10px; border-top: 1px solid #eee; }
.method-filters label { font-size: 0.8em; font-weight: 600; color: #555; margin-right: 8px; }
.method-logic-toggle { display: inline-flex; align-items: center; gap: 6px; margin-left: 12px; padding: 4px 10px; background: #f5f5f5; border-radius: 16px; font-size: 0.75em; font-weight: 600; border: 1px solid #ddd; }
.method-logic-toggle span { padding: 2px 8px; border-radius: 10px; cursor: pointer; color: #777; }
.method-logic-toggle span.active { background: #1565c0; color: white; }
.method-logic-toggle span.disabled { opacity: 0.45; cursor: not-allowed; pointer-events: none; }
.method-chip { display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px; background: #e3f2fd; border-radius: 16px; font-size: 0.8em; cursor: pointer; user-select: none; border: 1px solid #bbdefb; }
.method-chip.active { background: #1565c0; color: white; border-color: #1565c0; }
.btn-reset { padding: 8px 16px; background: #e0e0e0; border: none; border-radius: 6px; cursor: pointer; font-size: 0.85em; font-weight: 600; }
.btn-reset:hover { background: #bdbdbd; }
.table-container { background: white; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); overflow: hidden; margin-bottom: 20px; }
.table-info { padding: 12px 20px; background: #fafafa; border-bottom: 1px solid #eee; font-size: 0.85em; color: #666; }
table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
thead { background: #1a237e; color: white; position: sticky; top: 0; }
th { padding: 12px 10px; text-align: left; cursor: pointer; user-select: none; white-space: nowrap; }
th:hover { background: #283593; }
th .sort-icon { margin-left: 4px; opacity: 0.5; }
th.sorted-asc .sort-icon::after { content: ' ▲'; opacity: 1; }
th.sorted-desc .sort-icon::after { content: ' ▼'; opacity: 1; }
td { padding: 10px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
tr:hover { background: #f5f5f5; }
tr.risk-critical { border-left: 4px solid #d32f2f; }
tr.risk-high { border-left: 4px solid #f57c00; }
tr.risk-medium { border-left: 4px solid #fbc02d; }
tr.risk-low { border-left: 4px solid #388e3c; }
tr.risk-unknown { border-left: 4px solid #9e9e9e; }
tr.risk-na { border-left: 4px solid #9e9e9e; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.8em; font-weight: 600; }
.badge-critical { background: #ffebee; color: #c62828; }
.badge-high { background: #fff3e0; color: #e65100; }
.badge-medium { background: #fffde7; color: #f57f17; }
.badge-low { background: #e8f5e9; color: #2e7d32; }
.badge-unknown { background: #f5f5f5; color: #616161; }
.badge-na { background: #f5f5f5; color: #616161; }
.badge-enabled { background: #e8f5e9; color: #2e7d32; }
.badge-disabled { background: #ffebee; color: #c62828; }
.badge-user { background: #f3e5f5; color: #6a1b9a; }
.badge-sp { background: #e0f7fa; color: #00695c; }
.badge-group { background: #e3f2fd; color: #1565c0; }
.badge-yes { background: #e8f5e9; color: #2e7d32; }
.badge-no { background: #ffebee; color: #c62828; }
.role-chip { display: inline-block; padding: 2px 7px; margin: 1px 2px 1px 0; border-radius: 9px; font-size: 0.92em; white-space: nowrap; }
.role-active { background: #ffebee; color: #b71c1c; }
.role-pim { background: #f3e5f5; color: #6a1b9a; }
.role-groupbased { background: #e3f2fd; color: #0d47a1; }
.role-pimgroup { background: #ede7f6; color: #4527a0; }
.role-cell { min-width: 300px; max-width: 460px; }
.notes-cell { min-width: 260px; }
#principalTable { min-width: 1500px; }
.muted { color: #757575; font-size: 0.85em; }
.footer { margin-top: 20px; text-align: center; font-size: 0.8em; color: #999; }
.pii-notice { background: #e8f4fd; border: 1px solid #4f83cc; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px; font-size: 0.85em; color: #17324d; display: flex; align-items: flex-start; gap: 12px; }
.pii-notice .pii-icon { font-size: 1.4em; flex-shrink: 0; line-height: 1.2; color: #1565c0; }
.pii-notice .pii-text strong { display: block; margin-bottom: 4px; color: #0d47a1; }
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
.pie-row { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
.pie-box-title { font-size: 0.9em; font-weight: 700; color: #1a237e; margin-bottom: 10px; }
.pie-box-inner { display: flex; align-items: center; gap: 16px; }
.pie-legend { display: flex; flex-direction: column; gap: 5px; }
.section-title { font-size: 0.9em; font-weight: 700; color: #1a237e; padding: 16px 20px 0; }
</style>
</head>
<body>
<div class="header">
<h1>Entra ID Privileged Account Report</h1>
<div class="meta">Tenant: $TenantName | Generated: $generatedDate | Privileged Principals: $totalPrincipals</div>
</div>

<div class="pii-notice" id="piiNotice">
  <span class="pii-icon">&#9888;</span>
  <div class="pii-text">
    <strong>Data Privacy Notice (GDPR)</strong>
    This report contains personal data and a complete map of administrative privilege in the tenant.
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
      <div class="summary-col-header" id="standingColHeader">&#128737; Standing admins</div>
      <div class="summary-mini-cards" id="standingCards"></div>
    </div>
    <div class="summary-col">
      <div class="summary-col-header" id="pimColHeader">&#9203; PIM-eligible only</div>
      <div class="summary-mini-cards" id="pimCards"></div>
    </div>
  </div>
  <div class="summary-footer" id="summaryFooter"></div>
</div>

<div class="summary-block">
  <div class="pie-row">
    <div>
      <div class="pie-box-title">Risk Summary (privileged users)</div>
      <div class="pie-box-inner">
        <svg id="riskPie" width="90" height="90" viewBox="-1 -1 2 2" style="flex-shrink:0"></svg>
        <div class="pie-legend" id="riskPieLegend"></div>
      </div>
    </div>
    <div>
      <div class="pie-box-title">Privilege Paths (role assignments)</div>
      <div class="pie-box-inner">
        <svg id="pathPie" width="90" height="90" viewBox="-1 -1 2 2" style="flex-shrink:0"></svg>
        <div class="pie-legend" id="pathPieLegend"></div>
      </div>
    </div>
  </div>
</div>

<div class="filters">
<h3>Filters</h3>
<div class="filter-row">
<div class="filter-group"><label>Search (Name / UPN / Role / Group)</label><input type="text" id="searchBox" placeholder="Name, UPN, role, or group"></div>
<div class="filter-group"><label>Risk Level</label><select id="filterRisk"><option value="">All</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option><option value="Unknown">Unknown</option><option value="N/A">N/A</option></select></div>
<div class="filter-group"><label>Principal Type</label><select id="filterType"><option value="">All</option><option value="User">User</option><option value="Service Principal">Service Principal</option><option value="Role-Assignable Group">Role-Assignable Group</option></select></div>
<div class="filter-group"><label>Account Status</label><select id="filterStatus"><option value="">All</option><option value="Enabled">Enabled</option><option value="Disabled">Disabled</option><option value="N/A">N/A</option></select></div>
<div class="filter-group"><label>MFA Status</label><select id="filterMfa"><option value="">All</option><option value="Enabled">Enabled</option><option value="Disabled">Disabled</option><option value="Unknown">Unknown</option><option value="N/A">N/A</option></select></div>
<div class="filter-group"><label>Restricted AU</label><select id="filterAu"><option value="">All</option><option value="Yes">Protected</option><option value="No">Not protected</option><option value="N/A">N/A</option></select></div>
<div class="filter-group"><label>Assignment Type</label><select id="filterAssignment"><option value="">All</option><option value="Active">Active</option><option value="PIM Eligible">PIM Eligible</option><option value="Group-Based">Group-Based</option><option value="PIM Group Eligible">PIM Group Eligible</option></select></div>
<div class="filter-group"><label>Role</label><select id="filterRole"><option value="">All</option></select></div>
<div class="filter-group"><button class="btn-reset" onclick="resetFilters()">Reset All</button></div>
</div>
<div class="method-filters">
<label>MFA Methods:</label>
<span class="method-chip" data-method="Authenticator" onclick="toggleMethod(this)">Authenticator</span>
<span class="method-chip" data-method="Phone" onclick="toggleMethod(this)">Phone</span>
<span class="method-chip" data-method="FIDO2" onclick="toggleMethod(this)">FIDO2</span>
<span class="method-chip" data-method="Windows Hello" onclick="toggleMethod(this)">Windows Hello</span>
<span class="method-chip" data-method="Software OATH" onclick="toggleMethod(this)">Software OATH</span>
<span class="method-chip" data-method="Email" onclick="toggleMethod(this)">Email</span>
<span class="method-chip" data-method="TAP" onclick="toggleMethod(this)">TAP</span>
<div class="method-logic-toggle"><span id="modeOr" class="active" onclick="setMethodMode('or')">OR</span><span id="modeAnd" onclick="setMethodMode('and')">AND</span></div>
<label class="method-only-toggle" style="margin-left:10px;font-size:0.78em;color:#555"><input type="checkbox" id="filterOnlySelectedMethods"> Only selected methods</label>
</div>
</div>

<div class="table-container">
<div class="table-info">Showing <span id="visibleCount">0</span> of <span id="totalCount">0</span> privileged principals</div>
<div style="overflow-x:auto; max-height: 70vh; overflow-y: auto;">
<table id="principalTable">
<thead>
<tr>
<th data-col="displayName" onclick="sortTable('displayName')">Display Name<span class="sort-icon"></span></th>
<th data-col="identifier" onclick="sortTable('identifier')">Identifier<span class="sort-icon"></span></th>
<th data-col="principalType" onclick="sortTable('principalType')">Type<span class="sort-icon"></span></th>
<th data-col="accountStatus" onclick="sortTable('accountStatus')">Account<span class="sort-icon"></span></th>
<th data-col="mfaStatus" onclick="sortTable('mfaStatus')">MFA<span class="sort-icon"></span></th>
<th data-col="mfaMethods" onclick="sortTable('mfaMethods')">MFA Methods<span class="sort-icon"></span></th>
<th data-col="auProtected" onclick="sortTable('auProtected')" title="Protected by a restricted administrative unit">Restricted AU<span class="sort-icon"></span></th>
<th data-col="roleCount" onclick="sortTable('roleCount')">#<span class="sort-icon"></span></th>
<th data-col="rolesText" onclick="sortTable('rolesText')">Roles<span class="sort-icon"></span></th>
<th data-col="mfaTrust" onclick="sortTable('mfaTrust')" title="Cross-tenant inbound MFA trust for a guest's home tenant">MFA Trust<span class="sort-icon"></span></th>
<th data-col="riskLevel" onclick="sortTable('riskLevel')">Risk<span class="sort-icon"></span></th>
<th data-col="riskNotes" onclick="sortTable('riskNotes')">Risk Notes<span class="sort-icon"></span></th>
</tr>
</thead>
<tbody id="tableBody"></tbody>
</table>
</div>
</div>

<div class="table-container">
<div class="section-title">Role Distribution</div>
<div class="table-info">All directory roles with at least one assignment</div>
<div style="overflow-x:auto; max-height: 50vh; overflow-y: auto;">
<table id="roleTable">
<thead>
<tr>
<th data-rcol="roleName" onclick="sortRoles('roleName')">Role<span class="sort-icon"></span></th>
<th data-rcol="type" onclick="sortRoles('type')">Type<span class="sort-icon"></span></th>
<th data-rcol="active" onclick="sortRoles('active')">Active<span class="sort-icon"></span></th>
<th data-rcol="eligible" onclick="sortRoles('eligible')">PIM Eligible<span class="sort-icon"></span></th>
<th data-rcol="groupBased" onclick="sortRoles('groupBased')">Group-Based<span class="sort-icon"></span></th>
<th data-rcol="pimGroup" onclick="sortRoles('pimGroup')">PIM Group<span class="sort-icon"></span></th>
<th data-rcol="totalUsers" onclick="sortRoles('totalUsers')">Unique Principals<span class="sort-icon"></span></th>
</tr>
</thead>
<tbody id="roleTableBody"></tbody>
</table>
</div>
</div>

<div class="footer">
Generated by I.D.E.A. 002 - Entra ID Privileged Account Report | Per-Torben Sørensen
</div>

<script>
const DATA = $jsonData;
const ROLES = $jsonRoles;
let sortCol = 'riskLevel';
let sortDir = 'asc';
let roleSortCol = 'totalUsers';
let roleSortDir = 'desc';
let activeMethodFilters = [];
let methodFilterMode = 'or';
let onlySelectedMethods = false;
const riskOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4, 'N/A': 5 };
const roleClassMap = { 'Active': 'role-active', 'PIM Eligible': 'role-pim', 'Group-Based': 'role-groupbased', 'PIM Group Eligible': 'role-pimgroup' };
const typeBadgeMap = { 'User': 'badge-user', 'Service Principal': 'badge-sp', 'Role-Assignable Group': 'badge-group' };

function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function riskKey(r) { return (r === 'N/A' ? 'na' : r.toLowerCase()); }

function renderTable() {
    const search = document.getElementById('searchBox').value.toLowerCase();
    const fRisk = document.getElementById('filterRisk').value;
    const fType = document.getElementById('filterType').value;
    const fStatus = document.getElementById('filterStatus').value;
    const fMfa = document.getElementById('filterMfa').value;
    const fAu = document.getElementById('filterAu').value;
    const fAssign = document.getElementById('filterAssignment').value;
    const fRole = document.getElementById('filterRole').value;

    const filtered = DATA.filter(r => {
        if (search) {
            const hay = (r.displayName + ' ' + r.identifier + ' ' + r.rolesText + ' ' + r.roles.map(x => x.g).join(' ')).toLowerCase();
            if (!hay.includes(search)) return false;
        }
        if (fRisk && r.riskLevel !== fRisk) return false;
        if (fType && r.principalType !== fType) return false;
        if (fStatus && r.accountStatus !== fStatus) return false;
        if (fMfa && r.mfaStatus !== fMfa) return false;
        if (fAu && r.auProtected !== fAu) return false;
        if (fAssign && !r.assignmentTags.includes(fAssign)) return false;
        if (fRole && !r.roles.some(x => x.n === fRole)) return false;
        if (activeMethodFilters.length > 0) {
            const userMethods = Array.isArray(r.methodTags) ? r.methodTags : [];
            if (onlySelectedMethods && !userMethods.every(m => activeMethodFilters.includes(m))) return false;
            if (methodFilterMode === 'and') {
                if (!activeMethodFilters.every(m => userMethods.includes(m))) return false;
            } else if (!activeMethodFilters.some(m => userMethods.includes(m))) return false;
        }
        return true;
    });

    filtered.sort((a, b) => {
        let va = a[sortCol];
        let vb = b[sortCol];
        if (sortCol === 'riskLevel') { va = riskOrder[va] ?? 9; vb = riskOrder[vb] ?? 9; }
        else if (sortCol === 'roleCount') { va = va || 0; vb = vb || 0; }
        else { va = (va || '').toString().toLowerCase(); vb = (vb || '').toString().toLowerCase(); }
        if (va < vb) return sortDir === 'asc' ? -1 : 1;
        if (va > vb) return sortDir === 'asc' ? 1 : -1;
        return 0;
    });

    document.getElementById('visibleCount').textContent = filtered.length;
    document.getElementById('totalCount').textContent = DATA.length;

    document.getElementById('tableBody').innerHTML = filtered.map(r => {
        const k = riskKey(r.riskLevel);
        const roleHtml = r.roles.length === 0
            ? '<span class="muted">No direct assignments</span>'
            : r.roles.map(x => '<span class="role-chip ' + (roleClassMap[x.t] || '') + '" title="' + esc(x.t + (x.g ? ' via ' + x.g : '')) + '">' + esc(x.n) + (x.g ? ' <span class="muted">&#8594; ' + esc(x.g) + '</span>' : '') + '</span>').join('');
        const auHtml = r.auProtected === 'N/A'
            ? '<span class="badge badge-na">N/A</span>'
            : '<span class="badge badge-' + (r.auProtected === 'Yes' ? 'yes' : 'no') + '">' + r.auProtected + '</span>' + (r.auName ? ' <span class="muted">' + esc(r.auName) + '</span>' : '');
        return '<tr class="risk-' + k + '">' +
            '<td>' + esc(r.displayName) + '</td>' +
            '<td>' + esc(r.identifier) + '</td>' +
            '<td><span class="badge ' + (typeBadgeMap[r.principalType] || 'badge-na') + '">' + esc(r.principalType) + '</span></td>' +
            '<td>' + (r.accountStatus === 'N/A' ? '<span class="badge badge-na">N/A</span>' : '<span class="badge badge-' + r.accountStatus.toLowerCase() + '">' + r.accountStatus + '</span>') + '</td>' +
            '<td>' + (r.mfaStatus === 'Enabled' || r.mfaStatus === 'Disabled' ? '<span class="badge badge-' + r.mfaStatus.toLowerCase() + '">' + r.mfaStatus + '</span>' : '<span class="badge badge-na">' + esc(r.mfaStatus) + '</span>') + '</td>' +
            '<td>' + esc(r.mfaMethods) + (r.phoneNumbers ? '<div class="muted">' + esc(r.phoneNumbers) + '</div>' : '') + '</td>' +
            '<td>' + auHtml + '</td>' +
            '<td>' + r.roleCount + '</td>' +
            '<td class="role-cell">' + roleHtml + '</td>' +
            '<td>' + esc(r.mfaTrust === 'N/A' ? '' : r.mfaTrust) + (r.homeTenant ? ' <span class="muted">(' + esc(r.homeTenant) + ')</span>' : '') + '</td>' +
            '<td><span class="badge badge-' + k + '">' + esc(r.riskLevel) + '</span></td>' +
            '<td class="notes-cell">' + esc(r.riskNotes) + '</td></tr>';
    }).join('');

    document.querySelectorAll('#principalTable th').forEach(th => th.classList.remove('sorted-asc', 'sorted-desc'));
    const th = document.querySelector('#principalTable th[data-col="' + sortCol + '"]');
    if (th) th.classList.add(sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc');
}

function renderRoleTable() {
    const sorted = ROLES.slice().sort((a, b) => {
        let va = a[roleSortCol];
        let vb = b[roleSortCol];
        if (typeof va === 'string') { va = va.toLowerCase(); vb = (vb || '').toLowerCase(); }
        if (va < vb) return roleSortDir === 'asc' ? -1 : 1;
        if (va > vb) return roleSortDir === 'asc' ? 1 : -1;
        return 0;
    });
    document.getElementById('roleTableBody').innerHTML = sorted.map(r =>
        '<tr><td>' + esc(r.roleName) + '</td><td>' + esc(r.type) + '</td><td>' + r.active + '</td><td>' + r.eligible +
        '</td><td>' + r.groupBased + '</td><td>' + r.pimGroup + '</td><td><strong>' + r.totalUsers + '</strong></td></tr>'
    ).join('');

    document.querySelectorAll('#roleTable th').forEach(th => th.classList.remove('sorted-asc', 'sorted-desc'));
    const th = document.querySelector('#roleTable th[data-rcol="' + roleSortCol + '"]');
    if (th) th.classList.add(roleSortDir === 'asc' ? 'sorted-asc' : 'sorted-desc');
}

function sortTable(col) {
    if (sortCol === col) { sortDir = sortDir === 'asc' ? 'desc' : 'asc'; }
    else { sortCol = col; sortDir = 'asc'; }
    renderTable();
}

function sortRoles(col) {
    if (roleSortCol === col) { roleSortDir = roleSortDir === 'asc' ? 'desc' : 'asc'; }
    else { roleSortCol = col; roleSortDir = (col === 'roleName' || col === 'type') ? 'asc' : 'desc'; }
    renderRoleTable();
}

function toggleMethod(el) {
    const m = el.dataset.method;
    el.classList.toggle('active');
    if (el.classList.contains('active')) { activeMethodFilters.push(m); }
    else { activeMethodFilters = activeMethodFilters.filter(x => x !== m); }
    updateMethodModeToggle();
    renderTable();
}

function setMethodMode(mode) {
    if (activeMethodFilters.length < 2) { return; }
    methodFilterMode = mode;
    document.getElementById('modeOr').classList.toggle('active', mode === 'or');
    document.getElementById('modeAnd').classList.toggle('active', mode === 'and');
    renderTable();
}

function updateMethodModeToggle() {
    const allowMultiMode = activeMethodFilters.length >= 2;
    const modeOrEl = document.getElementById('modeOr');
    const modeAndEl = document.getElementById('modeAnd');
    modeOrEl.classList.toggle('disabled', !allowMultiMode);
    modeAndEl.classList.toggle('disabled', !allowMultiMode);
    if (!allowMultiMode) {
        methodFilterMode = 'or';
        modeOrEl.classList.add('active');
        modeAndEl.classList.remove('active');
    }
}

function populateRoleFilter() {
    const names = [...new Set(DATA.flatMap(r => r.roles.map(x => x.n)))].sort();
    const sel = document.getElementById('filterRole');
    names.forEach(n => {
        const o = document.createElement('option');
        o.value = n; o.textContent = n;
        sel.appendChild(o);
    });
}

function drawPie(svgId, legendId, segs) {
    const svgEl = document.getElementById(svgId);
    const lgdEl = document.getElementById(legendId);
    const tot = segs.reduce((s, d) => s + d.v, 0);
    if (!svgEl || !lgdEl || tot === 0) return;
    let ang = -Math.PI / 2, paths = '', lgd = '';
    segs.forEach(s => {
        const frac = s.v / tot;
        const end = ang + frac * 2 * Math.PI;
        if (frac >= 0.9999) {
            paths += '<circle cx="0" cy="0" r="1" fill="' + s.c + '"/>';
        } else {
            const la = frac > 0.5 ? 1 : 0;
            const x1 = Math.cos(ang).toFixed(5), y1 = Math.sin(ang).toFixed(5);
            const x2 = Math.cos(end).toFixed(5), y2 = Math.sin(end).toFixed(5);
            paths += '<path d="M0,0 L' + x1 + ',' + y1 + ' A1,1,0,' + la + ',1,' + x2 + ',' + y2 + ' Z" fill="' + s.c + '" stroke="white" stroke-width="0.03"/>';
        }
        lgd += '<div style="display:flex;align-items:center;gap:5px;font-size:0.78em;line-height:1.5">' +
               '<span style="width:10px;height:10px;border-radius:2px;background:' + s.c + ';flex-shrink:0;display:inline-block"></span>' +
               esc(s.l) + ': <strong>' + s.v + '</strong></div>';
        ang = end;
    });
    svgEl.innerHTML = paths;
    lgdEl.innerHTML = lgd;
}

function renderSummary() {
    const isPhishRes = m => m.includes('FIDO2') || m.includes('Windows Hello');
    const hasAuthApp = m => m.includes('Authenticator');
    const hasWeak = m => m.includes('Phone') || m.includes('Email');
    const users = DATA.filter(r => r.principalType === 'User' && r.accountStatus === 'Enabled');
    const total = users.length;

    const barNoMFA = users.filter(r => r.mfaStatus === 'Disabled').length;
    const barUnknown = users.filter(r => r.mfaStatus === 'Unknown').length;
    const barWeak = users.filter(r => r.mfaStatus === 'Enabled' && hasWeak(r.methodTags) && !isPhishRes(r.methodTags) && !hasAuthApp(r.methodTags)).length;
    const barAuth = users.filter(r => r.mfaStatus === 'Enabled' && hasAuthApp(r.methodTags) && !isPhishRes(r.methodTags)).length;
    const barPhish = users.filter(r => r.mfaStatus === 'Enabled' && isPhishRes(r.methodTags)).length;
    const barOther = total - barNoMFA - barUnknown - barWeak - barAuth - barPhish;
    const pct = n => total > 0 ? (n / total * 100).toFixed(1) : 0;
    const segments = [
        { n: barNoMFA, color: '#d32f2f', label: 'No MFA' },
        { n: barWeak, color: '#f57c00', label: 'Weak only (phone/email)' },
        { n: barAuth, color: '#fbc02d', label: 'Authenticator only' },
        { n: barPhish, color: '#388e3c', label: 'Phishing-resistant' },
        { n: barUnknown, color: '#9e9e9e', label: 'Unknown' }
    ];
    if (barOther > 0) segments.push({ n: barOther, color: '#607d8b', label: 'Other MFA' });
    document.getElementById('mfaBarLabel').textContent = 'MFA method distribution - enabled privileged users (' + total + ')';
    document.getElementById('mfaBar').innerHTML = segments.filter(s => s.n > 0).map(s =>
        '<div class="mfa-bar-segment" style="width:' + pct(s.n) + '%;background:' + s.color + '" title="' + s.label + ': ' + s.n + '"></div>'
    ).join('');
    document.getElementById('mfaBarLegend').innerHTML = segments.filter(s => s.n > 0).map(s =>
        '<span class="mfa-bar-legend-item"><span class="mfa-bar-legend-swatch" style="background:' + s.color + '"></span>' + s.label + ': <strong>' + s.n + '</strong> (' + pct(s.n) + '%)</span>'
    ).join('');

    const mcStyles = {
        bad: n => n > 0 ? { bg: '#ffebee', fg: '#c62828' } : { bg: '#e8f5e9', fg: '#388e3c' },
        warn: n => n > 0 ? { bg: '#fff3e0', fg: '#f57c00' } : { bg: '#e8f5e9', fg: '#388e3c' }
    };
    const mc = (val, tot, lbl, s) => '<div class="summary-mini-card" style="background:' + s.bg + '"><div class="smc-value" style="color:' + s.fg + '">' + val + '<span style="font-size:0.58em;font-weight:400;color:#888"> / ' + tot + '</span></div><div class="smc-label">' + lbl + '</div></div>';

    const isStanding = r => r.assignmentTags.includes('Active') || r.assignmentTags.includes('Group-Based');
    const standing = users.filter(isStanding);
    const pimOnly = users.filter(r => !isStanding(r) && r.assignmentTags.length > 0);

    const fillCol = (headerId, cardsId, icon, label, set) => {
        const noMfa = set.filter(r => r.mfaStatus === 'Disabled').length;
        const phone = set.filter(r => r.methodTags.includes('Phone')).length;
        const noAu = set.filter(r => r.auProtected === 'No').length;
        document.getElementById(headerId).innerHTML = icon + ' ' + label + ' (' + set.length + ')';
        document.getElementById(cardsId).innerHTML =
            mc(noMfa, set.length, 'Without MFA', mcStyles.bad(noMfa)) +
            mc(phone, set.length, 'Phone MFA', mcStyles.warn(phone)) +
            mc(noAu, set.length, 'No restricted AU', mcStyles.warn(noAu));
    };
    fillCol('standingColHeader', 'standingCards', '&#128737;', 'Standing admins', standing);
    fillCol('pimColHeader', 'pimCards', '&#9203;', 'PIM-eligible only', pimOnly);

    const sps = DATA.filter(r => r.principalType === 'Service Principal').length;
    const grps = DATA.filter(r => r.principalType === 'Role-Assignable Group').length;
    const disabled = DATA.filter(r => r.principalType === 'User' && r.accountStatus === 'Disabled').length;
    document.getElementById('summaryFooter').innerHTML = '<span>Service principals with roles: <strong>' + sps +
        '</strong> \xb7 Role-assignable groups: <strong>' + grps +
        '</strong> \xb7 Disabled privileged users: <strong>' + disabled +
        '</strong> \xb7 Roles in use: <strong>' + ROLES.length + '</strong></span>';

    const rCounts = {};
    DATA.filter(r => r.principalType === 'User').forEach(r => { rCounts[r.riskLevel] = (rCounts[r.riskLevel] || 0) + 1; });
    const rColors = { Critical: '#d32f2f', High: '#f57c00', Medium: '#fbc02d', Low: '#388e3c', Unknown: '#9e9e9e' };
    drawPie('riskPie', 'riskPieLegend',
        ['Critical', 'High', 'Medium', 'Low', 'Unknown'].filter(k => rCounts[k]).map(k => ({ l: k, v: rCounts[k], c: rColors[k] })));

    const pCounts = {};
    DATA.forEach(r => r.roles.forEach(x => { pCounts[x.t] = (pCounts[x.t] || 0) + 1; }));
    const pColors = { 'Active': '#c62828', 'PIM Eligible': '#6a1b9a', 'Group-Based': '#1565c0', 'PIM Group Eligible': '#4527a0' };
    drawPie('pathPie', 'pathPieLegend',
        ['Active', 'PIM Eligible', 'Group-Based', 'PIM Group Eligible'].filter(k => pCounts[k]).map(k => ({ l: k, v: pCounts[k], c: pColors[k] })));
}

function resetFilters() {
    ['searchBox', 'filterRisk', 'filterType', 'filterStatus', 'filterMfa', 'filterAu', 'filterAssignment', 'filterRole']
        .forEach(id => { document.getElementById(id).value = ''; });
    document.getElementById('filterOnlySelectedMethods').checked = false;
    activeMethodFilters = [];
    methodFilterMode = 'or';
    onlySelectedMethods = false;
    document.getElementById('modeOr').classList.add('active');
    document.getElementById('modeAnd').classList.remove('active');
    document.querySelectorAll('.method-chip').forEach(c => c.classList.remove('active'));
    updateMethodModeToggle();
    renderTable();
}

document.getElementById('searchBox').addEventListener('input', renderTable);
document.querySelectorAll('.filters select').forEach(s => s.addEventListener('change', renderTable));
document.getElementById('filterOnlySelectedMethods').addEventListener('change', function (e) {
    onlySelectedMethods = e.target.checked;
    renderTable();
});
populateRoleFilter();
updateMethodModeToggle();
renderTable();
renderRoleTable();
renderSummary();
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Log "HTML report exported to: $OutputPath" -Level "SUCCESS"
}

#endregion

try {
    Write-Log "Starting Privileged Account Report generation" -Level "INFO"
    
    # Required Graph API scopes
    $requiredScopes = @(
        "User.Read.All",
        "Directory.Read.All",
        "RoleManagement.Read.Directory",
        "RoleEligibilitySchedule.Read.Directory",
        "UserAuthenticationMethod.Read.All",
        "PrivilegedAccess.Read.AzureADGroup",
        "Policy.Read.All",
        "CrossTenantInformation.ReadBasic.All"
    )
    
    Write-Log "Connecting to Microsoft Graph..." -Level "INFO"
    if ($UseInteractiveAuth) {
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        $context = Get-MgContext
    }
    else {
        # Check if already connected (via Connect-ToGraphCert.ps1 or previous session)
        $context = Get-MgContext
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Run ..\Connect-ToGraphCert.ps1 first or use -UseInteractiveAuth"
        }
    }
    
    if (-not $context -or -not $context.TenantId) {
        throw "Failed to establish Microsoft Graph context"
    }
    Write-Log "✓ Connected to tenant: $($context.TenantId)" -Level "SUCCESS"
    
    # Validate required permissions
    Write-Log "Validating required permissions..." -Level "INFO"
    
    $missingPermissions = @()
    
    # For app-only auth, check granted app roles; for delegated, check scopes
    if ($context.AuthType -eq 'AppOnly') {
        Write-Log "Using app-only authentication - testing API access..." -Level "INFO"
        
        # Test each permission by attempting API calls
        $permissionTests = @{
            "User.Read.All" = { 
                try { Get-MgUser -Top 1 -ErrorAction Stop | Out-Null; return $true } 
                catch { return $false }
            }
            "Directory.Read.All" = { 
                try { Get-MgOrganization -Top 1 -ErrorAction Stop | Out-Null; return $true } 
                catch { return $false }
            }
            "RoleManagement.Read.Directory" = { 
                try { 
                    Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions" -Method GET -ErrorAction Stop | Out-Null
                    return $true 
                } catch { 
                    return $false 
                }
            }
            "RoleEligibilitySchedule.Read.Directory" = { 
                try { 
                    Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances" -Method GET -ErrorAction Stop | Out-Null
                    return $true 
                } catch { 
                    return $false 
                }
            }
            "UserAuthenticationMethod.Read.All" = { 
                try {
                    # Try to get a user first
                    $testUser = Get-MgUser -Top 1 -ErrorAction SilentlyContinue
                    if ($testUser) {
                        Get-MgUserAuthenticationMethod -UserId $testUser.Id -ErrorAction Stop | Out-Null
                    }
                    return $true 
                } catch { return $false }
            }
            "PrivilegedAccess.Read.AzureADGroup" = {
                try {
                    # This endpoint requires groupId or principalId filter, so test with a role-assignable group
                    $testGroup = Get-MgGroup -Filter "isAssignableToRole eq true" -Top 1 -ErrorAction SilentlyContinue
                    if ($testGroup) {
                        Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$($testGroup.Id)'" -Method GET -ErrorAction Stop | Out-Null
                    }
                    return $true
                } catch { 
                    if ($_.Exception.Message -match "PermissionScopeNotGranted|UnauthorizedAccessException|403") {
                        return $false
                    }
                    # Other errors (like no groups found) don't mean permission is missing
                    return $true
                }
            }
        }
    }
    else {
        Write-Log "Using delegated authentication - checking context scopes..." -Level "INFO"
        Write-Host "" 
        Write-Host "⚠️  INTERACTIVE AUTHENTICATION WARNING" -ForegroundColor Yellow
        Write-Host "MFA status reporting may be incomplete if privileged users are in Restricted" -ForegroundColor Yellow
        Write-Host "Administrative Units (RAUs) that you don't have access to. Consider using" -ForegroundColor Yellow
        Write-Host "app-only authentication for complete reporting." -ForegroundColor Yellow
        Write-Host "" 
        
        # For delegated auth, just check if scopes are present
        $permissionTests = @{}
        foreach ($perm in $requiredScopes) {
            $permissionTests[$perm] = { $context.Scopes -contains $perm }
        }
    }
    
    foreach ($permission in $permissionTests.Keys) {
        $hasPermission = & $permissionTests[$permission]
        if ($hasPermission) {
            Write-Log "  ✓ $permission" -Level "SUCCESS"
        } else {
            Write-Log "  ✗ $permission (MISSING)" -Level "ERROR"
            $missingPermissions += $permission
        }
    }
    
    # Track available features based on permissions
    $availableFeatures = @{
        ActiveRoleAssignments = $missingPermissions -notcontains "RoleManagement.Read.Directory"
        PIMEligibleAssignments = $missingPermissions -notcontains "RoleEligibilitySchedule.Read.Directory"
        MFAStatus = $missingPermissions -notcontains "UserAuthenticationMethod.Read.All"
        UserDetails = ($missingPermissions -notcontains "User.Read.All") -and ($missingPermissions -notcontains "Directory.Read.All")
        PIMGroupEligibility = $missingPermissions -notcontains "PrivilegedAccess.Read.AzureADGroup"
    }
    
    if ($missingPermissions.Count -gt 0) {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "LIMITED PERMISSIONS DETECTED" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "The following Microsoft Graph permissions are missing:" -ForegroundColor Yellow
        $missingPermissions | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        Write-Host ""
        Write-Host "Impact on report:" -ForegroundColor Cyan
        if (-not $availableFeatures.ActiveRoleAssignments) {
            Write-Host "  ✗ Active role assignments will not be retrieved" -ForegroundColor Red
        }
        if (-not $availableFeatures.PIMEligibleAssignments) {
            Write-Host "  ✗ PIM eligible assignments will not be retrieved" -ForegroundColor Red
            Write-Host "    (Note: PIM requires Entra ID P2 licensing)" -ForegroundColor DarkGray
        }
        if (-not $availableFeatures.MFAStatus) {
            Write-Host "  ✗ MFA status will not be checked" -ForegroundColor Red
        }
        if (-not $availableFeatures.UserDetails) {
            Write-Host "  ✗ User details may be limited" -ForegroundColor Red
        }
        Write-Host ""
        
        # Special note about P2 licensing if PIM permission is missing
        if ($missingPermissions -contains "RoleEligibilitySchedule.Read.Directory") {
            Write-Host "ℹ Licensing Note:" -ForegroundColor Cyan
            Write-Host "  RoleEligibilitySchedule.Read.Directory requires Entra ID P2 (Premium P2) licensing." -ForegroundColor Gray
            Write-Host "  If your tenant only has P1 licenses, PIM features are not available." -ForegroundColor Gray
            Write-Host ""
        }
        
        Write-Host "To add available permissions, run:" -ForegroundColor Cyan
        Write-Host "  ..\AppRegistration\Add-MFAReportPermissions.ps1" -ForegroundColor White
        Write-Host ""
        Write-Host "Continuing with best-effort reporting using available permissions..." -ForegroundColor Yellow
        Write-Host ""
        Write-Log "Continuing with limited permissions: $($missingPermissions -join ', ')" -Level "WARNING"
    }
    else {
        Write-Log "✓ All required permissions verified" -Level "SUCCESS"
    }
    Write-Host ""
    
    # Initialize collections
    $privilegedUsers = @{}
    $privilegedServicePrincipals = @{}
    $privilegedGroups = @{}
    $roleStats = @{}
    $roleDefinitionsCache = @{}
    $userDetailsCache = @{}
    $mfaStatusCache = @{}
    
    # If including groups, also check for role-assignable groups in the tenant
    $roleAssignableGroups = @()
    if ($IncludeGroups) {
        Write-Log "Checking for role-assignable groups in the tenant..." -Level "INFO"
        try {
            $roleAssignableGroups = Get-MgGroup -Filter "isAssignableToRole eq true" -All
            Write-Log "Found $($roleAssignableGroups.Count) role-assignable groups in tenant" -Level "INFO"
            
            # Check membership of each role-assignable group to find potential privileged users
            foreach ($group in $roleAssignableGroups) {
                Write-Log "  - Role-assignable group: $($group.DisplayName) (ID: $($group.Id))" -Level "INFO"
                
                try {
                    $groupMembers = Get-MgGroupMember -GroupId $group.Id -All
                    if ($groupMembers.Count -gt 0) {
                        Write-Log "    Members ($($groupMembers.Count)):" -Level "INFO"
                        foreach ($member in $groupMembers) {
                            if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                                # Get user details directly since function scope isn't working here
                                try {
                                    $memberUser = Get-MgUser -UserId $member.Id -Property DisplayName,UserPrincipalName,UserType,AccountEnabled -ErrorAction Stop
                                    Write-Log "      - User: $($memberUser.DisplayName) ($($memberUser.UserPrincipalName))" -Level "INFO"
                                    
                                    # Add these users to privileged users as they have potential for privilege escalation
                                    # even if they don't currently have active assignments
                                    if (-not $privilegedUsers.ContainsKey($member.Id)) {
                                        $privilegedUsers[$member.Id] = @{
                                            UserPrincipalName = $memberUser.UserPrincipalName
                                            DisplayName = $memberUser.DisplayName
                                            UserId = $member.Id
                                            AccountEnabled = $memberUser.AccountEnabled
                                            ActiveRoles = @()
                                            EligibleRoles = @()
                                            GroupBasedRoles = @()
                                            PIMGroupEligibleRoles = @()
                                            MFAStatus = $null
                                            AUProtection = $null
                                        }
                                    }
                                    
                                    # Add a special role to track PIM Group Active Membership
                                    $privilegedUsers[$member.Id].GroupBasedRoles += @{
                                        RoleName = "PIM Group Active Member"
                                        RoleId = $null
                                        AssignmentType = "PIM Group Active Membership"
                                        GroupName = $group.DisplayName
                                        GroupId = $group.Id
                                        NestingLevel = 0
                                    }
                                    
                                    # Track this in role statistics
                                    if (-not $roleStats.ContainsKey("PIM Group Active Member")) {
                                        $roleStats["PIM Group Active Member"] = @{
                                            RoleName = "PIM Group Active Member"
                                            RoleId = $group.Id
                                            Type = "Group"
                                            ActiveCount = 0
                                            EligibleCount = 0
                                            GroupBasedCount = 0
                                            PIMGroupEligibleCount = 0
                                            TotalUniqueUsers = 0
                                            Users = @()
                                        }
                                    }
                                    $roleStats["PIM Group Active Member"].GroupBasedCount++
                                }
                                catch {
                                    Write-Log "      - Error getting user details for $($member.Id): $($_.Exception.Message)" -Level "WARNING"
                                }
                            }
                            elseif ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group') {
                                Write-Log "      - Nested Group: $($member.Id)" -Level "INFO"
                            }
                        }
                    }
                    # Also check for PIM eligible assignments where users might be eligible for groups that contain nested privileged groups
                    try {
                        $nestedGroupMembers = Get-NestedGroupMembers -GroupId $group.Id
                        if ($nestedGroupMembers.Count -gt 0) {
                            Write-Log "    Found $($nestedGroupMembers.Count) nested members, checking for additional PIM eligibility" -Level "INFO"
                        }
                    }
                    catch {
                        Write-Log "    Error checking nested members: $($_.Exception.Message)" -Level "WARNING"
                    }
                }
                catch {
                    Write-Log "    Error retrieving group members: $($_.Exception.Message)" -Level "WARNING"
                }
            }
        }
        catch {
            Write-Log "Error retrieving role-assignable groups: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    # Get active role assignments (if permission available)
    $activeAssignments = @()
    if ($availableFeatures.ActiveRoleAssignments) {
        $activeAssignments = Get-ActiveRoleAssignments
    }
    else {
        Write-Log "Skipping active role assignments (missing RoleManagement.Read.Directory)" -Level "WARNING"
    }
    
    # Get PIM eligible assignments (if permission available)
    $eligibleAssignments = @()
    if ($availableFeatures.PIMEligibleAssignments) {
        $eligibleAssignments = Get-PIMEligibleAssignments
    }
    else {
        Write-Log "Skipping PIM eligible assignments (missing RoleEligibilitySchedule.Read.Directory)" -Level "WARNING"
    }
    
    # Get PIM group eligibility assignments (always try if including groups)
    $pimGroupEligibilityAssignments = @()
    if ($IncludeGroups) {
        $pimGroupEligibilityAssignments = Get-PIMGroupEligibilityAssignments -RoleAssignableGroups $roleAssignableGroups -EligibleAssignments $eligibleAssignments
    }
    
    # Optionally get group-based assignments
    $groupAssignments = @()
    if ($IncludeGroups) {
        $groupAssignments = Get-GroupBasedRoleAssignments
    }
    
    # Helper function to get role definition (with caching)
    function Get-RoleDefinitionDetails {
        param([string]$RoleDefinitionId)
        
        if (-not $roleDefinitionsCache.ContainsKey($RoleDefinitionId)) {
            try {
                $roleDefinition = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$RoleDefinitionId" -Method GET
                $roleDefinitionsCache[$RoleDefinitionId] = $roleDefinition
            }
            catch {
                Write-Log "Error retrieving role definition $RoleDefinitionId : $($_.Exception.Message)" -Level "WARNING"
                return $null
            }
        }
        return $roleDefinitionsCache[$RoleDefinitionId]
    }
    
    # Helper function to get user details (with caching)
    function Get-UserDetails {
        param([string]$UserId)
        
        if (-not $userDetailsCache.ContainsKey($UserId)) {
            try {
                $user = Get-MgUser -UserId $UserId -Property DisplayName,UserPrincipalName,UserType,AccountEnabled -ErrorAction Stop
                $userDetailsCache[$UserId] = $user
            }
            catch {
                # Silently skip non-user principals (groups, service principals)
                # These are expected and not errors
                $userDetailsCache[$UserId] = $null
                return $null
            }
        }
        return $userDetailsCache[$UserId]
    }
    
    # Helper function to get MFA status (with caching)
    function Get-UserMFAStatus {
        param([string]$UserId)
        
        # Return null status if permission is missing
        if (-not $availableFeatures.MFAStatus) {
            return @{
                HasMicrosoftAuthenticator = $null
                HasPhone = $null
                HasEmail = $null
                HasFIDO2 = $null
                HasWindowsHello = $null
                HasSoftwareOath = $null
                HasTemporaryAccessPass = $null
                MethodCount = 0
                MethodsList = @()
                PhoneNumbers = @()
                MFACapable = $null
            }
        }
        
        if (-not $mfaStatusCache.ContainsKey($UserId)) {
            try {
                $authMethods = Get-MgUserAuthenticationMethod -UserId $UserId -ErrorAction Stop
                
                $methods = @{
                    HasMicrosoftAuthenticator = $false
                    HasPhone = $false
                    HasEmail = $false
                    HasFIDO2 = $false
                    HasWindowsHello = $false
                    HasSoftwareOath = $false
                    HasTemporaryAccessPass = $false
                    MethodCount = 0
                    MethodsList = @()
                    PhoneNumbers = @()
                    MFACapable = $false
                }
                
                foreach ($method in $authMethods) {
                    $methodType = $method.AdditionalProperties.'@odata.type'
                    
                    switch ($methodType) {
                        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
                            $methods.HasMicrosoftAuthenticator = $true
                            $methods.MethodsList += 'Microsoft Authenticator'
                        }
                        '#microsoft.graph.phoneAuthenticationMethod' {
                            $methods.HasPhone = $true
                            $methods.MethodsList += 'Phone'
                            # Capture phone number
                            if ($method.AdditionalProperties.phoneNumber) {
                                $methods.PhoneNumbers += $method.AdditionalProperties.phoneNumber
                            }
                        }
                        '#microsoft.graph.emailAuthenticationMethod' {
                            $methods.HasEmail = $true
                            $methods.MethodsList += 'Email'
                        }
                        '#microsoft.graph.fido2AuthenticationMethod' {
                            $methods.HasFIDO2 = $true
                            $methods.MethodsList += 'FIDO2 Security Key'
                        }
                        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' {
                            $methods.HasWindowsHello = $true
                            $methods.MethodsList += 'Windows Hello'
                        }
                        '#microsoft.graph.softwareOathAuthenticationMethod' {
                            $methods.HasSoftwareOath = $true
                            $methods.MethodsList += 'Software OATH'
                        }
                        '#microsoft.graph.temporaryAccessPassAuthenticationMethod' {
                            $methods.HasTemporaryAccessPass = $true
                            $methods.MethodsList += 'Temporary Access Pass'
                        }
                    }
                }
                
                $methods.MethodCount = $methods.MethodsList.Count
                $methods.MFACapable = $methods.HasMicrosoftAuthenticator -or 
                                      $methods.HasPhone -or 
                                      $methods.HasFIDO2 -or 
                                      $methods.HasWindowsHello -or 
                                      $methods.HasSoftwareOath
                
                $mfaStatusCache[$UserId] = $methods
            }
            catch {
                Write-Log "Error retrieving MFA status for $UserId : $($_.Exception.Message)" -Level "WARNING"
                # Return default status on error
                $mfaStatusCache[$UserId] = @{
                    HasMicrosoftAuthenticator = $false
                    HasPhone = $false
                    HasEmail = $false
                    HasFIDO2 = $false
                    HasWindowsHello = $false
                    HasSoftwareOath = $false
                    HasTemporaryAccessPass = $false
                    MethodCount = 0
                    MethodsList = @()
                    PhoneNumbers = @()
                    MFACapable = $false
                }
            }
        }
        return $mfaStatusCache[$UserId]
    }
    
    # Helper function to check if user is in a restricted administrative unit
    function Test-UserInRestrictedAU {
        param([string]$UserId)
        
        if (-not $script:restrictedAUs) {
            # Cache restricted AUs on first call
            try {
                $script:restrictedAUs = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits?`$filter=isMemberManagementRestricted eq true" -Method GET -ErrorAction Stop
                Write-Log "Found $($script:restrictedAUs.value.Count) restricted administrative units" -Level "INFO"
            }
            catch {
                Write-Log "Error retrieving restricted administrative units: $($_.Exception.Message)" -Level "WARNING"
                $script:restrictedAUs = @{ value = @() }
            }
        }
        
        # Check if user is member of any restricted AU
        foreach ($au in $script:restrictedAUs.value) {
            try {
                $members = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/members?`$filter=id eq '$UserId'" -Method GET -ErrorAction Stop
                if ($members.value.Count -gt 0) {
                    return @{
                        IsProtected = $true
                        AUName = $au.displayName
                        AUId = $au.id
                    }
                }
            }
            catch {
                # Silently continue if check fails
                continue
            }
        }
        
        return @{
            IsProtected = $false
            AUName = $null
            AUId = $null
        }
    }
    
    Write-Log "Processing active role assignments..." -Level "INFO"
    $activeProcessedCount = 0
    $activeNonUserCount = 0
    foreach ($assignment in $activeAssignments) {
        $principalId = $assignment.principalId
        $roleId = $assignment.roleDefinitionId
        
        # Get user details to verify it's a user (not a group or service principal)
        $userDetails = Get-UserDetails -UserId $principalId
        
        if ($userDetails) {
            $activeProcessedCount++
            
            # Get role definition
            $roleDefinition = Get-RoleDefinitionDetails -RoleDefinitionId $roleId
            
            if ($roleDefinition) {
                $roleName = $roleDefinition.displayName
                
                if (-not $privilegedUsers.ContainsKey($principalId)) {
                    $privilegedUsers[$principalId] = @{
                        UserPrincipalName = $userDetails.UserPrincipalName
                        DisplayName = $userDetails.DisplayName
                        UserId = $principalId
                        AccountEnabled = $userDetails.AccountEnabled
                        ActiveRoles = @()
                        EligibleRoles = @()
                        GroupBasedRoles = @()
                        PIMGroupEligibleRoles = @()
                        MFAStatus = $null
                        AUProtection = $null
                    }
                }
                
                $privilegedUsers[$principalId].ActiveRoles += @{
                    RoleName = $roleName
                    RoleId = $roleId
                    AssignmentType = "Active"
                }
                
                # Track role statistics
                if (-not $roleStats.ContainsKey($roleName)) {
                    $roleStats[$roleName] = @{
                        RoleName = $roleName
                        RoleId = $roleId
                        Type = "Role"
                        ActiveCount = 0
                        EligibleCount = 0
                        GroupBasedCount = 0
                        PIMGroupEligibleCount = 0
                        TotalUniqueUsers = 0
                        Users = @()
                    }
                }
                $roleStats[$roleName].ActiveCount++
            }
        }
        else {
            $activeNonUserCount++
            Write-Log "Active assignment $principalId is not a user - checking if it's a group..." -Level "INFO"
            
            # Check if this is a group
            try {
                $group = Get-MgGroup -GroupId $principalId -ErrorAction Stop
                $roleDefinition = Get-RoleDefinitionDetails -RoleDefinitionId $roleId
                
                # Store group information
                if (-not $privilegedGroups.ContainsKey($principalId)) {
                    $privilegedGroups[$principalId] = @{
                        DisplayName = $group.DisplayName
                        GroupId = $principalId
                        IsAssignableToRole = $group.IsAssignableToRole
                        ActiveRoles = @()
                        EligibleRoles = @()
                        MemberCount = 0
                        Members = @()
                    }
                }
                
                if ($roleDefinition) {
                    $privilegedGroups[$principalId].ActiveRoles += @{
                        RoleName = $roleDefinition.displayName
                        RoleId = $roleId
                        AssignmentType = "Active (Group Assignment)"
                    }
                }
                
                # Get group members for processing
                try {
                    $groupMembers = Get-MgGroupMember -GroupId $principalId -All
                    $privilegedGroups[$principalId].MemberCount = $groupMembers.Count
                    
                    # Store sample members for detail reporting
                    foreach ($member in $groupMembers) {
                        if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                            $memberUser = Get-UserDetails -UserId $member.Id
                            if ($memberUser) {
                                $privilegedGroups[$principalId].Members += @{
                                    DisplayName = $memberUser.DisplayName
                                    UserPrincipalName = $memberUser.UserPrincipalName
                                    UserId = $member.Id
                                }
                            }
                        }
                    }
                }
                catch {
                    $privilegedGroups[$principalId].MemberCount = -1  # Unknown
                }
                
                Write-Log "Found active GROUP assignment: $($group.DisplayName) with role: $($roleDefinition.displayName)" -Level "INFO"
                
                # Process all members of this group (including nested and PIM eligible)
                $allGroupUsers = Get-AllGroupMembers -GroupId $principalId -AllPIMGroupEligibility $pimGroupEligibilityAssignments
                Write-Log "Active role group $($group.DisplayName) has $($allGroupUsers.Count) total users (including nested and PIM eligible)" -Level "INFO"
                
                foreach ($groupMember in $allGroupUsers) {
                    $memberUserId = $groupMember.UserId
                    
                    # Skip users who reach this group only through PIM eligibility (no active membership in the chain)
                    # They will be processed in the dedicated PIM group eligibility section
                    if ($groupMember.MembershipType -eq "PIM Eligible") {
                        Write-Log "Skipping user $memberUserId in active group processing - only has PIM eligible access, will be handled in dedicated PIM section" -Level "INFO"
                        continue
                    }
                    
                    # Also skip users who have PIM eligibility anywhere in the system for any role-assignable group
                    # This handles cases where group PIM activation causes transitive membership
                    $hasPIMEligibility = $pimGroupEligibilityAssignments | Where-Object { $_.principalId -eq $memberUserId }
                    if ($hasPIMEligibility) {
                        Write-Log "Skipping user $memberUserId in active group processing - has PIM group eligibility elsewhere, prioritizing PIM section" -Level "INFO"
                        continue
                    }
                    
                    # Get user details
                    try {
                        $memberUser = Get-MgUser -UserId $memberUserId -Property DisplayName,UserPrincipalName,UserType,AccountEnabled -ErrorAction Stop
                        
                        $membershipPath = $groupMember.GroupPath -join " → "
                        Write-Log "Adding user $($memberUser.DisplayName) via active group assignment: $membershipPath → $($group.DisplayName) ($($groupMember.MembershipType))" -Level "INFO"
                        
                        if (-not $privilegedUsers.ContainsKey($memberUserId)) {
                            $privilegedUsers[$memberUserId] = @{
                                UserPrincipalName = $memberUser.UserPrincipalName
                                DisplayName = $memberUser.DisplayName
                                UserId = $memberUserId
                                AccountEnabled = $memberUser.AccountEnabled
                                ActiveRoles = @()
                                EligibleRoles = @()
                                GroupBasedRoles = @()
                                PIMGroupEligibleRoles = @()
                                MFAStatus = $null
                                AUProtection = $null
                            }
                        }
                        
                        # Build display name showing the membership path
                        # [Nested] indicates nested group membership
                        # Only add marker if path doesn't already end with one (to avoid duplication)
                        $displayGroupName = if ($groupMember.NestingLevel -gt 0) {
                            if ($membershipPath -notmatch '\[(PIM|Nested)\]$') {
                                "$membershipPath [Nested]"
                            } else {
                                $membershipPath
                            }
                        } else {
                            $membershipPath
                        }
                        
                        $privilegedUsers[$memberUserId].GroupBasedRoles += @{
                            RoleName = $roleDefinition.displayName
                            RoleId = $roleId
                            AssignmentType = "Group-Based"
                            GroupName = $displayGroupName
                            GroupId = $principalId
                            NestingLevel = $groupMember.NestingLevel
                        }
                        
                        # Track role statistics
                        if (-not $roleStats.ContainsKey($roleDefinition.displayName)) {
                            $roleStats[$roleDefinition.displayName] = @{
                                RoleName = $roleDefinition.displayName
                                RoleId = $roleId
                                Type = "Role"
                                ActiveCount = 0
                                EligibleCount = 0
                                GroupBasedCount = 0
                                PIMGroupEligibleCount = 0
                                TotalUniqueUsers = 0
                                Users = @()
                            }
                        }
                        $roleStats[$roleDefinition.displayName].GroupBasedCount++
                    }
                    catch {
                        Write-Log "Error processing active group member $memberUserId : $($_.Exception.Message)" -Level "WARNING"
                    }
                }
            }
            catch {
                # Not a group, check if it's a service principal
                try {
                    $servicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $principalId -ErrorAction Stop
                    
                    # Get role definition for service principal
                    $roleDefinition = Get-RoleDefinitionDetails -RoleDefinitionId $roleId
                    if ($roleDefinition) {
                        if (-not $privilegedServicePrincipals.ContainsKey($principalId)) {
                            $privilegedServicePrincipals[$principalId] = @{
                                DisplayName = $servicePrincipal.DisplayName
                                ServicePrincipalId = $principalId
                                AppId = $servicePrincipal.AppId
                                ActiveRoles = @()
                                EligibleRoles = @()
                            }
                        }
                        
                        $privilegedServicePrincipals[$principalId].ActiveRoles += @{
                            RoleName = $roleDefinition.displayName
                            RoleId = $roleId
                            AssignmentType = "Active (Service Principal)"
                        }
                        Write-Log "Found active SERVICE PRINCIPAL assignment: $($servicePrincipal.DisplayName) with role: $($roleDefinition.displayName)" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Active assignment $principalId is unknown principal type" -Level "WARNING"
                }
            }
        }
    }
    Write-Log "Processed $activeProcessedCount active user assignments and $activeNonUserCount non-user assignments out of $($activeAssignments.Count) total" -Level "SUCCESS"
    
    Write-Log "Processing PIM eligible assignments..." -Level "INFO"
    $pimProcessedCount = 0
    $pimNonUserCount = 0
    foreach ($assignment in $eligibleAssignments) {
        $principalId = $assignment.principalId
        $roleId = $assignment.roleDefinitionId
        
        Write-Log "Processing PIM assignment: Principal $principalId for Role $roleId" -Level "INFO"
        
        # Get user details to verify it's a user
        $userDetails = Get-UserDetails -UserId $principalId
        
        if ($userDetails) {
            $pimProcessedCount++
            Write-Log "Found PIM eligible user: $($userDetails.DisplayName)" -Level "INFO"
            
            # Get role definition
            $roleDefinition = Get-RoleDefinitionDetails -RoleDefinitionId $roleId
            
            if ($roleDefinition) {
                $roleName = $roleDefinition.displayName
                Write-Log "PIM role: $roleName for user $($userDetails.DisplayName)" -Level "INFO"
                
                if (-not $privilegedUsers.ContainsKey($principalId)) {
                    $privilegedUsers[$principalId] = @{
                        UserPrincipalName = $userDetails.UserPrincipalName
                        DisplayName = $userDetails.DisplayName
                        UserId = $principalId
                        AccountEnabled = $userDetails.AccountEnabled
                        ActiveRoles = @()
                        EligibleRoles = @()
                        GroupBasedRoles = @()
                        PIMGroupEligibleRoles = @()
                        MFAStatus = $null
                        AUProtection = $null
                    }
                }
                
                $privilegedUsers[$principalId].EligibleRoles += @{
                    RoleName = $roleName
                    RoleId = $roleId
                    AssignmentType = "PIM Eligible"
                }
                
                # Track role statistics
                if (-not $roleStats.ContainsKey($roleName)) {
                    $roleStats[$roleName] = @{
                        RoleName = $roleName
                        RoleId = $roleId
                        Type = "Role"
                        ActiveCount = 0
                        EligibleCount = 0
                        GroupBasedCount = 0
                        PIMGroupEligibleCount = 0
                        TotalUniqueUsers = 0
                        Users = @()
                    }
                }
                $roleStats[$roleName].EligibleCount++
            }
        }
        else {
            $pimNonUserCount++
            Write-Log "PIM assignment $principalId is not a user - checking if it's a group..." -Level "INFO"
            
            # Check if this is a group with PIM eligible role assignment
            try {
                $group = Get-MgGroup -GroupId $principalId -ErrorAction Stop
                $roleDefinition = Get-RoleDefinitionDetails -RoleDefinitionId $roleId
                Write-Log "Found PIM eligible GROUP: $($group.DisplayName) with role: $($roleDefinition.displayName)" -Level "INFO"
                
                # Get all current members of this PIM eligible group (including nested and PIM eligible)
                $allGroupUsers = Get-AllGroupMembers -GroupId $principalId -AllPIMGroupEligibility $pimGroupEligibilityAssignments
                Write-Log "PIM eligible group $($group.DisplayName) has $($allGroupUsers.Count) total members (including nested and PIM eligible)" -Level "INFO"
                
                foreach ($groupMember in $allGroupUsers) {
                    $memberUserId = $groupMember.UserId
                    
                    # Get user details
                    try {
                        $memberUser = Get-MgUser -UserId $memberUserId -Property DisplayName,UserPrincipalName,UserType,AccountEnabled -ErrorAction Stop
                        
                        $membershipPath = $groupMember.GroupPath -join " → "
                        Write-Log "Adding user $($memberUser.DisplayName) via PIM eligible group: $membershipPath → $($group.DisplayName) ($($groupMember.MembershipType))" -Level "INFO"
                        
                        if (-not $privilegedUsers.ContainsKey($memberUserId)) {
                            $privilegedUsers[$memberUserId] = @{
                                UserPrincipalName = $memberUser.UserPrincipalName
                                DisplayName = $memberUser.DisplayName
                                UserId = $memberUserId
                                AccountEnabled = $memberUser.AccountEnabled
                                ActiveRoles = @()
                                EligibleRoles = @()
                                GroupBasedRoles = @()
                                PIMGroupEligibleRoles = @()
                                MFAStatus = $null
                                AUProtection = $null
                            }
                        }
                        
                        # Build display name showing the membership path
                        # [PIM] marker indicates PIM eligibility, [Nested] indicates nested group membership
                        # Only add marker if path doesn't already end with one (to avoid duplication)
                        $displayGroupName = if ($groupMember.MembershipType -eq "PIM Eligible") {
                            $fullPath = "$membershipPath → $($group.DisplayName)"
                            if ($fullPath -notmatch '\[(PIM|Nested)\]$') {
                                "$fullPath [PIM]"
                            } else {
                                $fullPath
                            }
                        } elseif ($groupMember.NestingLevel -gt 0) {
                            $fullPath = "$membershipPath → $($group.DisplayName)"  
                            if ($fullPath -notmatch '\[(PIM|Nested)\]$') {
                                "$fullPath [Nested]"
                            } else {
                                $fullPath
                            }
                        } else {
                            "$membershipPath → $($group.DisplayName)"
                        }
                        
                        $privilegedUsers[$memberUserId].PIMGroupEligibleRoles += @{
                            RoleName = $roleDefinition.displayName
                            RoleId = $roleId
                            AssignmentType = if ($groupMember.MembershipType -eq "PIM Eligible") { "PIM Group Eligible (via PIM)" } else { "PIM Group Eligible (Current Member)" }
                            GroupName = $displayGroupName
                            GroupId = $principalId
                            NestingLevel = $groupMember.NestingLevel
                        }
                        
                        # Track role statistics
                        if (-not $roleStats.ContainsKey($roleDefinition.displayName)) {
                            $roleStats[$roleDefinition.displayName] = @{
                                RoleName = $roleDefinition.displayName
                                RoleId = $roleId
                                Type = "Role"
                                ActiveCount = 0
                                EligibleCount = 0
                                GroupBasedCount = 0
                                PIMGroupEligibleCount = 0
                                TotalUniqueUsers = 0
                                Users = @()
                            }
                        }
                        $roleStats[$roleDefinition.displayName].PIMGroupEligibleCount++
                    }
                    catch {
                        Write-Log "Error processing PIM group member $memberUserId : $($_.Exception.Message)" -Level "WARNING"
                    }
                }
                
                # Also check for users who are PIM eligible for this group (but not necessarily current members)
                Write-Log "Checking for users PIM eligible for group membership in $($group.DisplayName)" -Level "INFO"
                try {
                    # Try to get PIM eligibility for this specific group
                    $groupEligibilityUri = "https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$principalId'"
                    $groupEligibilityResponse = Invoke-MgGraphRequest -Uri $groupEligibilityUri -Method GET -ErrorAction Stop
                    
                    if ($groupEligibilityResponse.value -and $groupEligibilityResponse.value.Count -gt 0) {
                        Write-Log "Found $($groupEligibilityResponse.value.Count) PIM eligible assignments for group $($group.DisplayName)" -Level "INFO"
                        
                        foreach ($groupEligibility in $groupEligibilityResponse.value) {
                            $eligibleUserId = $groupEligibility.principalId
                            
                            try {
                                $eligibleUser = Get-MgUser -UserId $eligibleUserId -Property DisplayName,UserPrincipalName,UserType,AccountEnabled -ErrorAction Stop
                                Write-Log "Adding user $($eligibleUser.DisplayName) via PIM group eligibility for $($group.DisplayName)" -Level "INFO"
                                
                                if (-not $privilegedUsers.ContainsKey($eligibleUserId)) {
                                    $privilegedUsers[$eligibleUserId] = @{
                                        UserPrincipalName = $eligibleUser.UserPrincipalName
                                        DisplayName = $eligibleUser.DisplayName
                                        UserId = $eligibleUserId
                                        AccountEnabled = $eligibleUser.AccountEnabled
                                        ActiveRoles = @()
                                        EligibleRoles = @()
                                        GroupBasedRoles = @()
                                        PIMGroupEligibleRoles = @()
                                        MFAStatus = $null
                                        AUProtection = $null
                                    }
                                }
                                
                                $privilegedUsers[$eligibleUserId].PIMGroupEligibleRoles += @{
                                    RoleName = $roleDefinition.displayName
                                    RoleId = $roleId
                                    AssignmentType = "PIM Group Eligible (Membership Eligible)"
                                    GroupName = $group.DisplayName
                                    GroupId = $principalId
                                    NestingLevel = 0
                                }
                                
                                $roleStats[$roleDefinition.displayName].PIMGroupEligibleCount++
                            }
                            catch {
                                Write-Log "Error processing PIM group eligible user $eligibleUserId : $($_.Exception.Message)" -Level "WARNING"
                            }
                        }
                    }
                    else {
                        Write-Log "No PIM eligible users found for group membership in $($group.DisplayName)" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not check PIM group eligibility for $($group.DisplayName): $($_.Exception.Message)" -Level "INFO"
                }
            }
            catch {
                # Not a group either, check if it's a service principal
                try {
                    $servicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $principalId -ErrorAction Stop
                    $roleDefinition = Get-RoleDefinitionDetails -RoleDefinitionId $roleId
                    
                    if ($roleDefinition) {
                        if (-not $privilegedServicePrincipals.ContainsKey($principalId)) {
                            $privilegedServicePrincipals[$principalId] = @{
                                DisplayName = $servicePrincipal.DisplayName
                                ServicePrincipalId = $principalId
                                AppId = $servicePrincipal.AppId
                                ActiveRoles = @()
                                EligibleRoles = @()
                            }
                        }
                        
                        $privilegedServicePrincipals[$principalId].EligibleRoles += @{
                            RoleName = $roleDefinition.displayName
                            RoleId = $roleId
                            AssignmentType = "PIM Eligible (Service Principal)"
                        }
                        Write-Log "Found PIM eligible SERVICE PRINCIPAL: $($servicePrincipal.DisplayName) with role: $($roleDefinition.displayName)" -Level "INFO"
                    }
                }
                catch {
                    Write-Log "PIM assignment $principalId is unknown principal type" -Level "WARNING"
                }
            }
        }
    }
    Write-Log "Processed $pimProcessedCount PIM eligible user assignments and $pimNonUserCount non-user assignments out of $($eligibleAssignments.Count) total" -Level "SUCCESS"
    
    # Process PIM group eligibility assignments with comprehensive group checking
    if ($pimGroupEligibilityAssignments.Count -gt 0) {
        Write-Log "Processing dedicated PIM group eligibility assignments..." -Level "INFO"
        
        foreach ($assignment in $pimGroupEligibilityAssignments) {
            $userId = $assignment.principalId
            $groupId = $assignment.groupId
            
            Write-Log "Processing PIM group eligibility: User $userId for Group $groupId" -Level "INFO"
            
            # Get user details to verify it's a user
            try {
                $userDetails = Get-MgUser -UserId $userId -Property DisplayName,UserPrincipalName,UserType,AccountEnabled -ErrorAction Stop
                
                if ($userDetails) {
                    Write-Log "Found PIM group eligible user: $($userDetails.DisplayName)" -Level "INFO"
                    
                    try {
                        # Get the group details
                        $group = Get-MgGroup -GroupId $groupId -ErrorAction Stop
                        Write-Log "PIM eligible for group: $($group.DisplayName)" -Level "INFO"
                        
                        # Check if this group has any role assignments (direct or through other means)
                        $groupRoleAssignments = $groupAssignments | Where-Object { $_.principalId -eq $groupId }
                        
                        # Use the new Get-GroupRoleChain function to resolve all roles this group provides
                        $groupRoles = Get-GroupRoleChain -GroupId $groupId `
                            -AllActiveAssignments $activeAssignments `
                            -AllEligibleAssignments $eligibleAssignments `
                            -AllPIMGroupEligibility $pimGroupEligibilityAssignments
                        
                        if ($groupRoles.Count -gt 0) {
                            # Group provides one or more roles (directly or through nesting)
                            foreach ($groupRole in $groupRoles) {
                                Write-Log "PIM group eligible role: $($groupRole.RoleName) for user $($userDetails.DisplayName) via $($groupRole.GroupPath.Count) level(s)" -Level "INFO"
                                
                                if (-not $privilegedUsers.ContainsKey($userId)) {
                                    $privilegedUsers[$userId] = @{
                                        UserPrincipalName = $userDetails.UserPrincipalName
                                        DisplayName = $userDetails.DisplayName
                                        UserId = $userId
                                        AccountEnabled = $userDetails.AccountEnabled
                                        ActiveRoles = @()
                                        EligibleRoles = @()
                                        GroupBasedRoles = @()
                                        PIMGroupEligibleRoles = @()
                                        MFAStatus = $null
                                        AUProtection = $null
                                    }
                                }
                                
                                # Build group path string for display
                                $groupPathNames = @()
                                foreach ($pathGroupId in $groupRole.GroupPath) {
                                    try {
                                        $pathGroup = Get-MgGroup -GroupId $pathGroupId -Property DisplayName -ErrorAction Stop
                                        $groupPathNames += $pathGroup.DisplayName
                                    }
                                    catch {
                                        $groupPathNames += $pathGroupId
                                    }
                                }
                                $groupPathString = ($groupPathNames -join " → ")
                                
                                # Check if this permission is already captured in GroupBasedRoles (to avoid duplicates)
                                $alreadyExists = $privilegedUsers[$userId].GroupBasedRoles | Where-Object {
                                    $_.RoleName -eq $groupRole.RoleName -and $_.GroupId -eq $groupId
                                }
                                
                                if (-not $alreadyExists) {
                                    $privilegedUsers[$userId].PIMGroupEligibleRoles += @{
                                        RoleName = $groupRole.RoleName
                                        RoleId = $groupRole.RoleId
                                        AssignmentType = "PIM Group Eligible"
                                        GroupName = $groupPathString
                                        GroupId = $groupId
                                        NestingLevel = $groupRole.NestingLevel
                                    }
                                    
                                    # Track role statistics (only when actually adding, not duplicates)
                                    if (-not $roleStats.ContainsKey($groupRole.RoleName)) {
                                        $roleStats[$groupRole.RoleName] = @{
                                            RoleName = $groupRole.RoleName
                                            RoleId = $groupRole.RoleId
                                            Type = "Role"
                                            ActiveCount = 0
                                            EligibleCount = 0
                                            GroupBasedCount = 0
                                            PIMGroupEligibleCount = 0
                                            TotalUniqueUsers = 0
                                            Users = @()
                                        }
                                    }
                                    $roleStats[$groupRole.RoleName].PIMGroupEligibleCount++
                                } else {
                                    Write-Log "Skipping duplicate: User $($userDetails.DisplayName) already has $($groupRole.RoleName) via group $groupId in GroupBasedRoles" -Level "INFO"
                                }
                            }
                        }
                        else {
                            # No roles found - group might be role-assignable but not currently assigned
                            if ($group.IsAssignableToRole) {
                                Write-Log "User $($userDetails.DisplayName) is PIM eligible for role-assignable group: $($group.DisplayName) (no current role assignments)" -Level "INFO"
                                
                                if (-not $privilegedUsers.ContainsKey($userId)) {
                                    $privilegedUsers[$userId] = @{
                                        UserPrincipalName = $userDetails.UserPrincipalName
                                        DisplayName = $userDetails.DisplayName
                                        UserId = $userId
                                        AccountEnabled = $userDetails.AccountEnabled
                                        ActiveRoles = @()
                                        EligibleRoles = @()
                                        GroupBasedRoles = @()
                                        PIMGroupEligibleRoles = @()
                                        MFAStatus = $null
                                        AUProtection = $null
                                    }
                                }
                                
                                $privilegedUsers[$userId].PIMGroupEligibleRoles += @{
                                    RoleName = "PIM Group Eligible Member"
                                    RoleId = $groupId
                                    AssignmentType = "PIM Group Eligible (No Role Assigned)"
                                    GroupName = $group.DisplayName
                                    GroupId = $groupId
                                    NestingLevel = 0
                                }
                                
                                # Track role statistics
                                if (-not $roleStats.ContainsKey("PIM Group Eligible Member")) {
                                    $roleStats["PIM Group Eligible Member"] = @{
                                        RoleName = "PIM Group Eligible Member"
                                        RoleId = $groupId
                                        Type = "Group"
                                        ActiveCount = 0
                                        EligibleCount = 0
                                        GroupBasedCount = 0
                                        PIMGroupEligibleCount = 0
                                        TotalUniqueUsers = 0
                                        Users = @()
                                    }
                                }
                                $roleStats["PIM Group Eligible Member"].PIMGroupEligibleCount++
                            }
                        }
                    }
                    catch {
                        Write-Log "Error retrieving group details for $groupId : $($_.Exception.Message)" -Level "WARNING"
                        continue
                    }
                }
            }
            catch {
                Write-Log "PIM group assignment $userId is not a user" -Level "INFO"
                continue
            }
        }
        
        Write-Log "Processed $($pimGroupEligibilityAssignments.Count) dedicated PIM group eligibility assignments" -Level "SUCCESS"
    }
    else {
        Write-Log "No dedicated PIM group eligibility assignments found" -Level "INFO"
    }
    
    # Calculate unique users per role
    # Enhanced search for missing privileged users - check all directory roles
    Write-Log "Performing comprehensive directory role member check..." -Level "INFO"
    
    try {
        # Get all directory role definitions to check for additional privileged users
        $directoryRoles = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/directoryRoles" -Method GET
        
        $additionalUsersFound = 0
        foreach ($role in $directoryRoles.value) {
            try {
                # Get members of each directory role
                $roleMembers = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/directoryRoles/$($role.id)/members" -Method GET
                
                foreach ($member in $roleMembers.value) {
                    if ($member.'@odata.type' -eq '#microsoft.graph.user') {
                        $memberId = $member.id
                        
                        # Check if this user is already in our privileged users list
                        if (-not $privilegedUsers.ContainsKey($memberId)) {
                            # This is a new privileged user we haven't found yet
                            try {
                                $newUserDetails = Get-MgUser -UserId $memberId -Property DisplayName,UserPrincipalName,UserType,AccountEnabled -ErrorAction Stop
                                
                                Write-Log "Found additional privileged user: $($newUserDetails.DisplayName) in directory role: $($role.displayName)" -Level "SUCCESS"
                                $additionalUsersFound++
                                
                                $privilegedUsers[$memberId] = @{
                                    UserPrincipalName = $newUserDetails.UserPrincipalName
                                    DisplayName = $newUserDetails.DisplayName
                                    UserId = $memberId
                                    AccountEnabled = $newUserDetails.AccountEnabled
                                    ActiveRoles = @()
                                    EligibleRoles = @()
                                    GroupBasedRoles = @()
                                    PIMGroupEligibleRoles = @()
                                    MFAStatus = $null
                                    AUProtection = $null
                                }
                                
                                # Add this as an active role assignment
                                $privilegedUsers[$memberId].ActiveRoles += @{
                                    RoleName = $role.displayName
                                    RoleId = $role.roleTemplateId
                                    AssignmentType = "Active (Directory Role)"
                                }
                                
                                # Track role statistics
                                if (-not $roleStats.ContainsKey($role.displayName)) {
                                    $roleStats[$role.displayName] = @{
                                        RoleName = $role.displayName
                                        RoleId = $role.roleTemplateId
                                        Type = "Role"
                                        ActiveCount = 0
                                        EligibleCount = 0
                                        GroupBasedCount = 0
                                        PIMGroupEligibleCount = 0
                                        TotalUniqueUsers = 0
                                        Users = @()
                                    }
                                }
                                $roleStats[$role.displayName].ActiveCount++
                            }
                            catch {
                                # Silent continue for individual user retrieval failures
                            }
                        }
                    }
                }
            }
            catch {
                # Silent continue for individual role member retrieval failures
            }
        }
        
        if ($additionalUsersFound -gt 0) {
            Write-Log "Found $additionalUsersFound additional privileged users through directory role membership check" -Level "SUCCESS"
        } else {
            Write-Log "No additional privileged users found through directory role membership check" -Level "INFO"
        }
    }
    catch {
        Write-Log "Error during comprehensive directory role check: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Final comprehensive search - check all users with specific names if we haven't found expected accounts
    Write-Log "Performing targeted search for potentially missing privileged users..." -Level "INFO"
    
    $expectedUsers = @("Sidney", "Macleod", "Debra", "Berger")
    $foundTargetedUsers = 0
    
    try {
        foreach ($searchTerm in $expectedUsers) {
            # Search for users by display name containing the search term
            $searchedUsers = Get-MgUser -Filter "startswith(displayName,'$searchTerm') or startswith(givenName,'$searchTerm') or startswith(surname,'$searchTerm')" -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,UserType -ErrorAction SilentlyContinue
            
            foreach ($searchedUser in $searchedUsers) {
                if ($searchedUser.UserType -eq "Member" -and -not $privilegedUsers.ContainsKey($searchedUser.Id)) {
                    # Found a potential user - check if they have any role assignments via different paths
                    Write-Log "Checking user $($searchedUser.DisplayName) for privileged access..." -Level "INFO"
                    
                    # Check all possible role assignment endpoints for this specific user
                    $userHasPrivileges = $false
                    
                    # Check direct role assignments
                    try {
                        $userRoleAssignments = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($searchedUser.Id)'" -Method GET -ErrorAction SilentlyContinue
                        if ($userRoleAssignments.value -and $userRoleAssignments.value.Count -gt 0) {
                            $userHasPrivileges = $true
                            Write-Log "Found role assignments for $($searchedUser.DisplayName)" -Level "SUCCESS"
                        }
                    }
                    catch { }
                    
                    # Check PIM eligible assignments
                    try {
                        $userPimAssignments = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$($searchedUser.Id)'" -Method GET -ErrorAction SilentlyContinue
                        if ($userPimAssignments.value -and $userPimAssignments.value.Count -gt 0) {
                            $userHasPrivileges = $true
                            Write-Log "Found PIM eligible assignments for $($searchedUser.DisplayName)" -Level "SUCCESS"
                        }
                    }
                    catch { }
                    
                    # Check group memberships for role-assignable groups
                    try {
                        $userGroups = Get-MgUserMemberOf -UserId $searchedUser.Id -All -ErrorAction SilentlyContinue
                        foreach ($group in $userGroups) {
                            if ($group.AdditionalProperties.isAssignableToRole -eq $true) {
                                $userHasPrivileges = $true
                                Write-Log "Found PIM Group Active Membership for $($searchedUser.DisplayName): $($group.AdditionalProperties.displayName)" -Level "SUCCESS"
                                break
                            }
                        }
                    }
                    catch { }
                    
                    if ($userHasPrivileges) {
                        $foundTargetedUsers++
                        Write-Log "Adding previously missed privileged user: $($searchedUser.DisplayName)" -Level "SUCCESS"
                        
                        $privilegedUsers[$searchedUser.Id] = @{
                            UserPrincipalName = $searchedUser.UserPrincipalName
                            DisplayName = $searchedUser.DisplayName
                            UserId = $searchedUser.Id
                            AccountEnabled = $searchedUser.AccountEnabled
                            ActiveRoles = @()
                            EligibleRoles = @()
                            GroupBasedRoles = @()
                            PIMGroupEligibleRoles = @()
                            MFAStatus = $null
                            AUProtection = $null
                        }
                        
                        # Add a placeholder role assignment to ensure they appear in the report
                        $privilegedUsers[$searchedUser.Id].ActiveRoles += @{
                            RoleName = "Privileged User (Detected via Search)"
                            RoleId = $null
                            AssignmentType = "Detected"
                        }
                        
                        # Track role statistics
                        if (-not $roleStats.ContainsKey("Privileged User (Detected via Search)")) {
                            $roleStats["Privileged User (Detected via Search)"] = @{
                                RoleName = "Privileged User (Detected via Search)"
                                RoleId = $null
                                Type = "Detection"
                                ActiveCount = 0
                                EligibleCount = 0
                                GroupBasedCount = 0
                                PIMGroupEligibleCount = 0
                                TotalUniqueUsers = 0
                                Users = @()
                            }
                        }
                        $roleStats["Privileged User (Detected via Search)"].ActiveCount++
                    }
                }
            }
        }
        
        if ($foundTargetedUsers -gt 0) {
            Write-Log "Found $foundTargetedUsers additional privileged users through targeted search" -Level "SUCCESS"
        } else {
            Write-Log "No additional privileged users found through targeted search" -Level "INFO"
        }
    }
    catch {
        Write-Log "Error during targeted privilege search: $($_.Exception.Message)" -Level "WARNING"
    }
    
    Write-Log "Calculating statistics..." -Level "INFO"
    foreach ($user in $privilegedUsers.Values) {
        $allRoles = @()
        $allRoles += $user.ActiveRoles.RoleName
        $allRoles += $user.EligibleRoles.RoleName
        if ($IncludeGroups) {
            $allRoles += $user.GroupBasedRoles.RoleName
        }
        $allRoles += $user.PIMGroupEligibleRoles.RoleName
        
        $uniqueRoles = $allRoles | Select-Object -Unique
        
        foreach ($roleName in $uniqueRoles) {
            if ($roleStats.ContainsKey($roleName)) {
                $roleStats[$roleName].Users += @{
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                }
                $roleStats[$roleName].TotalUniqueUsers = $roleStats[$roleName].Users.Count
            }
        }
    }
    
    # Get MFA status for all privileged users
    if ($availableFeatures.MFAStatus) {
        Write-Log "Retrieving MFA status for $($privilegedUsers.Count) privileged users..." -Level "INFO"
        $mfaRetrievalCount = 0
        foreach ($userId in $privilegedUsers.Keys) {
            $mfaRetrievalCount++
            if ($mfaRetrievalCount % 10 -eq 0) {
                Write-Log "Retrieved MFA status for $mfaRetrievalCount/$($privilegedUsers.Count) users..." -Level "INFO"
            }
            $privilegedUsers[$userId].MFAStatus = Get-UserMFAStatus -UserId $userId
        }
    }
    else {
        Write-Log "Skipping MFA status retrieval (missing UserAuthenticationMethod.Read.All)" -Level "WARNING"
        foreach ($userId in $privilegedUsers.Keys) {
            $privilegedUsers[$userId].MFAStatus = Get-UserMFAStatus -UserId $userId
        }
    }
    
    # Check AU protection for all privileged users
    Write-Log "Checking restricted AU protection for $($privilegedUsers.Count) privileged users..." -Level "INFO"
    $auCheckCount = 0
    foreach ($userId in $privilegedUsers.Keys) {
        $auCheckCount++
        if ($auCheckCount % 10 -eq 0) {
            Write-Log "Checked AU protection for $auCheckCount/$($privilegedUsers.Count) users..." -Level "INFO"
        }
        $privilegedUsers[$userId].AUProtection = Test-UserInRestrictedAU -UserId $userId
    }
    
    # Check cross-tenant inbound MFA trust for privileged B2B guests
    Write-Log "Retrieving cross-tenant access settings..." -Level "INFO"
    $crossTenantPolicy = Get-CrossTenantAccessPolicy -Force
    if ($crossTenantPolicy.Available) {
        $trustedPartners = @($crossTenantPolicy.Partners.Values | Where-Object { $_.MfaAccepted }).Count
        Write-Log "Cross-tenant access: default inbound MFA trust = $($crossTenantPolicy.DefaultMfaAccepted); $($crossTenantPolicy.Partners.Count) partner(s), $trustedPartners with MFA trust" -Level "INFO"
    }
    else {
        Write-Log "Could not read cross-tenant access settings (needs Policy.Read.All): $($crossTenantPolicy.Error)" -Level "WARNING"
    }
    
    foreach ($userId in $privilegedUsers.Keys) {
        $upn = $privilegedUsers[$userId].UserPrincipalName
        # UserType is not captured on every collection path; the #EXT# marker identifies B2B guests.
        $userType = if ($upn -like '*#EXT#@*') { 'Guest' } else { 'Member' }
        $privilegedUsers[$userId].MFATrust = Get-CrossTenantMfaTrust -UserPrincipalName $upn -UserType $userType -Policy $crossTenantPolicy
    }
    
    $guestsCoveredByTrust = @($privilegedUsers.Values | Where-Object {
        $_.MFAStatus.MFACapable -eq $false -and $_.MFATrust.Status -eq 'Trusted'
    }).Count
    if ($guestsCoveredByTrust -gt 0) {
        Write-Log "$guestsCoveredByTrust privileged guest(s) without local MFA are covered by inbound MFA trust" -Level "INFO"
    }
    
    # Calculate MFA statistics (handle null when permission missing)
    # Use @() to force array conversion for accurate .Count when single item returned
    $mfaEnabledCount = @($privilegedUsers.Values | Where-Object { $_.MFAStatus.MFACapable -eq $true }).Count
    $mfaDisabledCount = @($privilegedUsers.Values | Where-Object { $_.MFAStatus.MFACapable -eq $false }).Count
    $mfaUnknownCount = @($privilegedUsers.Values | Where-Object { $null -eq $_.MFAStatus.MFACapable }).Count
    
    # Calculate account status statistics
    # Use @() to force array conversion for accurate .Count when single item returned
    $accountsEnabledCount = @($privilegedUsers.Values | Where-Object { $_.AccountEnabled }).Count
    $accountsDisabledCount = $privilegedUsers.Count - $accountsEnabledCount
    
    # Calculate AU protection statistics
    $auProtectedCount = @($privilegedUsers.Values | Where-Object { $_.AUProtection.IsProtected }).Count
    $auUnprotectedCount = $privilegedUsers.Count - $auProtectedCount
    
    # Calculate risk statistics - separate phone MFA and AU protection risks
    # Use @() to force array conversion for accurate .Count when single item returned
    
    # CRITICAL: Users with no MFA at all
    $noMFA = @($privilegedUsers.Values | Where-Object { 
        ($_.MFAStatus.MFACapable -eq $false)
    })
    $noMFACount = $noMFA.Count
    
    $phoneRiskOnly = @($privilegedUsers.Values | Where-Object { 
        ($_.MFAStatus.MFACapable -eq $true) -and ($_.MFAStatus.HasPhone -eq $true) -and ($_.AUProtection.IsProtected -eq $true)
    })
    $phoneRiskOnlyCount = $phoneRiskOnly.Count
    
    $noAUOnly = @($privilegedUsers.Values | Where-Object { 
        ($_.MFAStatus.MFACapable -eq $true) -and ($_.MFAStatus.HasPhone -eq $false) -and ($_.AUProtection.IsProtected -eq $false)
    })
    $noAUOnlyCount = $noAUOnly.Count
    
    $bothRisks = @($privilegedUsers.Values | Where-Object { 
        ($_.MFAStatus.MFACapable -eq $true) -and ($_.MFAStatus.HasPhone -eq $true) -and ($_.AUProtection.IsProtected -eq $false)
    })
    $bothRisksCount = $bothRisks.Count
    
    $fullSecure = @($privilegedUsers.Values | Where-Object { 
        ($_.MFAStatus.MFACapable -eq $true) -and ($_.MFAStatus.HasPhone -eq $false) -and ($_.AUProtection.IsProtected -eq $true)
    })
    $fullSecureCount = $fullSecure.Count
    
    $unknownRisk = @($privilegedUsers.Values | Where-Object { 
        ($null -eq $_.MFAStatus.MFACapable)
    })
    $unknownRiskCount = $unknownRisk.Count
    
    Write-Log "Found $($privilegedUsers.Count) privileged users, $($privilegedServicePrincipals.Count) service principals, and $($privilegedGroups.Count) groups across $($roleStats.Count) roles" -Level "SUCCESS"
    
    # Diagnostic information to help understand what we found
    Write-Log "=== DIAGNOSTIC INFORMATION ===" -Level "INFO"
    Write-Log "Total role assignments found: $($activeAssignments.Count + $eligibleAssignments.Count)" -Level "INFO"
    Write-Log "  - Active assignments: $($activeAssignments.Count)" -Level "INFO"  
    Write-Log "  - PIM eligible assignments: $($eligibleAssignments.Count)" -Level "INFO"
    Write-Log "  - Total user assignments found: $(($privilegedUsers.Keys | Measure-Object).Count)" -Level "INFO"
    Write-Log "  - Non-user principals (groups/service principals): $(($activeAssignments.Count + $eligibleAssignments.Count) - (($privilegedUsers.Values | ForEach-Object { $_.ActiveRoles.Count + $_.EligibleRoles.Count } | Measure-Object -Sum).Sum))" -Level "INFO"
    
    # List the service principals that have role assignments for diagnostic purposes
    $servicePrincipalsWithRoles = @()
    foreach ($assignment in $activeAssignments) {
        $principalId = $assignment.principalId
        $userDetails = Get-UserDetails -UserId $principalId
        if (-not $userDetails) {
            try {
                # Try to get as group
                $group = Get-MgGroup -GroupId $principalId -ErrorAction Stop
                # This is a group, not a service principal
            }
            catch {
                # This is likely a service principal
                try {
                    $sp = Get-MgServicePrincipal -ServicePrincipalId $principalId -ErrorAction Stop
                    $roleDefinition = Get-RoleDefinitionDetails -RoleDefinitionId $assignment.roleDefinitionId
                    $servicePrincipalsWithRoles += @{
                        DisplayName = $sp.DisplayName
                        Id = $sp.Id
                        RoleName = $roleDefinition.displayName
                        AppId = $sp.AppId
                    }
                }
                catch {
                    # Unknown principal type
                    $servicePrincipalsWithRoles += @{
                        DisplayName = "Unknown"
                        Id = $principalId
                        RoleName = "Unknown"
                        AppId = "Unknown"
                    }
                }
            }
        }
    }
    
    if ($servicePrincipalsWithRoles.Count -gt 0) {
        Write-Log "Service principals with role assignments:" -Level "INFO"
        foreach ($sp in $servicePrincipalsWithRoles) {
            Write-Log "  - $($sp.DisplayName) ($($sp.Id)): $($sp.RoleName)" -Level "INFO"
        }
    }
    Write-Log "=== END DIAGNOSTIC INFORMATION ===" -Level "INFO"
    
    # Warn if no users found and permissions are missing
    if ($privilegedUsers.Count -eq 0) {
        if (-not $availableFeatures.ActiveRoleAssignments -and -not $availableFeatures.PIMEligibleAssignments) {
            Write-Host ""
            Write-Host "⚠ NO PRIVILEGED USERS FOUND" -ForegroundColor Red
            Write-Host ""
            Write-Host "This is likely because the following permissions are missing:" -ForegroundColor Yellow
            Write-Host "  - RoleManagement.Read.Directory (for active role assignments)" -ForegroundColor Yellow
            Write-Host "  - RoleEligibilitySchedule.Read.Directory (for PIM eligible assignments)" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Please add these permissions and try again." -ForegroundColor Yellow
            Write-Host ""
            return
        }
    }
    
    # Display account-focused report
    Write-Host "`n" -NoNewline
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                    PRIVILEGED ACCOUNT SUMMARY REPORT                         " -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Report generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
    
    # ============================================================================
    # PART 1: ROLE DETAILS - Show each role with its assigned users
    # ============================================================================
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                    ROLE DISTRIBUTION & DETAILS                                " -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Sort roles by total unique users (descending)
    $sortedRoles = $roleStats.Values | Sort-Object -Property TotalUniqueUsers -Descending
    
    foreach ($role in $sortedRoles) {
        Write-Host "───────────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "Role: " -NoNewline -ForegroundColor Cyan
        Write-Host "$($role.RoleName)" -ForegroundColor White
        Write-Host ""
        Write-Host "  Active Assignments:      " -NoNewline -ForegroundColor Yellow
        Write-Host "$($role.ActiveCount)" -ForegroundColor White
        Write-Host "  PIM Eligible:            " -NoNewline -ForegroundColor Magenta
        Write-Host "$($role.EligibleCount)" -ForegroundColor White
        
        if ($IncludeGroups) {
            Write-Host "  Group-Based Assignments: " -NoNewline -ForegroundColor Blue
            Write-Host "$($role.GroupBasedCount)" -ForegroundColor White
        }
        
        if ($role.PIMGroupEligibleCount -gt 0) {
            Write-Host "  PIM Group Eligible:      " -NoNewline -ForegroundColor DarkMagenta
            Write-Host "$($role.PIMGroupEligibleCount)" -ForegroundColor White
        }
        
        Write-Host "  Total Unique Users:      " -NoNewline -ForegroundColor Green
        Write-Host "$($role.TotalUniqueUsers)" -ForegroundColor White
        Write-Host ""
        
        # Display users for this role
        $usersForRole = $privilegedUsers.Values | Where-Object {
            ($_.ActiveRoles.RoleName -contains $role.RoleName) -or
            ($_.EligibleRoles.RoleName -contains $role.RoleName) -or
            ($IncludeGroups -and ($_.GroupBasedRoles.RoleName -contains $role.RoleName)) -or
            ($_.PIMGroupEligibleRoles.RoleName -contains $role.RoleName)
        } | Sort-Object -Property DisplayName
        
        foreach ($user in $usersForRole) {
            $userActiveRoles = $user.ActiveRoles | Where-Object { $_.RoleName -eq $role.RoleName }
            $userEligibleRoles = $user.EligibleRoles | Where-Object { $_.RoleName -eq $role.RoleName }
            $userGroupRoles = $user.GroupBasedRoles | Where-Object { $_.RoleName -eq $role.RoleName }
            $userPIMGroupRoles = $user.PIMGroupEligibleRoles | Where-Object { $_.RoleName -eq $role.RoleName }
            
            # Build assignment type badges
            $assignmentBadges = @()
            if ($userActiveRoles) { $assignmentBadges += "[Active]" }
            if ($userEligibleRoles) { $assignmentBadges += "[PIM]" }
            if ($userGroupRoles) { $assignmentBadges += "[Group]" }
            if ($userPIMGroupRoles) { $assignmentBadges += "[PIM-Group]" }
            
            # Get MFA status
            $mfaStatus = $user.MFAStatus
            if ($null -eq $mfaStatus.MFACapable) {
                $mfaMethods = "Unknown"
            }
            elseif ($mfaStatus.MFACapable) {
                if ($mfaStatus.MethodsList.Count -gt 0) {
                    $mfaMethods = ($mfaStatus.MethodsList | ForEach-Object {
                        switch ($_) {
                            'Microsoft Authenticator' { 'MS Auth' }
                            'FIDO2 Security Key' { 'FIDO2' }
                            'Phone' { 'Phone' }
                            'Windows Hello' { 'Win Hello' }
                            'Software OATH' { 'OATH' }
                            'Temporary Access Pass' { 'TAP' }
                            'Email' { 'Email' }
                            default { $_ }
                        }
                    }) -join ', '
                }
                else {
                    $mfaMethods = "Registered"
                }
            }
            else {
                $mfaMethods = "NO MFA"
            }
            
            # Display user info in compact format
            Write-Host "  • " -NoNewline -ForegroundColor DarkGray
            Write-Host $user.DisplayName -NoNewline -ForegroundColor White
            
            # Assignment type badges
            Write-Host " " -NoNewline
            foreach ($badge in $assignmentBadges) {
                if ($badge -eq "[Active]") {
                    Write-Host $badge -NoNewline -ForegroundColor Yellow
                }
                elseif ($badge -eq "[PIM]") {
                    Write-Host $badge -NoNewline -ForegroundColor Magenta
                }
                elseif ($badge -eq "[PIM-Group]") {
                    Write-Host $badge -NoNewline -ForegroundColor DarkMagenta
                }
                else {
                    Write-Host $badge -NoNewline -ForegroundColor Blue
                }
                Write-Host " " -NoNewline
            }
            
            # Account status
            if (-not $user.AccountEnabled) {
                Write-Host "[DISABLED]" -NoNewline -ForegroundColor Red
                Write-Host " " -NoNewline
            }
            
            # Risk indicator - show specific risk level based on combined MFA and AU status
            $hasPhoneRisk = ($mfaStatus.HasPhone -eq $true)
            $hasAURisk = ($user.AUProtection.IsProtected -eq $false)
            $hasNoMFA = ($mfaStatus.MFACapable -eq $false)
            
            if ($null -eq $mfaStatus.MFACapable) {
                Write-Host "? [UNKNOWN RISK]" -NoNewline -ForegroundColor DarkGray
                Write-Host " " -NoNewline
            }
            elseif ($hasNoMFA) {
                Write-Host "🚨 [CRITICAL]" -NoNewline -ForegroundColor Red
                Write-Host " " -NoNewline
            }
            elseif ($hasPhoneRisk -and $hasAURisk) {
                Write-Host "🚨 [HIGH RISK]" -NoNewline -ForegroundColor Red
                Write-Host " " -NoNewline
            }
            elseif ($hasPhoneRisk -or $hasAURisk) {
                Write-Host "⚠️ [MEDIUM RISK]" -NoNewline -ForegroundColor Yellow
                Write-Host " " -NoNewline
            }
            else {
                Write-Host "✅ [LOW RISK]" -NoNewline -ForegroundColor Green
                Write-Host " " -NoNewline
            }
            
            # Phone-based MFA indicator
            if ($mfaStatus.HasPhone -eq $true) {
                Write-Host "[Phone MFA Risk]" -NoNewline -ForegroundColor Red
                Write-Host " " -NoNewline
            }
            
            # AU protection status
            if ($user.AUProtection.IsProtected) {
                Write-Host "[AU ✓]" -NoNewline -ForegroundColor Green
                Write-Host " " -NoNewline
            }
            else {
                Write-Host "[No AU ✗]" -NoNewline -ForegroundColor Red
                Write-Host " " -NoNewline
            }
            
            # MFA status
            if ($null -eq $mfaStatus.MFACapable) {
                Write-Host "? MFA Unknown" -ForegroundColor Yellow
            }
            elseif ($mfaStatus.MFACapable) {
                Write-Host "✓ MFA" -ForegroundColor Green
            }
            else {
                Write-Host "✗ NO MFA" -ForegroundColor Red
            }
            
            # Second line: UPN and MFA methods
            Write-Host "    $($user.UserPrincipalName)" -NoNewline -ForegroundColor DarkGray
            if ($mfaStatus.MFACapable) {
                Write-Host " | Methods: " -NoNewline -ForegroundColor DarkGray
                Write-Host $mfaMethods -NoNewline -ForegroundColor Cyan
                
                # Display phone numbers if present
                if ($mfaStatus.PhoneNumbers.Count -gt 0) {
                    Write-Host " | Phone(s): " -NoNewline -ForegroundColor Yellow
                    Write-Host ($mfaStatus.PhoneNumbers -join ', ') -NoNewline -ForegroundColor Yellow
                }
                
                # Display AU protection info
                if ($user.AUProtection.IsProtected) {
                    Write-Host " | AU: " -NoNewline -ForegroundColor DarkGray
                    Write-Host $user.AUProtection.AUName -ForegroundColor Green
                }
                else {
                    Write-Host ""
                }
            }
            else {
                Write-Host ""
            }
        }
        
        Write-Host ""
    }
    
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # ============================================================================
    # PART 2: ACCOUNT DETAILS - Show each user/principal with their roles
    # ============================================================================

    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                    DETAILED ACCOUNT ANALYSIS                                 " -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Combine all privileged accounts for unified display
    $allPrivilegedAccounts = @()
    
    # Add users
    foreach ($user in $privilegedUsers.Values) {
        $allPrivilegedAccounts += @{
            Type = "User"
            DisplayName = $user.DisplayName
            Identifier = $user.UserPrincipalName
            AccountEnabled = $user.AccountEnabled
            MFAStatus = $user.MFAStatus
            AUProtection = $user.AUProtection
            MFATrust = $user.MFATrust
            ActiveRoles = $user.ActiveRoles
            EligibleRoles = $user.EligibleRoles
            GroupBasedRoles = $user.GroupBasedRoles
            PIMGroupEligibleRoles = $user.PIMGroupEligibleRoles
            SortKey = "1_$($user.DisplayName)"
        }
    }
    
    # Add service principals
    foreach ($sp in $privilegedServicePrincipals.Values) {
        $allPrivilegedAccounts += @{
            Type = "Service Principal"
            DisplayName = $sp.DisplayName
            Identifier = "App ID: $($sp.AppId)"
            AccountEnabled = $true  # Service principals are typically enabled if they have role assignments
            MFAStatus = $null  # N/A for service principals
            AUProtection = $null  # N/A for service principals
            ActiveRoles = $sp.ActiveRoles
            EligibleRoles = $sp.EligibleRoles
            GroupBasedRoles = @()
            PIMGroupEligibleRoles = @()
            SortKey = "2_$($sp.DisplayName)"
        }
    }
    
    # Add groups
    foreach ($group in $privilegedGroups.Values) {
        $allPrivilegedAccounts += @{
            Type = "Role-Assignable Group"
            DisplayName = $group.DisplayName
            Identifier = "$($group.MemberCount) members"
            AccountEnabled = $true  # Groups don't have enabled/disabled status in same way
            MFAStatus = $null  # N/A for groups
            AUProtection = $null  # N/A for groups
            ActiveRoles = $group.ActiveRoles
            EligibleRoles = $group.EligibleRoles
            GroupBasedRoles = @()  
            PIMGroupEligibleRoles = @()
            SortKey = "3_$($group.DisplayName)"
            Members = $group.Members
        }
    }
    
    # Sort all accounts by type first, then name
    $sortedAccounts = $allPrivilegedAccounts | Sort-Object SortKey
    
    foreach ($account in $sortedAccounts) {
        # Account header with type indicator
        $typeEmojiMap = @{
            "User" = "👤"
            "Service Principal" = "🔧"
            "Role-Assignable Group" = "👥"
        }
        
        Write-Host "$($typeEmojiMap[$account.Type]) " -NoNewline -ForegroundColor White
        Write-Host "$($account.DisplayName)" -NoNewline -ForegroundColor White
        Write-Host " [$($account.Type)]" -ForegroundColor DarkGray
        Write-Host "   $($account.Identifier)" -ForegroundColor DarkGray
        
        # Show account status for users
        if ($account.Type -eq "User") {
            # Calculate risk level (same logic as CSV export)
            $mfaStatus = $account.MFAStatus
            $hasPhoneRisk = ($mfaStatus.HasPhone -eq $true)
            $hasAURisk = ($account.AUProtection.IsProtected -eq $false)
            $hasNoMFA = ($mfaStatus.MFACapable -eq $false)
            
            $riskLevel = if ($null -eq $mfaStatus.MFACapable) {
                "Unknown"
            } elseif ($hasNoMFA) {
                "Critical"
            } elseif ($hasPhoneRisk -and $hasAURisk) {
                "High"
            } elseif ($hasPhoneRisk -and -not $hasAURisk) {
                "Medium"
            } elseif (-not $hasPhoneRisk -and $hasAURisk) {
                "Medium"
            } else {
                "Low"
            }
            
            # A guest's MFA happens in their home tenant, so "no MFA" here is not the whole picture
            # when inbound MFA trust makes this tenant accept that home tenant's MFA claim.
            if ($riskLevel -eq "Critical" -and $account.MFATrust.Status -eq "Trusted") {
                $riskLevel = "Medium"
            }
            
            # Display comprehensive security status line
            Write-Host "   Risk: " -NoNewline -ForegroundColor DarkGray
            switch ($riskLevel) {
                "Critical" { Write-Host "🚨 CRITICAL" -NoNewline -ForegroundColor Red }
                "High" { Write-Host "🚨 HIGH" -NoNewline -ForegroundColor Red }
                "Medium" { Write-Host "⚠️ MEDIUM" -NoNewline -ForegroundColor Yellow }
                "Low" { Write-Host "✅ LOW" -NoNewline -ForegroundColor Green }
                "Unknown" { Write-Host "❓ UNKNOWN" -NoNewline -ForegroundColor DarkGray }
            }
            
            # Account enabled/disabled status
            Write-Host " | Account: " -NoNewline -ForegroundColor DarkGray
            if ($account.AccountEnabled) {
                Write-Host "✅ Enabled" -NoNewline -ForegroundColor Green
            } else {
                Write-Host "❌ Disabled" -NoNewline -ForegroundColor Red
            }
            
            # MFA status
            Write-Host " | MFA: " -NoNewline -ForegroundColor DarkGray
            if ($null -eq $mfaStatus.MFACapable) {
                Write-Host "❓ Unknown" -NoNewline -ForegroundColor DarkGray
            } elseif ($mfaStatus.MFACapable) {
                Write-Host "✅ Yes" -NoNewline -ForegroundColor Green
            } else {
                Write-Host "❌ No" -NoNewline -ForegroundColor Red
            }
            
            # Inbound MFA trust for guests whose MFA happens in their home tenant
            if ($account.MFATrust -and $account.MFATrust.Status -ne 'N/A') {
                Write-Host " | Home tenant MFA: " -NoNewline -ForegroundColor DarkGray
                switch ($account.MFATrust.Status) {
                    "Trusted"     { Write-Host "✅ Trusted ($($account.MFATrust.HomeTenant))" -NoNewline -ForegroundColor Green }
                    "Not trusted" { Write-Host "❌ Not trusted ($($account.MFATrust.HomeTenant))" -NoNewline -ForegroundColor Red }
                    default       { Write-Host "❓ Unknown" -NoNewline -ForegroundColor DarkGray }
                }
            }
            
            # SMS/Phone MFA status (separate field)
            Write-Host " | SMS: " -NoNewline -ForegroundColor DarkGray
            if ($null -eq $mfaStatus.HasPhone) {
                Write-Host "❓ Unknown" -NoNewline -ForegroundColor DarkGray
            } elseif ($mfaStatus.HasPhone -eq $true) {
                Write-Host "⚠️ Yes" -NoNewline -ForegroundColor Yellow
            } else {
                Write-Host "✅ No" -NoNewline -ForegroundColor Green
            }
            
            # RMAU protection status
            Write-Host " | RMAU: " -NoNewline -ForegroundColor DarkGray
            if ($account.AUProtection.IsProtected) {
                Write-Host "🔒 Yes" -ForegroundColor Green
            } else {
                Write-Host "🔓 No" -ForegroundColor Red
            }
        } else {
            Write-Host ""
        }
        
        # Show all roles and assignments for this account
        $hasAnyRoles = $false
        
        # Active Roles
        if ($account.ActiveRoles.Count -gt 0) {
            $hasAnyRoles = $true
            Write-Host ""
            Write-Host "   🔴 ACTIVE ROLE ASSIGNMENTS ($($account.ActiveRoles.Count)):" -ForegroundColor Red
            foreach ($role in $account.ActiveRoles) {
                Write-Host "      • " -NoNewline -ForegroundColor DarkGray
                Write-Host "$($role.RoleName)" -ForegroundColor Yellow
            }
        }
        
        # PIM Eligible Roles
        if ($account.EligibleRoles.Count -gt 0) {
            $hasAnyRoles = $true
            Write-Host ""
            Write-Host "   🟡 PIM ELIGIBLE ROLES ($($account.EligibleRoles.Count)):" -ForegroundColor Magenta
            foreach ($role in $account.EligibleRoles) {
                Write-Host "      • " -NoNewline -ForegroundColor DarkGray
                Write-Host "$($role.RoleName)" -ForegroundColor Magenta
            }
        }
        
        # Group-Based Roles (for users)
        if ($account.GroupBasedRoles.Count -gt 0) {
            $hasAnyRoles = $true
            
            # Filter out redundant "PIM Group Active Member" entries
            # Skip if the same group (or its nested path) grants actual roles
            $filteredGroupRoles = @()
            foreach ($role in $account.GroupBasedRoles) {
                if ($role.RoleName -eq "PIM Group Active Member") {
                    # Check if this group appears in the path of any actual roles
                    $groupGrantsActualRoles = $false
                    $baseGroupName = $role.GroupName
                    
                    foreach ($otherRole in ($account.GroupBasedRoles + $account.PIMGroupEligibleRoles)) {
                        if ($otherRole.RoleName -ne "PIM Group Active Member") {
                            # Check if the base group name appears at the start of the other role's group path
                            # This handles cases like "PIM – PIM – User admin" being the start of 
                            # "PIM – PIM – User admin → PIM - User admin [PIM]"
                            if ($otherRole.GroupName -eq $baseGroupName -or 
                                $otherRole.GroupName -like "$baseGroupName *" -or
                                $otherRole.GroupName -like "$baseGroupName → *") {
                                $groupGrantsActualRoles = $true
                                break
                            }
                        }
                    }
                    
                    if (-not $groupGrantsActualRoles) {
                        $filteredGroupRoles += $role
                    }
                } else {
                    $filteredGroupRoles += $role
                }
            }
            
            if ($filteredGroupRoles.Count -gt 0) {
                Write-Host ""
                Write-Host "   🔵 ROLES VIA GROUP MEMBERSHIP ($($filteredGroupRoles.Count)):" -ForegroundColor Blue
                foreach ($role in $filteredGroupRoles) {
                    Write-Host "      • " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($role.RoleName)" -NoNewline -ForegroundColor Blue
                    Write-Host " [via Group: " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($role.GroupName)" -NoNewline -ForegroundColor Cyan
                    Write-Host "]" -ForegroundColor DarkGray
                }
            }
        }
        
        # PIM Group Eligible Roles (for users)
        if ($account.PIMGroupEligibleRoles.Count -gt 0) {
            $hasAnyRoles = $true
            Write-Host ""
            Write-Host "   🟣 PIM ELIGIBLE FOR GROUP ROLES ($($account.PIMGroupEligibleRoles.Count)):" -ForegroundColor DarkMagenta
            foreach ($role in $account.PIMGroupEligibleRoles) {
                Write-Host "      • " -NoNewline -ForegroundColor DarkGray
                Write-Host "$($role.RoleName)" -NoNewline -ForegroundColor DarkMagenta
                Write-Host " [PIM Group: " -NoNewline -ForegroundColor DarkGray
                Write-Host "$($role.GroupName)" -NoNewline -ForegroundColor Cyan
                Write-Host "]" -ForegroundColor DarkGray
            }
        }
        
        # Show sample group members for role-assignable groups
        if ($account.Type -eq "Role-Assignable Group" -and $account.Members.Count -gt 0) {
            Write-Host ""
            Write-Host "   👤 SAMPLE MEMBERS:" -ForegroundColor DarkGray
            $sampleMembers = $account.Members | Select-Object -First 5
            foreach ($member in $sampleMembers) {
                Write-Host "      • " -NoNewline -ForegroundColor DarkGray
                Write-Host "$($member.DisplayName)" -NoNewline -ForegroundColor White
                Write-Host " (" -NoNewline -ForegroundColor DarkGray
                Write-Host "$($member.UserPrincipalName)" -NoNewline -ForegroundColor DarkGray
                Write-Host ")" -ForegroundColor DarkGray
            }
            if ($account.Members.Count -gt 5) {
                Write-Host "      ... and $($account.Members.Count - 5) more members" -ForegroundColor DarkGray
            }
        }
        
        # Summary line
        if ($hasAnyRoles) {
            # Calculate filtered group roles count (exclude redundant "PIM Group Active Member" entries)
            $filteredGroupRolesCount = 0
            foreach ($role in $account.GroupBasedRoles) {
                if ($role.RoleName -eq "PIM Group Active Member") {
                    # Check if this group appears in the path of any actual roles
                    $groupGrantsActualRoles = $false
                    $baseGroupName = $role.GroupName
                    
                    foreach ($otherRole in ($account.GroupBasedRoles + $account.PIMGroupEligibleRoles)) {
                        if ($otherRole.RoleName -ne "PIM Group Active Member") {
                            # Check if the base group name appears at the start of the other role's group path
                            if ($otherRole.GroupName -eq $baseGroupName -or 
                                $otherRole.GroupName -like "$baseGroupName *" -or
                                $otherRole.GroupName -like "$baseGroupName → *") {
                                $groupGrantsActualRoles = $true
                                break
                            }
                        }
                    }
                    if (-not $groupGrantsActualRoles) {
                        $filteredGroupRolesCount++
                    }
                } else {
                    $filteredGroupRolesCount++
                }
            }
            
            $totalRoles = $account.ActiveRoles.Count + $account.EligibleRoles.Count + $filteredGroupRolesCount + $account.PIMGroupEligibleRoles.Count
            Write-Host ""
            Write-Host "   📊 TOTAL PRIVILEGE ASSIGNMENTS: " -NoNewline -ForegroundColor DarkGray
            Write-Host "$totalRoles" -ForegroundColor White
        } else {
            Write-Host ""
            Write-Host "   ⚠️  NO DIRECT ROLE ASSIGNMENTS FOUND" -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Host "   " + ("─" * 75) -ForegroundColor DarkGray
        Write-Host ""
    }
    
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # ============================================================================
    # PART 3: COMBINED SUMMARY - Overall statistics for users, roles, and security
    # ============================================================================
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                    OVERALL SUMMARY                                           " -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Principal Counts
    Write-Host "📊 PRIVILEGED PRINCIPALS" -ForegroundColor Yellow
    Write-Host "══════════════════════════" -ForegroundColor Yellow
    Write-Host "Total Privileged Users:       " -NoNewline -ForegroundColor Cyan
    Write-Host "$($privilegedUsers.Count)" -ForegroundColor White
    Write-Host "Total Service Principals:     " -NoNewline -ForegroundColor Cyan  
    Write-Host "$($privilegedServicePrincipals.Count)" -ForegroundColor White
    Write-Host "Total Role-Assignable Groups: " -NoNewline -ForegroundColor Cyan
    Write-Host "$($roleAssignableGroups.Count)" -ForegroundColor White
    Write-Host "Total Roles Assigned:         " -NoNewline -ForegroundColor Cyan
    Write-Host "$($roleStats.Count)" -ForegroundColor White
    Write-Host ""
    
    # Role Distribution Summary
    Write-Host "🎯 TOP ROLES BY ASSIGNMENT COUNT" -ForegroundColor Yellow
    Write-Host "═════════════════════════════════" -ForegroundColor Yellow
    $sortedRolesSummary = $roleStats.Values | Sort-Object -Property TotalUniqueUsers -Descending | Select-Object -First 10
    foreach ($role in $sortedRolesSummary) {
        $totalAssignments = $role.ActiveCount + $role.EligibleCount + $role.GroupBasedCount + $role.PIMGroupEligibleCount
        Write-Host "• " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($role.RoleName)" -NoNewline -ForegroundColor White
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$totalAssignments" -NoNewline -ForegroundColor Yellow
        Write-Host " assignments)" -ForegroundColor DarkGray
    }
    if ($roleStats.Count -gt 10) {
        Write-Host "  ... and $($roleStats.Count - 10) more roles" -ForegroundColor DarkGray
    }
    Write-Host ""
    
    # User Security Status
    Write-Host "🛡️ USER SECURITY STATUS" -ForegroundColor Yellow
    Write-Host "══════════════════════" -ForegroundColor Yellow
    Write-Host "Account Status:" -ForegroundColor Cyan
    Write-Host "  ✅ Enabled:  " -NoNewline -ForegroundColor Green
    Write-Host "$accountsEnabledCount" -ForegroundColor White
    Write-Host "  ❌ Disabled: " -NoNewline -ForegroundColor Red
    Write-Host "$accountsDisabledCount" -ForegroundColor White
    Write-Host ""
    
    Write-Host "MFA Status:" -ForegroundColor Cyan
    if ($availableFeatures.MFAStatus) {
        Write-Host "  ✅ MFA Enabled:  " -NoNewline -ForegroundColor Green
        Write-Host "$mfaEnabledCount" -ForegroundColor White
        Write-Host "  ❌ MFA Disabled: " -NoNewline -ForegroundColor Red
        Write-Host "$mfaDisabledCount" -ForegroundColor White
    }
    else {
        Write-Host "  ❓ MFA Status:   " -NoNewline -ForegroundColor Yellow
        Write-Host "Unknown (Missing Permission)" -ForegroundColor Yellow
    }
    Write-Host ""
    
    Write-Host "AU Protection:" -ForegroundColor Cyan
    Write-Host "  🔒 Protected (Restricted AU):   " -NoNewline -ForegroundColor Green
    Write-Host "$auProtectedCount" -ForegroundColor White
    Write-Host "  🔓 Not Protected (No Rest. AU): " -NoNewline -ForegroundColor Red
    Write-Host "$auUnprotectedCount" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Risk Assessment:" -ForegroundColor Cyan
    Write-Host "  ✅ Fully Secure (MFA without Phone, AU Protected):           " -NoNewline -ForegroundColor Green
    Write-Host "$fullSecureCount" -ForegroundColor White
    Write-Host "  ⚠️  Medium risk: Phone MFA Risk Only (Phone as MFA, Has AU): " -NoNewline -ForegroundColor Yellow
    Write-Host "$phoneRiskOnlyCount" -ForegroundColor White
    Write-Host "  ⚠️  Medium risk: No AU Protection Only (MFA without phone):   " -NoNewline -ForegroundColor Yellow
    Write-Host "$noAUOnlyCount" -ForegroundColor White
    Write-Host "  🚨 High risk: Both Risks (MFA with Phone + No AU):           " -NoNewline -ForegroundColor Red
    Write-Host "$bothRisksCount" -ForegroundColor White
    Write-Host "  🚨 CRITICAL - No MFA:                                        " -NoNewline -ForegroundColor Red
    Write-Host "$noMFACount" -ForegroundColor White
    if ($unknownRiskCount -gt 0) {
        Write-Host "  ❓ Unknown MFA Status:                      " -NoNewline -ForegroundColor DarkGray
        Write-Host "$unknownRiskCount" -ForegroundColor DarkGray
    }
    Write-Host ""
    
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # ============================================================================
    # PART 4: EXPORT PROMPT
    # ============================================================================
    Write-Host "Export options:" -ForegroundColor Yellow
    Write-Host "  [1] CSV (role distribution + user status)" -ForegroundColor White
    Write-Host "  [2] Interactive HTML report" -ForegroundColor White
    Write-Host "  [3] Both" -ForegroundColor White
    Write-Host "  [4] None" -ForegroundColor White
    Write-Host ""
    Write-Host "Select an option (1-4): " -NoNewline -ForegroundColor Yellow
    $response = Read-Host

    $exportToCsv = $response -in @('1', '3')
    $exportToHtml = $response -in @('2', '3')

    $exportDirectory = $null
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    if ($exportToCsv -or $exportToHtml) {
        $exportDirectory = Join-Path $PSScriptRoot "exports"
        if (-not (Test-Path $exportDirectory)) {
            try {
                New-Item -ItemType Directory -Path $exportDirectory -Force | Out-Null
                Write-Host ""
                Write-Host "Created exports directory: $exportDirectory" -ForegroundColor Green
            }
            catch {
                Write-Host ""
                Write-Host "Failed to create exports directory, using Logs directory instead" -ForegroundColor Yellow
                $exportDirectory = $LogDirectory
            }
        }
    }

    # Export to CSV if requested
    if ($exportToCsv) {
        $roleDistributionPath = Join-Path $exportDirectory "RoleDistribution-$timestamp.csv"
        $userStatusPath = Join-Path $exportDirectory "UserStatus-$timestamp.csv"
        
        Write-Host ""
        Write-Host "Exporting to:" -ForegroundColor Cyan
        Write-Host "  1. Role Distribution: $roleDistributionPath" -ForegroundColor White
        Write-Host "  2. User Status: $userStatusPath" -ForegroundColor White
        Write-Host ""
        
        Write-Log "Exporting role distribution data to CSV..." -Level "INFO"
        
        # ============================================================================
        # EXPORT 1: ROLE DISTRIBUTION
        # ============================================================================
        $roleDistributionData = @()
        foreach ($role in $roleStats.Values) {
            $roleDistributionData += [PSCustomObject]@{
                RoleName = $role.RoleName
                RoleId = $role.RoleId
                Type = $role.Type
                ActiveAssignments = $role.ActiveCount
                PIMEligible = $role.EligibleCount
                GroupBasedAssignments = $role.GroupBasedCount
                PIMGroupEligible = $role.PIMGroupEligibleCount
                TotalUniqueUsers = $role.TotalUniqueUsers
            }
        }
        
        $roleDistributionData | Sort-Object -Property TotalUniqueUsers -Descending | 
            Export-Csv -Path $roleDistributionPath -NoTypeInformation -Encoding UTF8
        Write-Log "Role distribution CSV exported to: $roleDistributionPath" -Level "SUCCESS"
        Write-Host "✓ Role distribution exported" -ForegroundColor Green
        
        # ============================================================================
        # EXPORT 2: USER STATUS DETAILS
        # ============================================================================
        Write-Log "Exporting user status data to CSV..." -Level "INFO"
        
        $exportData = @()
        foreach ($user in $privilegedUsers.Values) {
            $mfaStatus = $user.MFAStatus
            $mfaMethods = if ($null -eq $mfaStatus.MFACapable) { 
                "Unknown" 
            } elseif ($mfaStatus.MethodsList.Count -gt 0) { 
                $mfaStatus.MethodsList -join '; ' 
            } else { 
                "None" 
            }
            $mfaEnabled = if ($null -eq $mfaStatus.MFACapable) { 
                "Unknown" 
            } elseif ($mfaStatus.MFACapable) { 
                "Yes" 
            } else { 
                "No" 
            }
            $accountStatus = if ($user.AccountEnabled) { "Enabled" } else { "Disabled" }
            
            # Calculate risk level for this user
            $hasPhoneRisk = ($mfaStatus.HasPhone -eq $true)
            $hasAURisk = ($user.AUProtection.IsProtected -eq $false)
            $hasNoMFA = ($mfaStatus.MFACapable -eq $false)
            $riskLevel = if ($null -eq $mfaStatus.MFACapable) {
                "Unknown"
            } elseif ($hasNoMFA) {
                "Critical (No MFA)"
            } elseif ($hasPhoneRisk -and $hasAURisk) {
                "High (Phone MFA + No AU)"
            } elseif ($hasPhoneRisk -and -not $hasAURisk) {
                "Medium (Phone MFA, Has AU)"
            } elseif (-not $hasPhoneRisk -and $hasAURisk) {
                "Medium (MFA, No AU)"
            } else {
                "Low (Secure)"
            }
            
            # A guest's MFA happens in their home tenant, so "no MFA" here is not the whole picture
            # when inbound MFA trust makes this tenant accept that home tenant's MFA claim.
            if ($riskLevel -eq "Critical (No MFA)" -and $user.MFATrust.Status -eq "Trusted") {
                $riskLevel = "Medium (Home tenant MFA trusted)"
            }
            $mfaTrustStatus = if ($user.MFATrust) { $user.MFATrust.Status } else { "N/A" }
            $homeTenant = if ($user.MFATrust) { $user.MFATrust.HomeTenant } else { "" }
            
            # Create rows for active assignments
            foreach ($role in $user.ActiveRoles) {
                $exportData += [PSCustomObject]@{
                    PrincipalType = "User"
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    UserId = $user.UserId
                    AccountEnabled = $accountStatus
                    RoleName = $role.RoleName
                    RoleId = $role.RoleId
                    AssignmentType = "Active"
                    GroupName = ""
                    GroupId = ""
                    MFAEnabled = $mfaEnabled
                    MFAMethods = $mfaMethods
                    MethodCount = $mfaStatus.MethodCount
                    HasPhoneMFA = if ($null -eq $mfaStatus.HasPhone) { "Unknown" } elseif ($mfaStatus.HasPhone) { "Yes" } else { "No" }
                    AUProtected = if ($user.AUProtection.IsProtected) { "Yes" } else { "No" }
                    AUName = $user.AUProtection.AUName
                    MFATrust = $mfaTrustStatus
                    HomeTenant = $homeTenant
                    RiskLevel = $riskLevel
                }
            }
            
            # Create rows for eligible assignments
            foreach ($role in $user.EligibleRoles) {
                $exportData += [PSCustomObject]@{
                    PrincipalType = "User"
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    UserId = $user.UserId
                    AccountEnabled = $accountStatus
                    RoleName = $role.RoleName
                    RoleId = $role.RoleId
                    AssignmentType = "PIM Eligible"
                    GroupName = ""
                    GroupId = ""
                    MFAEnabled = $mfaEnabled
                    MFAMethods = $mfaMethods
                    MethodCount = $mfaStatus.MethodCount
                    HasPhoneMFA = if ($null -eq $mfaStatus.HasPhone) { "Unknown" } elseif ($mfaStatus.HasPhone) { "Yes" } else { "No" }
                    AUProtected = if ($user.AUProtection.IsProtected) { "Yes" } else { "No" }
                    AUName = $user.AUProtection.AUName
                    MFATrust = $mfaTrustStatus
                    HomeTenant = $homeTenant
                    RiskLevel = $riskLevel
                }
            }
            
            # Create rows for group-based assignments
            if ($IncludeGroups) {
                foreach ($role in $user.GroupBasedRoles) {
                    # Skip "PIM Group Active Member" entries if the same group grants actual roles
                    if ($role.RoleName -eq "PIM Group Active Member") {
                        # Check if this user has any other role entries (actual roles) that involve this same group
                        $hasActualRolesFromSameGroup = $false
                        
                        # Check in GroupBasedRoles for actual roles from this group or nested paths containing it
                        foreach ($otherRole in $user.GroupBasedRoles) {
                            if ($otherRole.RoleName -ne "PIM Group Active Member" -and 
                                ($otherRole.GroupId -eq $role.GroupId -or $otherRole.GroupName -like "*$($role.GroupName)*")) {
                                $hasActualRolesFromSameGroup = $true
                                break
                            }
                        }
                        
                        # Also check in PIMGroupEligibleRoles
                        if (-not $hasActualRolesFromSameGroup) {
                            foreach ($otherRole in $user.PIMGroupEligibleRoles) {
                                if ($otherRole.GroupId -eq $role.GroupId -or $otherRole.GroupName -like "*$($role.GroupName)*") {
                                    $hasActualRolesFromSameGroup = $true
                                    break
                                }
                            }
                        }
                        
                        # Skip this entry if actual roles from same group exist
                        if ($hasActualRolesFromSameGroup) {
                            Write-Log "Skipping redundant 'PIM Group Active Member' entry for $($user.DisplayName) - group $($role.GroupName) grants actual roles" -Level "INFO"
                            continue
                        }
                    }
                    
                    $exportData += [PSCustomObject]@{
                        PrincipalType = "User"
                        UserPrincipalName = $user.UserPrincipalName
                        DisplayName = $user.DisplayName
                        UserId = $user.UserId
                        AccountEnabled = $accountStatus
                        RoleName = $role.RoleName
                        RoleId = $role.RoleId
                        AssignmentType = "Group-Based"
                        GroupName = $role.GroupName
                        GroupId = $role.GroupId
                        NestingLevel = if ($role.NestingLevel) { $role.NestingLevel } else { 0 }
                        MFAEnabled = $mfaEnabled
                        MFAMethods = $mfaMethods
                        MethodCount = $mfaStatus.MethodCount
                        HasPhoneMFA = if ($null -eq $mfaStatus.HasPhone) { "Unknown" } elseif ($mfaStatus.HasPhone) { "Yes" } else { "No" }
                        AUProtected = if ($user.AUProtection.IsProtected) { "Yes" } else { "No" }
                        AUName = $user.AUProtection.AUName
                        MFATrust = $mfaTrustStatus
                        HomeTenant = $homeTenant
                        RiskLevel = $riskLevel
                    }
                }
            }
            
            # Create rows for PIM group eligible assignments
            foreach ($role in $user.PIMGroupEligibleRoles) {
                $exportData += [PSCustomObject]@{
                    PrincipalType = "User"
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    UserId = $user.UserId
                    AccountEnabled = $accountStatus
                    RoleName = $role.RoleName
                    RoleId = $role.RoleId
                    AssignmentType = "PIM Group Eligible"
                    GroupName = $role.GroupName
                    GroupId = $role.GroupId
                    NestingLevel = 0
                    MFAEnabled = $mfaEnabled
                    MFAMethods = $mfaMethods
                    MethodCount = $mfaStatus.MethodCount
                    HasPhoneMFA = if ($null -eq $mfaStatus.HasPhone) { "Unknown" } elseif ($mfaStatus.HasPhone) { "Yes" } else { "No" }
                    AUProtected = if ($user.AUProtection.IsProtected) { "Yes" } else { "No" }
                    AUName = $user.AUProtection.AUName
                    MFATrust = $mfaTrustStatus
                    HomeTenant = $homeTenant
                    RiskLevel = $riskLevel
                }
            }
        }
        
        # Add service principals to the export
        foreach ($sp in $privilegedServicePrincipals.Values) {
            # Create rows for active assignments
            foreach ($role in $sp.ActiveRoles) {
                $exportData += [PSCustomObject]@{
                    PrincipalType = "Service Principal"
                    UserPrincipalName = $sp.AppId
                    DisplayName = $sp.DisplayName
                    UserId = $sp.ServicePrincipalId
                    AccountEnabled = "N/A"
                    RoleName = $role.RoleName
                    RoleId = $role.RoleId
                    AssignmentType = "Active"
                    GroupName = ""
                    GroupId = ""
                    MFAEnabled = "N/A"
                    MFAMethods = "N/A"
                    MethodCount = 0
                    HasPhoneMFA = "N/A"
                    AUProtected = "N/A"
                    AUName = ""
                    RiskLevel = "N/A"
                }
            }
            
            # Create rows for eligible assignments
            foreach ($role in $sp.EligibleRoles) {
                $exportData += [PSCustomObject]@{
                    PrincipalType = "Service Principal"
                    UserPrincipalName = $sp.AppId
                    DisplayName = $sp.DisplayName
                    UserId = $sp.ServicePrincipalId
                    AccountEnabled = "N/A"
                    RoleName = $role.RoleName
                    RoleId = $role.RoleId
                    AssignmentType = "PIM Eligible"
                    GroupName = ""
                    GroupId = ""
                    MFAEnabled = "N/A"
                    MFAMethods = "N/A"
                    MethodCount = 0
                    HasPhoneMFA = "N/A"
                    AUProtected = "N/A"
                    AUName = ""
                    RiskLevel = "N/A"
                }
            }
        }
        
        $exportData | Export-Csv -Path $userStatusPath -NoTypeInformation -Encoding UTF8
        Write-Log "User status CSV exported to: $userStatusPath" -Level "SUCCESS"
        Write-Host "✓ User status exported" -ForegroundColor Green
        Write-Host ""
        Write-Host "Export Summary:" -ForegroundColor Cyan
        Write-Host "  Role Distribution: $($roleDistributionData.Count) roles" -ForegroundColor White
        Write-Host "  User Status: $($exportData.Count) assignments" -ForegroundColor White
        Write-Host ""
    }

    # ============================================================================
    # EXPORT 3: INTERACTIVE HTML REPORT
    # ============================================================================
    if ($exportToHtml) {
        $tenantName = "Unknown"
        try {
            $org = Get-MgOrganization -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($org -and $org.DisplayName) { $tenantName = $org.DisplayName }
        }
        catch { }

        $safeTenantName = $tenantName -replace '[^\w\-]', '_'
        $htmlPath = Join-Path $exportDirectory "PrivilegedAccountReport-$safeTenantName-$timestamp.html"

        Write-Log "Generating interactive HTML report..." -Level "INFO"
        New-PrivilegedAccountHtmlReport -PrivilegedUsers $privilegedUsers `
            -ServicePrincipals $privilegedServicePrincipals `
            -PrivilegedGroups $privilegedGroups `
            -RoleStats $roleStats `
            -OutputPath $htmlPath `
            -TenantName $tenantName `
            -IncludeGroupAssignments $IncludeGroups

        if (-not (Test-Path $htmlPath)) {
            throw "HTML report generation failed - no file was written to $htmlPath"
        }

        $htmlFullPath = (Resolve-Path $htmlPath).Path
        Write-Host "✓ HTML report exported: $htmlFullPath" -ForegroundColor Green

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
        Write-Host ""
    }
    
    # Return data if requested
    if ($ReturnData) {
        return @{
            Users = $privilegedUsers
            ServicePrincipals = $privilegedServicePrincipals
            Groups = $privilegedGroups
            RoleStats = $roleStats
            Summary = @{
                TotalPrivilegedUsers = $privilegedUsers.Count
                TotalRoles = $roleStats.Count
                TotalActiveAssignments = $activeAssignments.Count
                TotalEligibleAssignments = $eligibleAssignments.Count
                TotalGroupBasedAssignments = if ($IncludeGroups) { $groupAssignments.Count } else { 0 }
                TotalPIMGroupEligibleAssignments = $pimGroupEligibilityAssignments.Count
                TotalServicePrincipals = $privilegedServicePrincipals.Count
                TotalGroups = $privilegedGroups.Count
                AccountsEnabledCount = $accountsEnabledCount
                AccountsDisabledCount = $accountsDisabledCount
                MFAEnabledCount = $mfaEnabledCount
                MFADisabledCount = $mfaDisabledCount
                AUProtectedCount = $auProtectedCount
                AUUnprotectedCount = $auUnprotectedCount
                FullySecure = $fullSecure
                PhoneRiskOnly = $phoneRiskOnly
                NoAUOnly = $noAUOnly
                BothRisks = $bothRisks
                UnknownRisk = $unknownRisk
            }
        }
    }
    
    Write-Log "Privileged Account Report completed successfully" -Level "SUCCESS"
}
catch {
    Write-Log "Error during report generation: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    throw
}