#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Creates a Microsoft Entra ID application registration for Privileged Account Report script.
    Related blog post: https://agderinthe.cloud/2026/02/19/i-d-e-a-002-will-the-real-admin-please-stand-up/

.DESCRIPTION
    This script creates an application registration in Microsoft Entra ID specifically configured
    for running the Get-PrivilegedAccountReport.ps1 script. It generates a self-signed certificate,
    attaches it to the application, assigns only the required API permissions for privileged account
    reporting, and attempts to grant admin consent.
    
    IMPORTANT: Run this script on the same machine where you plan to run Get-PrivilegedAccountReport.ps1.
    The self-signed certificate is created and stored in the local computer's certificate store for
    authentication. If you need to run the report from a different machine, you'll need to export
    and import the certificate, or configure alternative authentication methods (interactive auth,
    client secret, etc.).
    
    The application is configured with minimal required permissions:
    - User.Read.All
    - Directory.Read.All
    - RoleManagement.Read.Directory
    - RoleEligibilitySchedule.Read.Directory
    - UserAuthenticationMethod.Read.All
    - PrivilegedAccess.Read.AzureADGroup
    - Policy.Read.All
    - CrossTenantInformation.ReadBasic.All

.PARAMETER TenantId
    The Microsoft Entra ID tenant ID where the application will be registered.

.PARAMETER AppName
    The display name for the application registration. Defaults to "PrivilegedAccountReport".

.PARAMETER AppDescription
    A description for the application registration. Defaults to automated description.

.PARAMETER CertDurationDays
    The number of days the certificate will be valid. Fixed at 90 days for security compliance.

.NOTES
    Requirements:
    - Microsoft Graph PowerShell module (Install-Module Microsoft.Graph)
    - Global Administrator or Application Administrator role to grant consent
    - The following Graph API permissions: Application.ReadWrite.All, Directory.ReadWrite.All, AppRoleAssignment.ReadWrite.All
    
    Author: Per-Torben Sørensen
    Version: 1.0
    Created: February 2026

.EXAMPLE
    # Run with default settings for current tenant
    .\Create-PrivilegedAccountReportApp.ps1
    
.EXAMPLE
    # Run with custom tenant ID
    Initialize-Variables -TenantId 'your-tenant-id'
    # Then execute the remaining functions
#>

# Check if Microsoft Graph module is installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Host "Microsoft Graph PowerShell module not found. Installing..." -ForegroundColor Yellow
    Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
    Write-Host "Microsoft Graph PowerShell module installed successfully." -ForegroundColor Green
}
else {
    Write-Host "Microsoft Graph PowerShell module already installed." -ForegroundColor Green
}

# ===== MODULES FOR APP REGISTRATION =====

function Initialize-Variables {
    param (
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [string]$AppName = "PrivilegedAccountReport",
        
        [Parameter(Mandatory = $false)]
        [string]$AppDescription = "Application for automated privileged account security reporting and compliance monitoring",
        
        [Parameter(Mandatory = $false)]
        [int]$CertDurationDays = 90
    )
    
    # If TenantId not provided, try to get from current context
    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        try {
            $context = Get-MgContext
            if ($context -and $context.TenantId) {
                $TenantId = $context.TenantId
                Write-Host "Using tenant ID from current context: $TenantId" -ForegroundColor Cyan
            }
            else {
                Write-Host "No tenant ID provided and no active Graph context found." -ForegroundColor Red
                Write-Host ""
                Write-Host "Required Permissions:" -ForegroundColor Yellow
                Write-Host "  - Application Administrator or Global Administrator role" -ForegroundColor White
                Write-Host ""
                Write-Host "Connect to Microsoft Graph with the required scopes:" -ForegroundColor Yellow
                Write-Host "  Connect-MgGraph -TenantId 'your-tenant-id' -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All','AppRoleAssignment.ReadWrite.All'" -ForegroundColor Cyan
                Write-Host ""
                exit 1
            }
        }
        catch {
            Write-Host "Error getting tenant context. Please provide TenantId parameter or connect to Graph first." -ForegroundColor Red
            Write-Host ""
            Write-Host "Connect with required permissions:" -ForegroundColor Yellow
            Write-Host "  Connect-MgGraph -TenantId 'your-tenant-id' -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All','AppRoleAssignment.ReadWrite.All'" -ForegroundColor Cyan
            Write-Host ""
            exit 1
        }
    }
    
    $script:tentantid = $TenantId
    $script:AppRegistrationName = $AppName
    $script:AppRegistrationDescription = $AppDescription
    $script:date = Get-Date -Format "yyyy.MM.dd"
    $script:CertName = "AppCert-$AppName-$($script:date)"
    $script:Certduration = $CertDurationDays
    
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Privileged Account Report App Registration Setup         ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor White
    Write-Host "  Application Name: $AppRegistrationName" -ForegroundColor Gray
    Write-Host "  Tenant ID: $TenantId" -ForegroundColor Gray
    Write-Host "  Certificate Duration: $CertDurationDays days" -ForegroundColor Gray
    Write-Host ""
}

function New-AppCertificate {
    param()
    
    Write-Host "Creating self-signed certificate: $script:CertName" -ForegroundColor Cyan
    $script:cert = New-SelfSignedCertificate -Subject "CN=$($script:CertName)" -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 4096 -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 -NotAfter (Get-Date).AddDays($script:Certduration)
    
    Write-Host "✓ Certificate created successfully" -ForegroundColor Green
    Write-Host "  Thumbprint: $($script:cert.Thumbprint)" -ForegroundColor Gray
    Write-Host "  Valid Until: $($script:cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
    Write-Host ""
    
    return $script:cert
}

function Connect-ToGraph {
    param()
    
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    # Add the AppRoleAssignment.ReadWrite.All scope which is required for granting consent
    Connect-MgGraph -TenantId $script:tentantid -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -NoWelcome
    Write-Host "✓ Connected to Microsoft Graph" -ForegroundColor Green
    Write-Host ""
}

function New-ApplicationRegistration {
    param()
    
    Write-Host "Creating application registration: $script:AppRegistrationName" -ForegroundColor Cyan
    $script:appRegistration = New-MgApplication -DisplayName $script:AppRegistrationName -Description $script:AppRegistrationDescription
    
    Write-Host "✓ Application registered successfully" -ForegroundColor Green
    Write-Host "  AppId (Client ID): $($script:appRegistration.AppId)" -ForegroundColor Gray
    Write-Host "  Object ID: $($script:appRegistration.Id)" -ForegroundColor Gray
    Write-Host ""
    
    # Create a service principal for the application
    Write-Host "Creating service principal..." -ForegroundColor Cyan
    $script:servicePrincipal = New-MgServicePrincipal -AppId $script:appRegistration.AppId
    Write-Host "✓ Service Principal created with Id: $($script:servicePrincipal.Id)" -ForegroundColor Green
    Write-Host ""
    
    return $script:appRegistration
}

function Add-CertificateToApplication {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId
    )
    
    Write-Host "Adding certificate to application..." -ForegroundColor Cyan
    
    # Create a proper KeyCredential object
    $keyCredential = New-Object Microsoft.Graph.PowerShell.Models.MicrosoftGraphKeyCredential
    $keyCredential.Type = "AsymmetricX509Cert"
    $keyCredential.Usage = "Verify"
    $keyCredential.Key = $Certificate.GetRawCertData()
    $keyCredential.DisplayName = $Certificate.Subject
    $keyCredential.StartDateTime = $Certificate.NotBefore
    $keyCredential.EndDateTime = $Certificate.NotAfter
    
    # Update the application with the key credential
    Update-MgApplication -ApplicationId $ApplicationId -KeyCredentials @($keyCredential)
    Write-Host "✓ Certificate credential added to application" -ForegroundColor Green
    Write-Host ""
}

function Add-ApplicationPermissions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId,
        
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId,
        
        [Parameter(Mandatory = $true)]
        [array]$Permissions
    )
    
    Write-Host "Adding API permissions to application..." -ForegroundColor Cyan
    Write-Host "Required permissions for Privileged Account Report:" -ForegroundColor White
    
    $msGraphAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph AppId
    
    # Get existing permissions first
    $app = Get-MgApplication -ApplicationId $ApplicationId
    $requiredResourceAccess = @()
    
    # Group permissions by resource
    $permissionsByResource = @{}
    foreach ($permission in $Permissions) {
        if (!$permissionsByResource.ContainsKey($permission.AppId)) {
            $permissionsByResource[$permission.AppId] = @()
        }
        $permissionsByResource[$permission.AppId] += $permission
    }
    
    # Store for consent
    $script:consentInfo = @()
    
    # Process each resource
    foreach ($resourceAppId in $permissionsByResource.Keys) {
        $apiServicePrincipal = Get-MgServicePrincipal -Filter "AppId eq '$resourceAppId'"
        $resourceAccess = @()
        
        foreach ($permission in $permissionsByResource[$resourceAppId]) {
            if ($permission.Type -eq "Delegated") {
                $apiPermission = $apiServicePrincipal.Oauth2PermissionScopes | Where-Object { $_.Value -eq $permission.PermissionName }
                if ($apiPermission) {
                    $resourceAccess += @{
                        Id = $apiPermission.Id
                        Type = "Scope"
                    }
                    Write-Host "  ✓ $($permission.PermissionName) (Delegated)" -ForegroundColor Green
                }
            } else {
                $apiPermission = $apiServicePrincipal.AppRoles | Where-Object { $_.Value -eq $permission.PermissionName }
                if ($apiPermission) {
                    $resourceAccess += @{
                        Id = $apiPermission.Id
                        Type = "Role"
                    }
                    Write-Host "  ✓ $($permission.PermissionName) (Application)" -ForegroundColor Green
                    $script:consentInfo += @{
                        ServicePrincipalId = $ServicePrincipalId
                        ApiServicePrincipal = $apiServicePrincipal
                        ApiPermission = $apiPermission
                    }
                }
            }
        }
        
        if ($resourceAccess.Count -gt 0) {
            $requiredResourceAccess += @{
                ResourceAppId = $resourceAppId
                ResourceAccess = $resourceAccess
            }
        }
    }
    
    # Update the application with all permissions at once
    Update-MgApplication -ApplicationId $ApplicationId -RequiredResourceAccess $requiredResourceAccess
    Write-Host ""
    Write-Host "✓ All permissions added to the application" -ForegroundColor Green
    Write-Host ""
    
    return $script:consentInfo
}

function Grant-AdminConsent {
    param(
        [Parameter(Mandatory = $true)]
        [array]$ConsentInfo
    )
    
    Write-Host "Granting admin consent for application permissions..." -ForegroundColor Cyan
    $consentGranted = $false
    $successCount = 0
    $failCount = 0
    
    foreach ($consent in $ConsentInfo) {
        try {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $consent.ServicePrincipalId `
                -PrincipalId $consent.ServicePrincipalId -ResourceId $consent.ApiServicePrincipal.Id -AppRoleId $consent.ApiPermission.Id -ErrorAction Stop
            Write-Host "  ✓ Admin consent granted: $($consent.ApiPermission.Value)" -ForegroundColor Green
            $consentGranted = $true
            $successCount++
        }
        catch {
            Write-Host "  ✗ Could not grant consent: $($consent.ApiPermission.Value)" -ForegroundColor Yellow
            Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor DarkGray
            $failCount++
        }
    }
    
    Write-Host ""
    
    if ($failCount -gt 0) {
        Write-Host "⚠️  Manual consent required for $failCount permission(s)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "To grant consent manually:" -ForegroundColor Yellow
        Write-Host "1. Go to Azure Portal > Microsoft Entra ID > App Registrations" -ForegroundColor White
        Write-Host "2. Find '$script:AppRegistrationName' in the list" -ForegroundColor White
        Write-Host "3. Go to API Permissions" -ForegroundColor White
        Write-Host "4. Click 'Grant admin consent for [your tenant]'" -ForegroundColor White
        Write-Host ""
        Write-Host "AppId for reference: $($script:appRegistration.AppId)" -ForegroundColor Cyan
        Write-Host ""
    }
    else {
        Write-Host "✓ All permissions granted successfully ($successCount/$($ConsentInfo.Count))" -ForegroundColor Green
        Write-Host ""
    }
    
    return $consentGranted
}

function Show-CompletionSummary {
    param()
    
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║  Application Registration Completed Successfully!         ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "Application Details:" -ForegroundColor White
    Write-Host "  Name: $($script:AppRegistrationName)" -ForegroundColor Gray
    Write-Host "  App ID (Client ID): $($script:appRegistration.AppId)" -ForegroundColor Cyan
    Write-Host "  Tenant ID: $($script:tentantid)" -ForegroundColor Gray
    Write-Host "  Certificate Thumbprint: $($script:cert.Thumbprint)" -ForegroundColor Cyan
    Write-Host "  Certificate Expires: $($script:cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor White
    Write-Host "1. Use these credentials to connect to Graph from Get-PrivilegedAccountReport.ps1" -ForegroundColor Gray
    Write-Host "2. Connection example:" -ForegroundColor Gray
    Write-Host ""
    Write-Host "   Connect-MgGraph -TenantId '$($script:tentantid)' ``" -ForegroundColor Cyan
    Write-Host "       -ClientId '$($script:appRegistration.AppId)' ``" -ForegroundColor Cyan
    Write-Host "       -CertificateThumbprint '$($script:cert.Thumbprint)'" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "3. Run the privileged account report:" -ForegroundColor Gray
    Write-Host "   .\\MFA Report\\Get-PrivilegedAccountReport.ps1" -ForegroundColor Cyan
    Write-Host ""
}

# ===== MAIN SCRIPT EXECUTION =====

# Initialize variables (will auto-detect tenant if already connected to Graph)
Initialize-Variables

# Create certificate (90 days validity)
$certificate = New-AppCertificate

# Connect to Microsoft Graph (will prompt if not already connected)
$context = Get-MgContext
if (-not $context) {
    Connect-ToGraph
}
else {
    Write-Host "Already connected to Microsoft Graph" -ForegroundColor Green
    Write-Host ""
}

# Create app registration
$appReg = New-ApplicationRegistration

# Add certificate to application
Add-CertificateToApplication -Certificate $certificate -ApplicationId $appReg.Id

# Define permissions required for Get-PrivilegedAccountReport.ps1
$permissionsToAdd = @(
    @{
        AppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        PermissionName = "User.Read.All"
        Type = "Application"
    },
    @{
        AppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        PermissionName = "Directory.Read.All"
        Type = "Application"
    },
    @{
        AppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        PermissionName = "RoleManagement.Read.Directory"
        Type = "Application"
    },
    @{
        AppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        PermissionName = "RoleEligibilitySchedule.Read.Directory"
        Type = "Application"
    },
    @{
        AppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        PermissionName = "UserAuthenticationMethod.Read.All"
        Type = "Application"
    },
    @{
        AppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        PermissionName = "PrivilegedAccess.Read.AzureADGroup"
        Type = "Application"
    },
    @{
        AppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        PermissionName = "Policy.Read.All"
        Type = "Application"
    },
    @{
        AppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        PermissionName = "CrossTenantInformation.ReadBasic.All"
        Type = "Application"
    }
)

# Add permissions
$consentInfo = Add-ApplicationPermissions -ApplicationId $appReg.Id `
    -ServicePrincipalId $script:servicePrincipal.Id -Permissions $permissionsToAdd

# Grant admin consent
Grant-AdminConsent -ConsentInfo $consentInfo

# Show completion summary
Show-CompletionSummary

Write-Host "Script execution completed!" -ForegroundColor Green
Write-Host ""
