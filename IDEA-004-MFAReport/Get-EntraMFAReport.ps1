<#
.SYNOPSIS
    Generates a comprehensive MFA report for Microsoft Entra ID users with interactive HTML output.

.DESCRIPTION
    Analyzes MFA status for all users in the tenant using Microsoft Graph Beta API.
    Provides detailed statistics about MFA adoption, authentication methods, risk levels,
    account categories (user/room/shared/equipment), admin status, licensing, and sign-in activity.
    
    Outputs include:
    - Console summary with statistics and risk analysis
    - CSV export (detailed user data + summary statistics)
    - Self-contained interactive HTML report with sorting, filtering, and search
    
    PREREQUISITE: An active Microsoft Graph connection with the required scopes must already exist.
    If not connected, the script will display the required connection command and exit.

.PARAMETER ExportToCsv
    Exports detailed user data and summary statistics to CSV files in the exports/ directory.

.PARAMETER ExportToHtml
    Generates a self-contained interactive HTML report with sorting, filtering, and search.
    The HTML file works offline with no external dependencies.

.PARAMETER ExportAll
    Exports both CSV and HTML reports.

.PARAMETER ReturnData
    Returns data objects instead of displaying the report. Useful for piping to other commands.

.PARAMETER LogDirectory
    Directory path for log files. Defaults to .\Logs

.EXAMPLE
    Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All","UserAuthenticationMethod.Read.All","AuditLog.Read.All" -NoWelcome
    .\Get-EntraMFAReport.ps1
    Connect to Microsoft Graph with required scopes, then run the report (console output only).

.EXAMPLE
    .\Get-EntraMFAReport.ps1 -ExportToHtml
    Generates the interactive HTML report.

.EXAMPLE
    .\Get-EntraMFAReport.ps1 -ExportAll
    Exports both CSV files and the HTML report.

.EXAMPLE
    $results = .\Get-EntraMFAReport.ps1 -ReturnData
    Stores results in a variable. Access with $results.Users, $results.Summary, $results.Statistics

.NOTES
    Requires an existing Microsoft Graph connection with these scopes:
    - User.Read.All
    - Directory.Read.All
    - UserAuthenticationMethod.Read.All
    - AuditLog.Read.All (for sign-in activity data)
    
    Author: Per-Torben Sørensen
    Version: 2.0
    Created: October 2025
    Updated: June 2026 - Added HTML report, risk levels, account categories, sign-in activity
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$ExportToCsv,

    [Parameter(Mandatory = $false)]
    [switch]$ExportToHtml,

    [Parameter(Mandatory = $false)]
    [switch]$ExportAll,

    [Parameter(Mandatory = $false)]
    [switch]$ReturnData,

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
    'Microsoft.Graph.Identity.DirectoryManagement'
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
# Handle ExportAll flag
# ============================================================================
if ($ExportAll) {
    $ExportToCsv = $true
    $ExportToHtml = $true
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
    $mfaEnabledPct = $Summary.MFAEnabledPercentage
    $mfaDisabledPct = $Summary.MFADisabledPercentage
    $criticalCount = ($UserData | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $highCount = ($UserData | Where-Object { $_.RiskLevel -eq 'High' }).Count
    $mediumCount = ($UserData | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    $lowCount = ($UserData | Where-Object { $_.RiskLevel -eq 'Low' }).Count

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
.card.low .value { color: #388e3c; }
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
tr.risk-low { border-left: 4px solid #388e3c; }
tr.risk-na { border-left: 4px solid #9e9e9e; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.8em; font-weight: 600; }
.badge-critical { background: #ffebee; color: #c62828; }
.badge-high { background: #fff3e0; color: #e65100; }
.badge-medium { background: #fffde7; color: #f57f17; }
.badge-low { background: #e8f5e9; color: #2e7d32; }
.badge-na { background: #f5f5f5; color: #616161; }
.badge-enabled { background: #e8f5e9; color: #2e7d32; }
.badge-disabled { background: #ffebee; color: #c62828; }
.badge-guest { background: #e3f2fd; color: #1565c0; }
.badge-member { background: #f3e5f5; color: #6a1b9a; }
.footer { margin-top: 20px; text-align: center; font-size: 0.8em; color: #999; }
@media (max-width: 768px) { .filter-row { flex-direction: column; } .filter-group select, .filter-group input { min-width: 100%; } }
</style>
</head>
<body>
<div class="header">
<h1>Entra ID MFA Report</h1>
<div class="meta">Tenant: $TenantName | Generated: $generatedDate | Total Accounts: $totalUsers</div>
</div>

<div class="dashboard">
<div class="card info"><div class="value">$totalUsers</div><div class="label">Total Accounts</div></div>
<div class="card info"><div class="value">${mfaEnabledPct}%</div><div class="label">MFA Enabled</div></div>
<div class="card critical"><div class="value">$criticalCount</div><div class="label">Critical Risk</div></div>
<div class="card high"><div class="value">$highCount</div><div class="label">High Risk</div></div>
<div class="card medium"><div class="value">$mediumCount</div><div class="label">Medium Risk</div></div>
<div class="card low"><div class="value">$lowCount</div><div class="label">Low Risk</div></div>
</div>

<div class="filters">
<h3>Filters</h3>
<div class="filter-row">
<div class="filter-group"><label>Search (Name / UPN)</label><input type="text" id="searchBox" placeholder="Type to search..."></div>
<div class="filter-group"><label>Risk Level</label><select id="filterRisk"><option value="">All</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option><option value="N/A">N/A</option></select></div>
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
const riskOrder = {Critical:0, High:1, Medium:2, Low:3, 'N/A':4};

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
            if (!activeMethodFilters.some(m => userMethods.includes(m.toLowerCase()))) return false;
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
# Main Script Logic
# ============================================================================
try {
    Write-Log "Starting Entra MFA Report generation" -Level "INFO"

    # Required Graph API scopes
    $requiredScopes = @(
        "User.Read.All",
        "Directory.Read.All",
        "UserAuthenticationMethod.Read.All",
        "AuditLog.Read.All",
        "Reports.Read.All"
    )

    # Check for existing Microsoft Graph connection
    $context = Get-MgContext
    if (-not $context) {
        Write-Host ""
        Write-Host "ERROR: No active Microsoft Graph connection found." -ForegroundColor Red
        Write-Host ""
        Write-Host "Please connect to Microsoft Graph first using the following command:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Connect-MgGraph -Scopes `"$($requiredScopes -join '","')`" -NoWelcome" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Then re-run this script." -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }

    Write-Log "Using existing Microsoft Graph connection (Tenant: $($context.TenantId))" -Level "INFO"

    # ========================================================================
    # Retrieve Users with extended properties
    # ========================================================================
    Write-Log "Retrieving all users from Entra ID..." -Level "INFO"
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
    # Detect account categories via Mailbox Usage Report (beta - has Recipient Type)
    # ========================================================================
    Write-Log "Retrieving mailbox types from usage report..." -Level "INFO"
    $mailboxTypes = @{}  # UPN -> Recipient Type (User/Shared/Room/Equipment)
    $reportPrivacyEnabled = $false
    try {
        $tempFile = [System.IO.Path]::GetTempFileName() + ".csv"
        Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/reports/getMailboxUsageDetail(period='D7')" -Method GET -OutputFilePath $tempFile -ErrorAction Stop
        $reportData = Import-Csv $tempFile -ErrorAction Stop

        # Check if UPNs are anonymized (privacy setting enabled)
        $sampleUpn = ($reportData | Select-Object -First 1).'User Principal Name'
        if ($sampleUpn -and $sampleUpn -match '^[A-F0-9]{32}$') {
            $reportPrivacyEnabled = $true
            Write-Log "Report privacy is enabled (concealed names). Mailbox type detection via report unavailable. Using heuristics." -Level "WARNING"
        }
        else {
            foreach ($row in $reportData) {
                if ($row.'User Principal Name' -and $row.'Recipient Type') {
                    $mailboxTypes[$row.'User Principal Name'.ToLower()] = $row.'Recipient Type'
                }
            }
            $typeSummary = $reportData | Group-Object 'Recipient Type' | ForEach-Object { "$($_.Name): $($_.Count)" }
            Write-Log "Mailbox types retrieved: $($typeSummary -join ', ')" -Level "INFO"
        }
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Could not retrieve mailbox usage report: $($_.Exception.Message). Using heuristic detection." -Level "WARNING"
        if ($tempFile -and (Test-Path $tempFile)) { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }
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
        $upnLower = $user.UserPrincipalName.ToLower()
        $mailLower = if ($user.Mail) { $user.Mail.ToLower() } else { "" }
        $displayLower = if ($user.DisplayName) { $user.DisplayName.ToLower() } else { "" }

        # 1. Check mailbox usage report (works when report privacy is OFF)
        if ($mailboxTypes.Count -gt 0 -and $mailboxTypes.ContainsKey($upnLower)) {
            $mbType = $mailboxTypes[$upnLower]
            switch ($mbType) {
                "Shared"    { $accountCategory = "Shared Mailbox" }
                "Room"      { $accountCategory = "Room" }
                "Equipment" { $accountCategory = "Equipment" }
                default     { $accountCategory = "User" }
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

        # Last sign-in
        $lastSignIn = $null
        if ($user.SignInActivity -and $user.SignInActivity.LastSignInDateTime) {
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
                        $output.tempPass = $true
                        $output.MFAstatus = "enabled"
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
            else {
                $output.RiskLevel = "Low"
                $output.RiskNotes = "Phishing-resistant MFA"
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

    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host "Entra ID MFA Report - Generated: $date" -ForegroundColor Green
    Write-Host ("=" * 80) -ForegroundColor Green

    Write-Host "`nOVERALL STATISTICS:" -ForegroundColor Yellow
    Write-Host "Total Users: $totalUsers"
    Write-Host "Enabled Accounts: $enabledAccounts ($([math]::Round(($enabledAccounts / $totalUsers) * 100, 1))%)"
    Write-Host "MFA Enabled: $mfaEnabled ($([math]::Round(($mfaEnabled / $totalUsers) * 100, 1))%)" -ForegroundColor Green
    Write-Host "MFA Disabled: $mfaDisabled ($([math]::Round(($mfaDisabled / $totalUsers) * 100, 1))%)" -ForegroundColor Red
    if ($mfaUnknown -gt 0) {
        Write-Host "MFA Unknown: $mfaUnknown ($([math]::Round(($mfaUnknown / $totalUsers) * 100, 1))%)" -ForegroundColor Yellow
    }

    Write-Host "`nRISK SUMMARY:" -ForegroundColor Yellow
    $riskCritical = ($export | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $riskHigh = ($export | Where-Object { $_.RiskLevel -eq "High" }).Count
    $riskMedium = ($export | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $riskLow = ($export | Where-Object { $_.RiskLevel -eq "Low" }).Count
    $riskNA = ($export | Where-Object { $_.RiskLevel -eq "N/A" }).Count
    Write-Host "  Critical (No MFA): $riskCritical" -ForegroundColor Red
    Write-Host "  High (SMS-only): $riskHigh" -ForegroundColor DarkYellow
    Write-Host "  Medium (No phishing-resistant): $riskMedium" -ForegroundColor Yellow
    Write-Host "  Low (Phishing-resistant): $riskLow" -ForegroundColor Green
    Write-Host "  N/A (Disabled/Blocked): $riskNA" -ForegroundColor Gray

    Write-Host "`nACCOUNT CATEGORIES:" -ForegroundColor Yellow
    $export | Group-Object accountCategory | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)"
    }
    if ($reportPrivacyEnabled) {
        Write-Host "  Note: Report privacy is enabled in this tenant. Account category detection" -ForegroundColor DarkGray
        Write-Host "  relies on heuristics only. For accurate results, disable 'Conceal user details'" -ForegroundColor DarkGray
        Write-Host "  in Microsoft 365 Admin > Settings > Org settings > Reports." -ForegroundColor DarkGray
    }

    Write-Host "`nADMIN ACCOUNTS:" -ForegroundColor Yellow
    $adminAccounts = $export | Where-Object { $_.isAdmin }
    $adminNoMFA = $adminAccounts | Where-Object { $_.MFAstatus -eq "disabled" }
    Write-Host "  Total Admins: $($adminAccounts.Count)"
    if ($adminNoMFA.Count -gt 0) {
        Write-Host "  Admins WITHOUT MFA: $($adminNoMFA.Count)" -ForegroundColor Red
    }

    Write-Host "`nMFA METHODS (users with MFA enabled):" -ForegroundColor Yellow
    $mfaUsers = $export | Where-Object { $_.MFAstatus -eq "enabled" }
    if ($mfaUsers.Count -gt 0) {
        $mc = $mfaUsers.Count
        Write-Host "  Authenticator App: $(($mfaUsers | Where-Object { $_.authApp }).Count) ($([math]::Round((($mfaUsers | Where-Object { $_.authApp }).Count / $mc) * 100, 1))%)"
        Write-Host "  Phone/SMS: $(($mfaUsers | Where-Object { $_.phoneSMS }).Count) ($([math]::Round((($mfaUsers | Where-Object { $_.phoneSMS }).Count / $mc) * 100, 1))%)"
        Write-Host "  FIDO2: $(($mfaUsers | Where-Object { $_.fido }).Count) ($([math]::Round((($mfaUsers | Where-Object { $_.fido }).Count / $mc) * 100, 1))%)"
        Write-Host "  Windows Hello: $(($mfaUsers | Where-Object { $_.helloForBusiness }).Count) ($([math]::Round((($mfaUsers | Where-Object { $_.helloForBusiness }).Count / $mc) * 100, 1))%)"
        Write-Host "  Passwordless: $(($mfaUsers | Where-Object { $_.passwordLess }).Count)"
        Write-Host "  Software OATH: $(($mfaUsers | Where-Object { $_.softwareAuth }).Count)"
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
        RiskCritical            = $riskCritical
        RiskHigh                = $riskHigh
        RiskMedium              = $riskMedium
        RiskLow                 = $riskLow
        RiskNA                  = $riskNA
        AdminCount              = $adminAccounts.Count
        AdminsWithoutMFA        = $adminNoMFA.Count
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

        Write-Host "CSV exported: $csvFilename" -ForegroundColor Green
        Write-Host "Summary exported: $summaryFilename" -ForegroundColor Green
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
        Write-Host "HTML report exported: $htmlFilename" -ForegroundColor Green
    }

    # ========================================================================
    # Return Data
    # ========================================================================
    if ($ReturnData) {
        return [PSCustomObject]@{
            Users      = $export
            Summary    = $enhancedReport
            Statistics = [PSCustomObject]@{
                TotalUsers       = $totalUsers
                EnabledAccounts  = $enabledAccounts
                MFAEnabled       = $mfaEnabled
                MFADisabled      = $mfaDisabled
                MFAUnknown       = $mfaUnknown
                AppPasswordUsers = $appPasswordUsers
                RiskCritical     = $riskCritical
                RiskHigh         = $riskHigh
                RiskMedium       = $riskMedium
                RiskLow          = $riskLow
                AdminCount       = $adminAccounts.Count
                ProcessingErrors = $errorCount
                CAErrors         = $caErrorCount
            }
        }
    }

    Write-Log "MFA Report generation completed successfully" -Level "SUCCESS"
}
catch {
    Write-Log "Error during script execution: $($_.Exception.Message)" -Level "ERROR"
    Write-Error "Script execution failed: $($_.Exception.Message)"
}
