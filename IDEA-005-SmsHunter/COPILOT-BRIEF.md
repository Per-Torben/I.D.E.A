# Brief for GitHub Copilot: I.D.E.A. 005

Delete this file before publishing.

## Goal
Finish `Get-SmsMfaReport.ps1`. Every `TODO` in a function's `.NOTES` block is the spec for that function. Do not change the output object shapes without updating the CSV/HTML code and the README.

## Suggested order
1. `Get-UserRegistrationDetails`: run it against a tenant and inspect real `methodsRegistered` values. Build the phone and phishing-resistant mappings from real output.
2. `Get-PhoneMethodDetail`: per-user `.../authentication/phoneMethods`, RMAU returns `AccessDenied` status, add 429 backoff in `Invoke-GraphPaged` and here.
3. `Find-SmsUsers` and `Get-SmsRiskLevel`: tiers are in the README.
4. `Get-SmsVoicePolicyFindings`, then `Resolve-PolicyTargetUsers`.
5. `Get-RegistrationCampaignFindings`.
6. `Get-PasskeyProfileFindings` (beta). Inspect the live response first.
7. `Show-UserConsole`, `New-HtmlReport`.

## Conventions (match I.D.E.A. 004)
- PowerShell 7+, ASCII only in the script (`[OK]`, `[X]`, no emoji, no em dashes).
- `Write-Log` for anything the user should see and the log should keep.
- Menu-driven, no mandatory parameters. Reuse an existing Graph connection, never discard an app-only one silently.
- Never name a function `Connect-Graph` (alias outranks functions).
- CSV is semicolon-delimited. HTML is one self-contained file, no external dependencies.
- Read-only. No `Set-`, `New-Mg`, `Update-` or `POST/PATCH/DELETE` calls.

## Do not
- Hardcode enum values or property names the live Graph response has not shown you.
- Drop users you cannot read. They go in as `Unknown`.
- Call the per-user auth methods API for every user. Pre-filter with the registration report.
