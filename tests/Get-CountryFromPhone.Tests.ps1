#Requires -Modules Pester
<#
.SYNOPSIS
    Pester tests for Get-CountryFromPhone function in Get-EntraMFAReport.ps1
#>

BeforeAll {
    # Dot-source only the country code map and function from the script
    # We parse the script and extract what we need without running the full script
    $scriptPath = Join-Path $PSScriptRoot "..\IDEA-004-MFAReport\Get-EntraMFAReport.ps1"
    $scriptContent = Get-Content $scriptPath -Raw

    # Extract $CountryCodes hashtable and Get-CountryFromPhone function, then invoke them
    $pattern = '(?s)(\$CountryCodes\s*=\s*@\{.*?\})\s*(function Get-CountryFromPhone \{.*?\n\})'
    if ($scriptContent -match $pattern) {
        Invoke-Expression $Matches[1]
        Invoke-Expression $Matches[2]
    }
    else {
        throw "Could not extract CountryCodes or Get-CountryFromPhone from script"
    }
}

Describe "Get-CountryFromPhone" {

    Context "Valid phone numbers with known country codes" {

        It "Returns 'Norway (+47)' for a Norwegian number" {
            $result = Get-CountryFromPhone -PhoneNumber "+47 91234567"
            $result | Should -Be "Norway (+47)"
        }

        It "Returns 'US/Canada (+1)' for a US number" {
            $result = Get-CountryFromPhone -PhoneNumber "+1 2025551234"
            $result | Should -Be "US/Canada (+1)"
        }

        It "Returns 'UK (+44)' for a UK number" {
            $result = Get-CountryFromPhone -PhoneNumber "+44 7700900123"
            $result | Should -Be "UK (+44)"
        }

        It "Returns 'Germany (+49)' for a German number" {
            $result = Get-CountryFromPhone -PhoneNumber "+49 15112345678"
            $result | Should -Be "Germany (+49)"
        }

        It "Returns 'Sweden (+46)' for a Swedish number" {
            $result = Get-CountryFromPhone -PhoneNumber "+46 701234567"
            $result | Should -Be "Sweden (+46)"
        }

        It "Handles numbers without spaces" {
            $result = Get-CountryFromPhone -PhoneNumber "+4791234567"
            $result | Should -Be "Norway (+47)"
        }

        It "Handles numbers with dashes" {
            $result = Get-CountryFromPhone -PhoneNumber "+47-912-34-567"
            $result | Should -Be "Norway (+47)"
        }

        It "Returns 3-digit code country correctly for UAE (+971)" {
            $result = Get-CountryFromPhone -PhoneNumber "+971 501234567"
            $result | Should -Be "UAE (+971)"
        }
    }

    Context "Invalid or missing phone numbers" {

        It "Returns null for null input" {
            $result = Get-CountryFromPhone -PhoneNumber $null
            $result | Should -BeNullOrEmpty
        }

        It "Returns null for empty string" {
            $result = Get-CountryFromPhone -PhoneNumber ""
            $result | Should -BeNullOrEmpty
        }

        It "Returns null for the string 'False'" {
            $result = Get-CountryFromPhone -PhoneNumber "False"
            $result | Should -BeNullOrEmpty
        }

        It "Returns 'Unknown' for a number without + prefix" {
            $result = Get-CountryFromPhone -PhoneNumber "91234567"
            $result | Should -Be "Unknown"
        }

        It "Returns Unknown with prefix info for an unrecognised country code" {
            $result = Get-CountryFromPhone -PhoneNumber "+000 12345678"
            $result | Should -BeLike "Unknown*"
        }
    }
}
