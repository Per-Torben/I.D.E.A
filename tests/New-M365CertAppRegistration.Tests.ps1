#Requires -Version 7.0

<#
.SYNOPSIS
    Pester tests for New-M365CertAppRegistration.ps1 (I.D.E.A. 003)

.NOTES
    Tests cover functions that do not require Microsoft Graph connectivity:
      - New-AppCertificate
      - Import-ExistingCertificate
      - Export-ConnectionScript

    Run from the repository root:
      Invoke-Pester -Path .\tests -Output Detailed
#>

BeforeAll {
    # Dot-source the main script to load function definitions without triggering
    # interactive main execution (the script guards with $MyInvocation.InvocationName -ne '.')
    $scriptPath = Join-Path $PSScriptRoot '..\IDEA-003-CertAppRegistration\New-M365CertAppRegistration.ps1'

    # Suppress module installation output during test load
    Mock Write-Host {} -ModuleName '' -Verifiable:$false -ErrorAction SilentlyContinue
    . $scriptPath

    # Ensure test-scoped directories
    $script:TestTempDir = Join-Path $env:TEMP 'IDEA003Tests'
    if (-not (Test-Path $script:TestTempDir)) {
        New-Item -ItemType Directory -Path $script:TestTempDir -Force | Out-Null
    }

    # Suppress Write-Log file output during tests by clearing LogFile
    $script:LogFile = $null
}

AfterAll {
    # Clean up temp directory
    if (Test-Path $script:TestTempDir) {
        Remove-Item $script:TestTempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'New-AppCertificate' {

    BeforeAll {
        $script:TestCertName    = "IDEA003-Pester-$(Get-Date -Format 'yyyyMMddHHmmss')"
        $script:CreatedThumbprint = $null
    }

    AfterAll {
        # Remove any test certificates from the personal store
        if ($script:CreatedThumbprint) {
            Remove-Item "Cert:\CurrentUser\My\$($script:CreatedThumbprint)" -ErrorAction SilentlyContinue
        }
    }

    Context 'Valid inputs' {

        It 'Returns a certificate object with the correct subject' {
            $cert = New-AppCertificate -CertName $script:TestCertName -DurationDays 90 -ExportDir $script:TestTempDir
            $script:CreatedThumbprint = $cert.Thumbprint

            $cert | Should -Not -BeNullOrEmpty
            $cert.Subject | Should -Be "CN=$($script:TestCertName)"
        }

        It 'Certificate is installed in Cert:\CurrentUser\My' {
            $stored = Get-ChildItem 'Cert:\CurrentUser\My' |
                      Where-Object { $_.Thumbprint -eq $script:CreatedThumbprint }
            $stored | Should -Not -BeNullOrEmpty
        }

        It 'Certificate has the private key (HasPrivateKey)' {
            $stored = Get-ChildItem 'Cert:\CurrentUser\My' |
                      Where-Object { $_.Thumbprint -eq $script:CreatedThumbprint }
            $stored.HasPrivateKey | Should -BeTrue
        }

        It 'Exports a .cer file to the export directory' {
            $expectedPath = Join-Path $script:TestTempDir "$($script:TestCertName).cer"
            Test-Path $expectedPath | Should -BeTrue
        }

        It 'Exported .cer file is non-empty' {
            $expectedPath = Join-Path $script:TestTempDir "$($script:TestCertName).cer"
            (Get-Item $expectedPath).Length | Should -BeGreaterThan 0
        }

        It 'Certificate NotAfter is approximately DurationDays from now' {
            $stored = Get-ChildItem 'Cert:\CurrentUser\My' |
                      Where-Object { $_.Thumbprint -eq $script:CreatedThumbprint }

            $expectedExpiry = (Get-Date).AddDays(90)
            # Allow ±2 day tolerance for timing
            $stored.NotAfter | Should -BeGreaterThan $expectedExpiry.AddDays(-2)
            $stored.NotAfter | Should -BeLessThan    $expectedExpiry.AddDays(2)
        }
    }

    Context 'Invalid inputs' {

        It 'Throws when DurationDays is below minimum (0)' {
            { New-AppCertificate -CertName 'TestCert' -DurationDays 0 -ExportDir $script:TestTempDir } |
                Should -Throw
        }

        It 'Throws when DurationDays exceeds maximum (3651)' {
            { New-AppCertificate -CertName 'TestCert' -DurationDays 3651 -ExportDir $script:TestTempDir } |
                Should -Throw
        }

        It 'Throws when ExportDir does not exist' {
            { New-AppCertificate -CertName 'TestCert' -DurationDays 90 -ExportDir 'C:\NonExistentPath\IDEA003\exports' } |
                Should -Throw
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Import-ExistingCertificate' {

    BeforeAll {
        # Create a temporary self-signed cert and export a .cer for import testing
        $script:TempCertName = "IDEA003-ImportTest-$(Get-Date -Format 'yyyyMMddHHmmss')"
        $script:TempCert     = New-SelfSignedCertificate `
            -Subject           "CN=$($script:TempCertName)" `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -KeyExportPolicy   Exportable `
            -KeySpec           Signature `
            -KeyLength         2048 `
            -KeyAlgorithm      RSA `
            -HashAlgorithm     SHA256 `
            -NotAfter          (Get-Date).AddDays(30)

        $script:TempCerPath = Join-Path $script:TestTempDir "$($script:TempCertName).cer"
        Export-Certificate -Cert $script:TempCert -FilePath $script:TempCerPath -Force | Out-Null
    }

    AfterAll {
        # Remove temp cert from store
        Remove-Item "Cert:\CurrentUser\My\$($script:TempCert.Thumbprint)" -ErrorAction SilentlyContinue
        Remove-Item $script:TempCerPath -Force -ErrorAction SilentlyContinue
    }

    Context 'Valid certificate file' {

        It 'Returns a certificate object for a valid .cer file' {
            $result = Import-ExistingCertificate -CertificatePath $script:TempCerPath
            $result | Should -Not -BeNullOrEmpty
        }

        It 'Returned certificate thumbprint matches the source certificate' {
            $result = Import-ExistingCertificate -CertificatePath $script:TempCerPath
            $result.Thumbprint | Should -Be $script:TempCert.Thumbprint
        }

        It 'Returns an X509Certificate2 object' {
            $result = Import-ExistingCertificate -CertificatePath $script:TempCerPath
            $result | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Certificate2]
        }
    }

    Context 'Invalid inputs' {

        It 'Throws when certificate file does not exist' {
            { Import-ExistingCertificate -CertificatePath 'C:\NonExistent\cert.cer' } |
                Should -Throw
        }

        It 'Throws when path is empty string' {
            { Import-ExistingCertificate -CertificatePath '' } |
                Should -Throw
        }

        It 'Throws when certificate is not yet valid (future start date)' {
            # Create a cert that is not yet valid
            $futureCert = New-SelfSignedCertificate `
                -Subject           'CN=FutureTestCert' `
                -CertStoreLocation 'Cert:\CurrentUser\My' `
                -KeyExportPolicy   Exportable `
                -KeySpec           Signature `
                -KeyLength         2048 `
                -KeyAlgorithm      RSA `
                -HashAlgorithm     SHA256 `
                -NotBefore         (Get-Date).AddDays(5) `
                -NotAfter          (Get-Date).AddDays(35)

            $futureCerPath = Join-Path $script:TestTempDir 'future-cert.cer'
            Export-Certificate -Cert $futureCert -FilePath $futureCerPath -Force | Out-Null

            { Import-ExistingCertificate -CertificatePath $futureCerPath } |
                Should -Throw

            # Cleanup
            Remove-Item "Cert:\CurrentUser\My\$($futureCert.Thumbprint)" -ErrorAction SilentlyContinue
            Remove-Item $futureCerPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Export-ConnectionScript' {

    Context 'MicrosoftGraph connection script' {

        It 'Creates a .ps1 file in the export directory' {
            Export-ConnectionScript `
                -Service    'MicrosoftGraph' `
                -Prefix     'TestPrefix' `
                -ClientId   'client-id-graph' `
                -TenantId   'tenant-id-0001' `
                -Thumbprint 'ABCDEF1234567890ABCDEF1234567890ABCDEF12' `
                -ExportDir  $script:TestTempDir

            $expectedFile = Join-Path $script:TestTempDir 'TestPrefix-Connect-MicrosoftGraph.ps1'
            Test-Path $expectedFile | Should -BeTrue
        }

        It 'Script contains Connect-MgGraph' {
            $file    = Join-Path $script:TestTempDir 'TestPrefix-Connect-MicrosoftGraph.ps1'
            $content = Get-Content $file -Raw
            $content | Should -Match 'Connect-MgGraph'
        }

        It 'Script contains the ClientId' {
            $file    = Join-Path $script:TestTempDir 'TestPrefix-Connect-MicrosoftGraph.ps1'
            $content = Get-Content $file -Raw
            $content | Should -Match 'client-id-graph'
        }

        It 'Script contains the TenantId' {
            $file    = Join-Path $script:TestTempDir 'TestPrefix-Connect-MicrosoftGraph.ps1'
            $content = Get-Content $file -Raw
            $content | Should -Match 'tenant-id-0001'
        }
    }

    Context 'MicrosoftTeams connection script' {

        It 'Creates a Teams .ps1 file containing Connect-MicrosoftTeams' {
            Export-ConnectionScript `
                -Service    'MicrosoftTeams' `
                -Prefix     'TestPrefix' `
                -ClientId   'client-id-teams' `
                -TenantId   'tenant-id-0001' `
                -Thumbprint 'ABCDEF1234567890' `
                -ExportDir  $script:TestTempDir

            $file    = Join-Path $script:TestTempDir 'TestPrefix-Connect-MicrosoftTeams.ps1'
            $content = Get-Content $file -Raw
            $file    | Should -Exist
            $content | Should -Match 'Connect-MicrosoftTeams'
            $content | Should -Match 'client-id-teams'
        }
    }

    Context 'ExchangeOnline connection script' {

        It 'Creates an Exchange .ps1 file with org domain and Connect-ExchangeOnline' {
            Export-ConnectionScript `
                -Service    'ExchangeOnline' `
                -Prefix     'TestPrefix' `
                -ClientId   'client-id-exo' `
                -TenantId   'tenant-id-0001' `
                -Thumbprint 'ABCDEF1234567890' `
                -ExportDir  $script:TestTempDir `
                -OrgDomain  'contoso.onmicrosoft.com'

            $file    = Join-Path $script:TestTempDir 'TestPrefix-Connect-ExchangeOnline.ps1'
            $content = Get-Content $file -Raw
            $file    | Should -Exist
            $content | Should -Match 'Connect-ExchangeOnline'
            $content | Should -Match 'contoso.onmicrosoft.com'
        }
    }

    Context 'SharePointOnline connection script' {

        It 'Creates a SharePoint .ps1 file with admin URL and Connect-PnPOnline' {
            Export-ConnectionScript `
                -Service     'SharePointOnline' `
                -Prefix      'TestPrefix' `
                -ClientId    'client-id-spo' `
                -TenantId    'tenant-id-0001' `
                -Thumbprint  'ABCDEF1234567890' `
                -ExportDir   $script:TestTempDir `
                -SPOAdminUrl 'https://contoso-admin.sharepoint.com/'

            $file    = Join-Path $script:TestTempDir 'TestPrefix-Connect-SharePointOnline.ps1'
            $content = Get-Content $file -Raw
            $file    | Should -Exist
            $content | Should -Match 'Connect-PnPOnline'
            $content | Should -Match 'contoso-admin.sharepoint.com'
        }
    }

    Context 'Invalid inputs' {

        It 'Throws for an unknown service key' {
            { Export-ConnectionScript `
                -Service    'UnknownService' `
                -Prefix     'TestPrefix' `
                -ClientId   'xxx' `
                -TenantId   'yyy' `
                -Thumbprint 'zzz' `
                -ExportDir  $script:TestTempDir } |
                Should -Throw
        }
    }
}
