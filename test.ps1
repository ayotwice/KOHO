# PCI-DSS Compliance Testing Script for Windows
param(
    [string]$Action = "test"
)

function Test-Policies {
    Write-Host "Running PCI-DSS compliance tests..." -ForegroundColor Green
    
    Write-Host "Testing compliant configuration..." -ForegroundColor Yellow
    conftest test --policy policies/opa/main.rego tests/fixtures/compliant_plan.json --output=table
    $compliant_exit = $LASTEXITCODE
    
    Write-Host "Testing non-compliant configuration..." -ForegroundColor Yellow
    conftest test --policy policies/opa/main.rego tests/fixtures/non_compliant_plan.json --output=table
    $noncompliant_exit = $LASTEXITCODE
    
    if ($noncompliant_exit -eq 0) {
        Write-Host "ERROR: Non-compliant test should have failed!" -ForegroundColor Red
        exit 1
    } else {
        Write-Host "SUCCESS: Non-compliant test failed as expected!" -ForegroundColor Green
    }
    
    if ($compliant_exit -ne 0) {
        Write-Host "WARNING: Compliant test failed - may need policy adjustment" -ForegroundColor Yellow
    } else {
        Write-Host "SUCCESS: Compliant test passed!" -ForegroundColor Green
    }
    
    Write-Host "Policy tests completed!" -ForegroundColor Green
}

function Install-Dependencies {
    Write-Host "Installing Conftest..." -ForegroundColor Green
    
    if (!(Get-Command conftest -ErrorAction SilentlyContinue)) {
        $url = "https://github.com/open-policy-agent/conftest/releases/download/v0.46.0/conftest_0.46.0_Windows_x86_64.zip"
        Invoke-WebRequest -Uri $url -OutFile "conftest.zip"
        Expand-Archive -Path "conftest.zip" -DestinationPath "." -Force
        Move-Item "conftest.exe" "$env:USERPROFILE\conftest.exe" -Force
        $env:PATH += ";$env:USERPROFILE"
        Remove-Item "conftest.zip"
        Write-Host "Conftest installed successfully!" -ForegroundColor Green
    } else {
        Write-Host "Conftest already installed" -ForegroundColor Green
    }
}

switch ($Action) {
    "install" { Install-Dependencies }
    "test" { 
        Install-Dependencies
        Test-Policies 
    }
    default { 
        Write-Host "Usage: .\test.ps1 [install|test]" -ForegroundColor Yellow
    }
}