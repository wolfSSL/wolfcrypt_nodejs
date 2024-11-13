$ErrorActionPreference = "Stop"

# Predefined Community, Professional, Enterprise versions of Visual Studio 2022
$vsPathCommunity = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe"
$vsPathProfessional = "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.exe"
$vsPathEnterprise = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.exe"

if (Test-Path "C:/workspace/wolfssl-$env:USERNAME") {
    $env:WOLFSSL_ROOT = "C:/workspace/wolfssl-$env:USERNAME"
    $env:PATH += ";$env:WOLFSSL_ROOT\DLL Release\x64"

    Write-Output "Found wolfSSL at $env:WOLFSSL_ROOT"
    $env:WOLFSSL_LIB_PATH           = "$env:WOLFSSL_ROOT/DLL Release/x64"
    $env:WOLFSSL_INCLUDE_PATH       = "$env:WOLFSSL_ROOT"
    $env:WOLFSSL_USER_SETTINGS_PATH = "$env:WOLFSSL_ROOT/IDE/WIN"

} elseif (Test-Path "C:/workspace/wolfssl") {
    $env:WOLFSSL_ROOT = "C:/workspace/wolfssl"
    $env:PATH += ";$env:WOLFSSL_ROOT\DLL Release\x64"

    Write-Output "Found wolfSSL at $env:WOLFSSL_ROOT"
    $env:WOLFSSL_LIB_PATH           = "$env:WOLFSSL_ROOT/DLL Release/x64"
    $env:WOLFSSL_INCLUDE_PATH       = "$env:WOLFSSL_ROOT"
    $env:WOLFSSL_USER_SETTINGS_PATH = "$env:WOLFSSL_ROOT/IDE/WIN"

} else {
    Write-Output "Could not find wolfSSL source directory."
}


Write-Output "WOLFSSL_LIB_PATH:           $($env:WOLFSSL_LIB_PATH)"
Write-Output "WOLFSSL_INCLUDE_PATH:       $($env:WOLFSSL_INCLUDE_PATH)"
Write-Output "WOLFSSL_USER_SETTINGS_PATH: $($env:WOLFSSL_USER_SETTINGS_PATH)"

fnm env --use-on-cd | Out-String | Invoke-Expression
fnm use --install-if-missing 20
node -v # should print `v20.18.0`
npx -v # should print `10.8.2`

# Launch VS2022 from the same shell:
# Check if the file exists
if (Test-Path $vsPathEnterprise) {
    # Run the file
    Write-Output "Launching Visual Studio 2022 Enterprise at: $vsPathEnterprise"
    Start-Process $vsPathEnterprise

} elseif (Test-Path $vsPathProfessional) {
    # Run the file
    Write-Output "Launching Visual Studio 2022 Professional at: $vsPathProfessional"
    Start-Process $vsPathProfessional

} elseif (Test-Path $vsPathCommunity) {
    # Run the file
    Write-Output "Launching Visual Studio 2022 Community at: $vsPathCommunity"
    Start-Process $vsPathCommunity

} else {
    Write-Output "Visual Studio 2022 executable not found."
}

Write-Output "Clean..."
npm run clean
npx node-gyp clean

Write-Output "Rebuild..."
npx node-gyp rebuild

Write-Output "Install..."
npm install

Write-Output "Test..."
npm run test


# One final check if the user_settings.h match
$File1 = Get-Content "$($env:WOLFSSL_USER_SETTINGS_PATH)/user_settings.h"
$File2 = Get-Content "./lib/user_settings.h"

$diff = Compare-Object $File1 $File2

if ($diff) {
    Write-Host "Warning: "
    Write-Host "./lib/user_settings.h does not match"
    Write-Host "$($env:WOLFSSL_USER_SETTINGS_PATH)/user_settings.h"
} else {
    Write-Host "Confirmed reference ./lib/user_settings.h matches wolfSSL source."
}
