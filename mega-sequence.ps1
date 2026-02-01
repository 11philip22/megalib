# mega-sequence.ps1
$ErrorActionPreference = "Stop"

# ---- set your credentials and target folder ----
$Email        = "shadowwitness3365@guerrillamailblock.com"
$Password     = "testlmao123"
$Proxy        = $null          # e.g. "http://localhost:8080" or leave $null
$RemoteFolder = "/Root/lol1"
$RemoteFolder2 = "/Root/lol2"

# ---- common setup ----
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $RepoRoot

# helper to run the compiled examples
$CommonArgs = @("--email", $Email, "--password", $Password)
if ($Proxy) { $CommonArgs += @("--proxy", $Proxy) }

function Invoke-Example($example, $extraArgs) {
    & cargo run --example $example -- @CommonArgs @extraArgs
}

# 1) create the folder
Write-Host "Creating folder $RemoteFolder"
Invoke-Example "mkdir"  @($RemoteFolder)

# 2) upload Cargo.toml into that folder
Write-Host "Uploading Cargo.toml to $RemoteFolder"
Invoke-Example "upload" @("$RepoRoot/Cargo.toml", "$RemoteFolder/")

# 3) export the uploaded file to get a public link
Write-Host "Exporting $RemoteFolder to get public link"
Invoke-Example "export" @("--path", "$RemoteFolder")

# 4) pause until user presses Enter
Read-Host "Verify if the exported link is correct and press Enter to upload Cargo.lock"

# 5) upload Cargo.lock (rename here if you truly meant 'carg0.lock')
Invoke-Example "upload" @("$RepoRoot/Cargo.lock", "$RemoteFolder/")

# 6) pause until user presses Enter
Read-Host "Check if both files are in the folder and login to upgrade encrypyion. Then press Enter to continue"

# 7) create a new subfolder
Write-Host "Creating another folder $RemoteFolder2"
Invoke-Example mkdir @($RemoteFolder2)

# 8) upload Cargo.lock into the new subfolder
Write-Host "Uploading Cargo.lock to $RemoteFolder2"
Invoke-Example "upload" @("$RepoRoot/Cargo.lock", "$RemoteFolder2")

# 9) export the new subfolder to get a public link
Write-Host "Exporting $RemoteFolder2 to get public link"
Invoke-Example "export" @("--path", "$RemoteFolder2")

# 10) pause until user presses Enter
Read-Host "Verify if the exported link is correct and press Enter to upload Cargo.toml"

# 11) upload Cargo.toml into the new subfolder
Write-Host "Uploading Cargo.toml to $RemoteFolder2"
Invoke-Example "upload" @("$RepoRoot/Cargo.toml", "$RemoteFolder2")
Write-Host "Please verify if both files are in the folder now."

# 12) done
Write-Host "Done."