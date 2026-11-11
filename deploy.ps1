# Run from this folder in PowerShell:  .\deploy.ps1 -User <your-ssh-user>
# Copies the app to the Ubuntu server and starts it. You will be asked for
# your SSH password (unless you use a key) and your sudo password.
param(
  [Parameter(Mandatory = $true)][string]$User,
  [string]$Server = "192.168.7.10"
)
$ErrorActionPreference = "Stop"
$target = "$User@$Server"
Set-Location $PSScriptRoot
ssh $target "mkdir -p ~/nsm-10"
if ($LASTEXITCODE -ne 0) { throw "Could not connect to $target" }
scp -r app Dockerfile docker-compose.yml requirements.txt install.sh "${target}:~/nsm-10/"
if ($LASTEXITCODE -ne 0) { throw "Copy failed" }
ssh -t $target "cd ~/nsm-10 && sudo bash install.sh"
if ($LASTEXITCODE -ne 0) { throw "Install failed on the server" }
Write-Host "Done. Open http://${Server}:8080 and create the admin password."
