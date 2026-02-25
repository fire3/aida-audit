# Build and Install Script for Windows
$ErrorActionPreference = "Stop"

# --- Frontend Build ---
$FrontendDir = "..\frontend"
$BackendStaticDir = "aida_cli\static"
$SkillsDir = "..\skills"
$BackendSkillsDir = "aida_cli\skills"

if (Test-Path $FrontendDir) {
    Write-Host "Found frontend directory. Building frontend..."
    
    # Check if npm is available
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Push-Location $FrontendDir
        try {
            Write-Host "Running npm install..."
            npm install
            if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
            
            Write-Host "Running npm run build..."
            npm run build
            if ($LASTEXITCODE -ne 0) { throw "npm run build failed" }
        }
        catch {
            Write-Host "Error building frontend: $_"
            Pop-Location
            exit 1
        }
        Pop-Location
        
        Write-Host "Copying frontend files to backend..."
        if (Test-Path $BackendStaticDir) { Remove-Item -Recurse -Force $BackendStaticDir }
        New-Item -ItemType Directory -Force -Path $BackendStaticDir | Out-Null
        Copy-Item -Recurse -Force "$FrontendDir\dist\*" $BackendStaticDir

        if (Test-Path "$BackendStaticDir\help.md") {
            Write-Host "Verified: help.md copied successfully."
        } else {
            Write-Host "Warning: help.md not found in backend static directory."
        }
    } else {
        Write-Host "Warning: npm not found. Skipping frontend build."
    }
} else {
    Write-Host "Frontend directory not found. Skipping frontend build."
}

# --- Backend Build ---
Write-Host "Cleaning up previous builds..."
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "aida_cli.egg-info") { Remove-Item -Recurse -Force "aida_cli.egg-info" }

if (Test-Path $SkillsDir) {
    Write-Host "Copying skills into backend package..."
    if (Test-Path $BackendSkillsDir) { Remove-Item -Recurse -Force $BackendSkillsDir }
    New-Item -ItemType Directory -Force -Path $BackendSkillsDir | Out-Null
    Copy-Item -Recurse -Force "$SkillsDir\*" $BackendSkillsDir
} else {
    Write-Host "Warning: skills directory not found at $SkillsDir."
}

Write-Host "Building package..."
# Ensure build tool is installed
python -m pip install --upgrade build

# Build wheel
python -m build

Write-Host "Installing package..."
$whl = Get-ChildItem "dist\*.whl" | Select-Object -First 1
if ($whl) {
    Write-Host "Found wheel: $($whl.FullName)"
    python -m pip uninstall -y "aida-cli"
    python -m pip install "$($whl.FullName)"
    Write-Host "Installation complete."
    Write-Host "You can now use the 'aida-cli' command."
    Write-Host "  Example: aida-cli export mybinary.exe -o ./output"
    Write-Host "  Example: aida-cli export mybinary.exe -o ./output --export-c"
    Write-Host "  Example: aida-cli serve ."
} else {
    Write-Host "Error: No wheel file found."
    exit 1
}
