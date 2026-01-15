# Build and Install Script for Windows

Write-Host "Cleaning up previous builds..."
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "ida_mcp.egg-info") { Remove-Item -Recurse -Force "ida_mcp.egg-info" }

Write-Host "Building package..."
# Ensure build tool is installed
python -m pip install --upgrade build

# Build wheel
python -m build

Write-Host "Installing package..."
$whl = Get-ChildItem "dist\*.whl" | Select-Object -First 1
if ($whl) {
    Write-Host "Found wheel: $($whl.FullName)"
    python -m pip install --force-reinstall "$($whl.FullName)"
    Write-Host "Installation complete."
    Write-Host "You can now use the 'ida-mcp' command."
    Write-Host "  Example: ida-mcp export mybinary.exe -o mybinary.db"
    Write-Host "  Example: ida-mcp serve --project ."
} else {
    Write-Host "Error: No wheel file found."
    exit 1
}
