@echo off
cd /d "%~dp0"
echo Cleaning up previous builds...
if exist dist rd /s /q dist
if exist build rd /s /q build
if exist aida_mcp.egg-info rd /s /q aida_mcp.egg-info

echo Building package...
python -m pip install --upgrade build
python -m build

echo Installing package...
for %%f in (dist\*.whl) do (
    echo Found wheel: %%f
    python -m pip install --force-reinstall "%%f"
    echo Installation complete.
    echo You can now use 'aida-mcp' command.
    goto :done
)

echo Error: No wheel file found.
exit /b 1

:done
