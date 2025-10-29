@echo off
cd /d "%~dp0.."
if not exist "venv\Scripts\activate.bat" (
    echo Environment not set up! Please run "Setup Environment" first.
    pause
    exit /b 1
)
call venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo Failed to activate virtual environment!
    pause
    exit /b 1
)
echo Starting SFT Server...
python secure_file_transfer_fixed.py --server --port 12345
if %errorlevel% neq 0 (
    echo Server failed to start!
    pause
    exit /b 1
)
pause