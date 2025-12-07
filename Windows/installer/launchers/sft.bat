@echo off
REM SFT Main Launcher
setlocal
set SCRIPT_DIR=%~dp0
set PYTHON_HOME=%SCRIPT_DIR%python
set PYTHONPATH=%SCRIPT_DIR%;%PYTHON_HOME%\Lib\site-packages
"%PYTHON_HOME%\python.exe" "%SCRIPT_DIR%sft.py" %*
