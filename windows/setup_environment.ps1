#!/usr/bin/env pwsh
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# Configurazione
$VCPKG_PATH = "C:\vcpkg"
$PYTHON_VERSION = "3.13.0"
$PYTHON_INSTALLER_URL = "https://www.python.org/ftp/python/$PYTHON_VERSION/python-$PYTHON_VERSION-amd64.exe"
$PYTHON_INSTALLER = "python_installer.exe"
$PROJECT_NAME = "SFT"
$VENV_NAME = "venv"
$APP_DATA_PATH = "$env:LOCALAPPDATA\$PROJECT_NAME"

function Write-Step {
    param($Message)
    Write-Host "`n=== $Message ===`n" -ForegroundColor Cyan
}

function Test-CommandExists {
    param($Command)
    try { Get-Command $Command -ErrorAction Stop | Out-Null; return $true }
    catch { return $false }
}

# Verifica Visual Studio Build Tools
Write-Step "Verifica Visual Studio Build Tools"
if (-not (Test-Path "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe")) {
    Write-Host "Visual Studio Build Tools non trovato. Installazione..." -ForegroundColor Yellow
    $vsInstallerUrl = "https://aka.ms/vs/17/release/vs_buildtools.exe"
    $vsInstaller = "vs_buildtools.exe"
    Invoke-WebRequest -Uri $vsInstallerUrl -OutFile $vsInstaller
    Start-Process -FilePath $vsInstaller -ArgumentList "--quiet --wait --norestart --nocache --installPath `"${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools`" --add Microsoft.VisualStudio.Workload.NativeDesktop --includeRecommended" -Wait
    Remove-Item $vsInstaller
}

# Installa Python se non presente
Write-Step "Verifica Python"
if (-not (Test-CommandExists python)) {
    Write-Host "Python non trovato. Installazione..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $PYTHON_INSTALLER_URL -OutFile $PYTHON_INSTALLER
    Start-Process -FilePath $PYTHON_INSTALLER -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
    Remove-Item $PYTHON_INSTALLER
    refreshenv
}

# Installa vcpkg se non presente
Write-Step "Verifica vcpkg"
if (-not (Test-Path $VCPKG_PATH)) {
    Write-Host "vcpkg non trovato. Installazione..." -ForegroundColor Yellow
    git clone https://github.com/Microsoft/vcpkg.git $VCPKG_PATH
    Push-Location $VCPKG_PATH
    .\bootstrap-vcpkg.bat
    .\vcpkg.exe integrate install
    Pop-Location
}

# Imposta variabile d'ambiente per vcpkg
[Environment]::SetEnvironmentVariable("VCPKG_ROOT", $VCPKG_PATH, [EnvironmentVariableTarget]::Machine)
$env:VCPKG_ROOT = $VCPKG_PATH

# Installa OpenSSL tramite vcpkg
Write-Step "Installazione OpenSSL"
Push-Location $VCPKG_PATH
.\vcpkg.exe install openssl:x64-windows
Pop-Location

# Ottieni il percorso dell'installazione
$INSTALL_PATH = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Write-Host "Directory di installazione: $INSTALL_PATH"

# Cambia alla directory di installazione
Set-Location $INSTALL_PATH

# Crea virtual environment e installa dipendenze
Write-Step "Configurazione ambiente Python"
if (-not (Test-Path $VENV_NAME)) {
    Write-Host "Creazione ambiente virtuale in $INSTALL_PATH\$VENV_NAME"
    python -m venv $VENV_NAME
}

# Attiva il virtual environment e installa le dipendenze
Write-Host "Attivazione ambiente virtuale..."
& "$INSTALL_PATH\$VENV_NAME\Scripts\Activate.ps1"
if ($?) {
    Write-Host "Aggiornamento pip..."
    python -m pip install --upgrade pip
    Write-Host "Installazione dipendenze..."
    pip install -r requirements.txt

    # Compila il modulo C
    Write-Step "Compilazione modulo C"
    $env:OPENSSL_ROOT_DIR = Join-Path $VCPKG_PATH "installed\x64-windows"
    Write-Host "OPENSSL_ROOT_DIR = $env:OPENSSL_ROOT_DIR"
    python setup.py build_ext --inplace
} else {
    Write-Error "Errore nell'attivazione dell'ambiente virtuale!"
    exit 1
}

Write-Step "Installazione completata!"
Write-Host "Per avviare il server:`n  .\$VENV_NAME\Scripts\python.exe secure_file_transfer_fixed.py --mode server`n"
Write-Host "Per avviare il client:`n  .\$VENV_NAME\Scripts\python.exe secure_file_transfer_fixed.py --mode client --connect <host>:<port> --file <file>`n"