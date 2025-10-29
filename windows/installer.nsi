; SFT Windows Installer
; Richiede NSIS 3.0 o superiore

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinVer.nsh"
!include "x64.nsh"

; Metadata dell'installer
Name "Secure File Transfer (SFT)"
OutFile "SFT_Setup.exe"
InstallDir "$PROGRAMFILES64\SFT"
RequestExecutionLevel admin

; Pagine dell'interfaccia
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Linguaggio
!insertmacro MUI_LANGUAGE "Italian"

; Verifica requisiti di sistema
Function .onInit
    ; Verifica Windows 10/11 64-bit
    ${IfNot} ${IsWin10}
    ${AndIfNot} ${IsWin11}
        MessageBox MB_OK|MB_ICONSTOP "Questo software richiede Windows 10 o Windows 11."
        Abort
    ${EndIf}
    
    ${IfNot} ${RunningX64}
        MessageBox MB_OK|MB_ICONSTOP "Questo software richiede Windows 64-bit."
        Abort
    ${EndIf}
FunctionEnd

Section "MainSection" SEC01
    SetOutPath "$INSTDIR"
    SetOverwrite try
    
    ; Copia i file del progetto
    File /r "..\*.py"
    File /r "..\requirements.txt"
    File /r "..\tests"
    File "..\setup.py"
    
    ; Crea la directory windows se non esiste
    CreateDirectory "$INSTDIR\windows"
    SetOutPath "$INSTDIR\windows"
    File "setup_environment.ps1"
    
    ; Crea directory per i file ricevuti
    CreateDirectory "$INSTDIR\ricevuti"
    
    ; Crea collegamenti nel menu Start
    CreateDirectory "$SMPROGRAMS\SFT"
    CreateShortCut "$SMPROGRAMS\SFT\Setup Environment.lnk" "powershell.exe" "-ExecutionPolicy Bypass -File `"$INSTDIR\windows\setup_environment.ps1`"" "$INSTDIR\windows\setup_environment.ps1" 0
    
    ; Crea file uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"
    
    ; Aggiungi entry nel registro per uninstaller
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SFT" "DisplayName" "Secure File Transfer"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SFT" "UninstallString" "$INSTDIR\uninstall.exe"
    
    ; Esegui setup_environment.ps1
    ExecWait 'powershell.exe -ExecutionPolicy Bypass -File "$INSTDIR\windows\setup_environment.ps1"'
SectionEnd

Section "Uninstall"
    ; Rimuovi file e directory
    RMDir /r "$INSTDIR\*.*"
    RMDir "$INSTDIR"
    
    ; Rimuovi collegamenti
    Delete "$SMPROGRAMS\SFT\*.*"
    RMDir "$SMPROGRAMS\SFT"
    
    ; Rimuovi chiavi di registro
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SFT"
SectionEnd