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
    ${If} ${AtLeastWin10}
        ; Windows 10 or later - OK
    ${Else}
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
    File "start_server.bat"
    File "GUIDA_RAPIDA.md"
    
    ; Crea directory per i file ricevuti e dati dell'applicazione
    CreateDirectory "$INSTDIR\ricevuti"
    CreateDirectory "$LOCALAPPDATA\SFT"
    CreateDirectory "$LOCALAPPDATA\SFT\logs"
    
    ; Imposta permessi usando PowerShell
    FileOpen $0 "$INSTDIR\windows\set_permissions.ps1" w
    FileWrite $0 "$$acl = Get-Acl '$INSTDIR\ricevuti'$\r$\n"
    FileWrite $0 "$$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Users', 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')$\r$\n"
    FileWrite $0 "$$acl.AddAccessRule($$rule)$\r$\n"
    FileWrite $0 "Set-Acl '$INSTDIR\ricevuti' $$acl$\r$\n"
    FileWrite $0 "$$acl = Get-Acl '$LOCALAPPDATA\SFT'$\r$\n"
    FileWrite $0 "$$acl.AddAccessRule($$rule)$\r$\n"
    FileWrite $0 "Set-Acl '$LOCALAPPDATA\SFT' $$acl$\r$\n"
    FileClose $0
    
    nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -File "$INSTDIR\windows\set_permissions.ps1"'
    Delete "$INSTDIR\windows\set_permissions.ps1"
    
    ; Crea cartella nel menu Start
    CreateDirectory "$SMPROGRAMS\SFT"
    
    ; Collegamento per Setup Environment
    ExecWait 'cmd.exe /c mklink "$SMPROGRAMS\SFT\Setup Environment.lnk" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"'
    WriteINIStr "$SMPROGRAMS\SFT\Setup Environment.lnk" "Shell" "Arguments" '-ExecutionPolicy Bypass -NoExit -File "$INSTDIR\windows\setup_environment.ps1"'
    
    ; Collegamento per Guida Rapida
    CreateShortCut "$SMPROGRAMS\SFT\Guida Rapida.lnk" "notepad.exe" \
                   '"$INSTDIR\windows\GUIDA_RAPIDA.md"'
    
    ; Collegamento per avviare il Server
    CreateShortCut "$SMPROGRAMS\SFT\Avvia Server.lnk" "cmd.exe" \
                   '/k "$INSTDIR\windows\start_server.bat"' \
                   "$WINDIR\System32\cmd.exe" 0
    
    ; Collegamento alla cartella dei file ricevuti
    CreateShortCut "$SMPROGRAMS\SFT\Files Ricevuti.lnk" "$INSTDIR\ricevuti"
    
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