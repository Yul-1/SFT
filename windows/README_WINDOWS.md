# SFT - Installazione su Windows

## Requisiti di Sistema
- Windows 10 o Windows 11 (64-bit)
- Almeno 2GB di spazio libero su disco
- Connessione internet (per il download delle dipendenze)

## Metodo 1: Installazione Automatica (Raccomandato)
1. Scarica `SFT_Setup.exe` dal [release page](https://github.com/Yul-1/SFT/releases)
2. Esegui l'installer come amministratore
3. Segui le istruzioni a schermo
4. L'installer configurerà automaticamente:
   - Python
   - Visual Studio Build Tools
   - vcpkg e OpenSSL
   - Ambiente virtuale Python
   - Compilazione del modulo C

## Metodo 2: Installazione Manuale
Se preferisci un'installazione manuale o l'installer automatico non funziona:

1. Installa i prerequisiti:
   - [Python 3.13.x](https://www.python.org/downloads/)
   - [Visual Studio Build Tools 2022](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   - [Git](https://git-scm.com/download/win)

2. Installa vcpkg:
   ```powershell
   git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
   cd C:\vcpkg
   .\bootstrap-vcpkg.bat
   .\vcpkg.exe integrate install
   ```

3. Installa OpenSSL:
   ```powershell
   .\vcpkg.exe install openssl:x64-windows
   ```

4. Clona il repository:
   ```powershell
   git clone https://github.com/Yul-1/SFT.git
   cd SFT
   git checkout feature/windows-porting
   ```

5. Configura l'ambiente Python:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

6. Compila il modulo C:
   ```powershell
   $env:OPENSSL_ROOT_DIR = "C:\vcpkg\installed\x64-windows"
   python setup.py build_ext --inplace
   ```

## Utilizzo

### Avvio del Server
```powershell
.\.venv\Scripts\python.exe secure_file_transfer_fixed.py --mode server
```

### Avvio del Client
```powershell
.\.venv\Scripts\python.exe secure_file_transfer_fixed.py --mode client --connect <host>:<port> --file <file>
```

## Risoluzione Problemi

### DLL non trovate
Se ricevi errori riguardo DLL mancanti:
1. Assicurati che vcpkg sia installato correttamente
2. Verifica che le DLL OpenSSL siano nel PATH o nella stessa directory del progetto

### Errori di Compilazione
1. Verifica che Visual Studio Build Tools sia installato correttamente
2. Assicurati che la variabile OPENSSL_ROOT_DIR punti alla directory corretta
3. Riprova la compilazione dopo aver riavviato il terminale

### Errori di Python
1. Verifica che il virtual environment sia attivato (.venv)
2. Controlla che tutte le dipendenze siano installate correttamente
3. Usa `pip list` per verificare le versioni dei pacchetti