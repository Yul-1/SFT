# Guida Rapida SFT (Secure File Transfer)

## Configurazione Iniziale

1. Dopo l'installazione, apri il menu Start e cerca "SFT"
2. Clicca su "Setup Environment" per configurare automaticamente l'ambiente Python e le dipendenze
3. Attendi il completamento della configurazione

## Utilizzo del Software

### Per avviare il server:
1. Apri un terminale PowerShell
2. Naviga nella cartella di installazione (di default `C:\Program Files\SFT`)
3. Attiva l'ambiente virtuale:
```powershell
.\venv\Scripts\activate
```
4. Avvia il server:
```powershell
python secure_file_transfer_fixed.py --server --port 12345
```

### Per inviare un file (client):
1. Apri un altro terminale PowerShell
2. Naviga nella cartella di installazione
3. Attiva l'ambiente virtuale:
```powershell
.\venv\Scripts\activate
```
4. Invia il file:
```powershell
python secure_file_transfer_fixed.py --client --host localhost --port 12345 --file path/del/tuo/file
```

### Note Importanti:
- I file ricevuti vengono salvati nella cartella `ricevuti` all'interno della directory di installazione
- Per trasferimenti tra computer diversi, sostituisci `localhost` con l'indirizzo IP del server
- La porta predefinita è 12345, ma può essere modificata secondo necessità
- Assicurati che il firewall permetta le connessioni sulla porta scelta

## Risoluzione Problemi

Se incontri problemi:
1. Verifica che l'ambiente sia stato configurato correttamente eseguendo "Setup Environment"
2. Assicurati che il firewall Windows non blocchi le connessioni
3. Controlla che il server sia in esecuzione prima di tentare l'invio dei file
4. Verifica che l'indirizzo IP e la porta siano corretti