AegisTransfer (SFT)

AegisTransfer è un sistema di trasferimento file sicuro (Secure File Transfer - SFT) client-server ad alte prestazioni. È progettato da zero con un'architettura "security-first", combinando la velocità della crittografia C (via OpenSSL) con la sicurezza e la flessibilità di Python.

Il sistema utilizza un modulo di accelerazione C per operazioni crittografiche intensive, ma include un fallback trasparente a un'implementazione Python pura (cryptography) nel caso in cui il modulo C non sia compilato o non sia disponibile, garantendo la portabilità.

Indice

Perché AegisTransfer?

Architettura del Sistema

Caratteristiche di Sicurezza

Requisiti

Installazione e Build

Branch main (Linux - Build Semplice)

Branch Porting (Windows/Linux - Build setup.py)

Testing

Utilizzo

Roadmap (Sviluppo Futuro)

Perché AegisTransfer?

Mentre esistono protocolli come SCP o SFTP, questo progetto serve come studio approfondito sull'implementazione di software sicuro a più livelli. L'obiettivo primario è mitigare le vulnerabilità comuni a livello di protocollo, rete e implementazione.

Performance: Le operazioni crittografiche (AES-GCM) sono delegate a C/OpenSSL compilato [cite: crypto-accelerator-fixed.c], riducendo drasticamente il carico sulla CPU rispetto a Python puro.

Robustezza: Il sistema è protetto contro attacchi DoS [cite: secure-file-transfer-fixed.py], replay attacks [cite: secure-file-transfer-fixed.py] e timing attacks [cite: crypto-accelerator-fixed.c, python-wrapper-fixed.py].

Sicurezza della Memoria: Particolare attenzione è data alla pulizia sicura dei dati sensibili (come chiavi e buffer) dalla memoria [cite: crypto-accelerator-fixed.c, python-wrapper-fixed.py].

Architettura del Sistema

Il progetto è diviso in tre layer logici che interagiscono tra loro:

Livello Protocollo (Python) - secure-file-transfer-fixed.py
È il "cervello" dell'applicazione. Gestisce la logica di rete (TCP server/client), implementa il protocollo di handshake (scambio di chiavi RSA-OAEP) e gestisce la logica di trasferimento. È responsabile dell'applicazione delle contromisure di sicurezza a livello di rete, come il rate-limiting e la protezione anti-replay [cite: secure-file-transfer-fixed.py].

Livello Wrapper (Python) - python-wrapper-fixed.py
È il "ponte" flessibile. Fornisce una classe SecureCrypto che funge da API unificata per il resto dell'applicazione. Al momento dell'inizializzazione, tenta di importare il modulo C compilato (crypto_accelerator). In caso di fallimento (es. ImportError), attiva un flag e utilizza implementazioni di fallback pure-Python (usando la libreria cryptography) per tutte le operazioni [cite: python-wrapper-fixed.py].

Livello Core (C) - crypto-accelerator-fixed.c
È il "motore" ad alte prestazioni. Si tratta di un'estensione Python C che espone funzioni OpenSSL ottimizzate. Gestisce le operazioni CPU-intensive:

Cifratura e Decifratura AES-256-GCM.

Generazione di byte casuali sicuri (RAND_bytes).

Confronto a tempo costante (CRYPTO_memcmp).

Caratteristiche di Sicurezza Dettagliate

Questo sistema implementa un'ampia gamma di contromisure di sicurezza:

Crittografia e Autenticazione

Cifratura Dati (C): AES-256-GCM tramite OpenSSL [cite: crypto-accelerator-fixed.c].

Cifratura Dati (Fallback Python): AES-256-GCM tramite cryptography [cite: python-wrapper-fixed.py].

Handshake Sicuro: Scambio di un segreto condiviso utilizzando RSA-4096 con padding OAEP (SHA-256) [cite: secure-file-transfer-fixed.py].

Autenticazione Messaggi:

HMAC: Tutti i pacchetti JSON sono firmati con HMAC-SHA256 (la cui chiave è derivata dal segreto condiviso tramite PBKDF2) [cite: secure-file-transfer-fixed.py].

GCM Tag: L'autenticità del ciphertext è garantita dal GCM Authentication Tag [cite: crypto-accelerator-fixed.c].

Protezione Denial of Service (DoS)

Rate Limiting: Un RateLimiter basato su client ID (IP) previene attacchi "brute force" o "spam" di pacchetti [cite: secure-file-transfer-fixed.py].

Limite Connessioni Globale: Il server limita il numero massimo di connessioni globali e thread attivi (MAX_GLOBAL_CONNECTIONS) [cite: secure-file-transfer-fixed.py].

Validazione Dimensione Pacchetti: Sia a livello di protocollo Python [cite: secure-file-transfer-fixed.py] che a livello C [cite: crypto-accelerator-fixed.c] viene validata la dimensione dei pacchetti prima di allocare memoria.

Timeout Socket: Tutti i socket hanno un timeout (SOCKET_TIMEOUT) per prevenire attacchi "slowloris" [cite: secure-file-transfer-fixed.py].

Protezione Anti-Replay

Timestamp: Il server rifiuta pacchetti con timestamp troppo vecchi [cite: secure-file-transfer-fixed.py].

Message ID Unici: Il server mantiene una deque (coda a dimensione fissa) degli hash dei messaggi ricevuti e scarta i duplicati [cite: secure-file-transfer-fixed.py].

Protezione Vulnerabilità Software

Timing Attacks: Le firme HMAC sono verificate usando hmac.compare_digest in Python [cite: python-wrapper-fixed.py] e CRYPTO_memcmp in C [cite: crypto-accelerator-fixed.c].

Gestione Sicura della Memoria: Il modulo C utilizza secure_memzero [cite: crypto-accelerator-fixed.c] per cancellare i buffer temporanei. Il wrapper Python pulisce (best-effort) le chiavi dalla memoria [cite: python-wrapper-fixed.py].

Hardening di Compilazione: Il modulo C è compilato con flag di sicurezza moderni (-fstack-protector-strong, -D_FORTIFY_SOURCE=2, ecc.) [cite: python-wrapper-fixed.py].

Path Traversal: I nomi dei file sono rigorosamente sanitizzati [cite: secure-file-transfer-fixed.py].

📋 Requisiti

Crea un file requirements.txt con il seguente contenuto e installalo (pip install -r requirements.txt):

cryptography
jsonschema
setuptools


🛠️ Installazione e Build

Questo progetto ha due sistemi di build a seconda del branch. Segui le istruzioni corrette per il tuo ambiente.

🐧 Branch main (Linux - Build Semplice)

Questo branch (main) è ottimizzato per Linux (Ubuntu/Debian) e utilizza uno script di compilazione integrato in python-wrapper-fixed.py.

Installa Dipendenze di Sistema:

sudo apt update
sudo apt install -y python3-dev build-essential libssl-dev python3-pip


Crea Venv e Installa Requisiti:

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


Compila il Modulo C:
Usa lo script di compilazione integrato nel wrapper [cite: python-wrapper-fixed.py].

python3 python-wrapper-fixed.py --compile


Output atteso: ✓ C module compiled successfully as crypto_accelerator.so

🚀 Branch Porting (Windows/Linux - Build setup.py)

Un branch separato (es. feature/windows-porting) utilizza setup.py per un build system multi-piattaforma.

🪟 Windows 11

Installa Strumenti C++:

Usa il "Visual Studio Installer".

Installa (o Modifica) "Visual Studio Build Tools".

Assicurati che il workload "Sviluppo di applicazioni desktop con C++" sia selezionato.

Installa Vcpkg e OpenSSL:

# Clona vcpkg
git clone [https://github.com/Microsoft/vcpkg.git](https://github.com/Microsoft/vcpkg.git) C:\vcpkg
cd C:\vcpkg
.\bootstrap-vcpkg.bat

# Installa OpenSSL
.\vcpkg.exe install openssl:x64-windows


Crea Venv e Installa Requisiti:

python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt


Compila il Modulo C:

# Imposta la variabile d'ambiente per trovare OpenSSL
$env:OPENSSL_ROOT_DIR = "C:\vcpkg\installed\x64-windows"

# Compila
python setup.py build_ext --inplace


Correzione Runtime (Copia DLL):

Copia i file libcrypto-*.dll e libssl-*.dll.

Da: C:\vcpkg\installed\x64-windows\bin

A: La cartella principale del tuo progetto (dove si trova setup.py).

🐧 Linux (Ubuntu/Debian - con setup.py)

Installa Dipendenze di Sistema:

sudo apt update
sudo apt install -y python3-dev build-essential libssl-dev python3-pip


Crea Venv e Installa Requisiti:

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


Compila:

python setup.py build_ext --inplace


🧪 Testing

Dopo la compilazione, puoi verificare l'integrazione del modulo C e il protocollo di rete.

Test del Wrapper C

Questo test verifica che il modulo C sia importato correttamente e che le funzioni di crittografia/decifratura funzionino.

# Assicurati che il venv sia attivo
# (Usa python3 su Linux, python su Windows)
python python-wrapper-fixed.py --test


Output atteso: C acceleration module loaded successfully e test superati (incluso il test di fallimento autenticazione).

Test End-to-End (E2E)

Questo test avvia un server e un client locali per verificare l'handshake e la comunicazione.

Terminale 1 (Server):

python secure-file-transfer-fixed.py --mode server


Terminale 2 (Client):

python secure-file-transfer-fixed.py --mode client --connect 127.0.0.1


Output atteso: Il client invia un PING e il server risponde con PONG.

🚀 Utilizzo

🖥️ Avviare il Server

# Esegui sull'host locale, porta 5555
python secure-file-transfer-fixed.py --mode server

# Esegui su un IP specifico e porta custom
python secure-file-transfer-fixed.py --mode server --host 192.168.1.100 --port 9999


💻 Connettere il Client

# Connettiti a un server locale
python secure-file-transfer-fixed.py --mode client --connect 127.0.0.1:5555

# Connettiti a un server remoto
python secure-file-transfer-fixed.py --mode client --connect 192.168.1.100:9999


🗺️ Roadmap (Sviluppo Futuro)

Team Dev: Implementare la logica file_transfer nel loop _handle_connection [cite: secure-file-transfer-fixed.py] per gestire l'invio e la ricezione di file reali.

Team Dev: Aggiungere la ripresa dei trasferimenti interrotti.

Team Controllo: Scrivere un set di test pytest completo per automatizzare i test di integrazione, inclusi i fallimenti (es. tag GCM errati, firme HMAC non valide, test del rate-limit).

Team Porting: Continuare il lavoro sul branch di porting per Windows (MSVC) e macOS (Clang), stabilizzando il build system setup.py.